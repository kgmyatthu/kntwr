#!/usr/bin/env python3
"""Read KNTWR profile ABI 7/8 and resolve runtime RVAs using the matching DLL/PDB.

Usage:
  python profile_symbolize.py receipt.json.profile.bin --dll build/kntwr/bin/Release/kntwr_runtime.dll
  python profile_symbolize.py receipt.json.profile.bin --frame-va 0x585d40

ABI 8 preserves the 15748-byte ABI-7 header, seven bucket_count*u32 image
histograms, and 4612-byte tick-chain trailer. The appended NTR8/v1 section is
24 little-endian u32 header words (RUNTIME_FIELDS below), four dense runtime
histograms, pair_capacity triples (runtime bucket RVA, image frame bucket RVA,
count), then wait_capacity triples (exact runtime return RVA, wait kind, count).
Section bytes includes its 96-byte header. Zero-count sparse slots are empty;
explicit occupied counts are observational and can race a live launcher copy.
Histograms: all observed threads, actual tick owner, worker heuristic, selected
site/tick owner. selected_site=0 means whole tick, otherwise CLI site index+1.

Workers exclude the tick owner and published AI worker, not exact pool membership.
All-thread sampling covers actual ticks plus main-thread samples outside ticks.
Frame gates are call-validated stack scans, NOT proof of an active site. Select
one frame bucket to avoid double counting overlapping stack frames. Wait callers
are [ESP] when possible, otherwise the first call-validated runtime return in a
bounded 1 KiB stack scan; scanned words can be stale. All counts are occupancy,
not elapsed time. Symbols/lines resolve the START of each 64-byte EIP bucket;
a bucket can straddle functions/lines. Exact wait return addresses are not rounded.
DbgHelp verifies the DLL's PDB identity; no LOAD_ANYTHING or symbol server is used.
"""
from __future__ import annotations

import argparse
from array import array
from collections import Counter
import ctypes as C
from dataclasses import dataclass
import heapq
from pathlib import Path
import struct
import sys

HEADER_BYTES = 15748
CHAIN_BYTES = 4612
RUNTIME_MAGIC = 0x3852544E
RUNTIME_FIELDS = (
    "magic version bytes runtime_base runtime_size bucket_bytes bucket_count histogram_count "
    "pair_capacity pair_count pair_overflow wait_capacity wait_count wait_overflow "
    "wait_samples wait_unresolved wait_direct wait_scanned tick_runtime_samples "
    "worker_runtime_samples all_runtime_samples selected_runtime_samples selected_site flags"
).split()
RUNTIME_HEADER = struct.Struct("<24I")
WAIT_NAMES = ("single", "multiple", "delay", "alert", "keyed_release", "keyed_wait")
IMAGE_NAMES = ("all-thread EIP", "tick-thread EIP", "frames", "main A1 (tick start)",
               "main B (post-tick)", "main C (otherwise)", "main A2 (remaining tick)")


def words(data: bytes, offset: int, count: int) -> array:
    end = offset + count * 4
    if offset < 0 or end > len(data):
        raise ValueError(f"truncated u32 table at offset {offset}, expected {count} words")
    result = array("I")
    result.frombytes(data[offset:end])
    if sys.byteorder != "little":
        result.byteswap()
    return result


@dataclass
class Profile:
    abi: int
    header: array
    image: list[array]
    chains: list[tuple[str, array]]
    runtime: dict[str, int] | None
    runtime_hist: list[array]
    pairs: list[tuple[int, int, int]]
    waits: list[tuple[int, int, int]]


def parse_profile(path: Path) -> Profile:
    data = path.read_bytes()
    if len(data) < 16:
        raise ValueError("truncated profile header")
    abi, header_size, bucket_bytes, count = struct.unpack_from("<4I", data)
    if abi not in (7, 8):
        raise ValueError(f"unsupported profile ABI {abi}; expected 7 or 8")
    if header_size != HEADER_BYTES or bucket_bytes != 64 or not 0 < count <= 0x10000000 // 64:
        raise ValueError("invalid ABI-7/8 header size or image bucket geometry")
    header = words(data, 0, header_size // 4)
    image = [words(data, header_size + i * count * 4, count) for i in range(7)]
    offset = header_size + count * 4 * 7
    tick_chain = words(data, offset, CHAIN_BYTES // 4)
    chains = [("tick", tick_chain), ("main A1", words(data, 11136, CHAIN_BYTES // 4)),
              ("main B", words(data, 6220, CHAIN_BYTES // 4))]
    for name, chain in chains:
        if any(length > 16 for length in chain[64:128]):
            raise ValueError(f"invalid {name} chain length")
    offset += CHAIN_BYTES
    profile = Profile(abi, header, image, chains, None, [], [], [])
    if abi == 7:
        if offset != len(data):
            raise ValueError("unexpected bytes after ABI-7 tick-chain trailer")
        return profile
    if len(data) < offset + RUNTIME_HEADER.size:
        raise ValueError("ABI 8 missing NTR8 section")
    runtime = dict(zip(RUNTIME_FIELDS, RUNTIME_HEADER.unpack_from(data, offset)))
    if runtime["magic"] != RUNTIME_MAGIC or runtime["version"] != 1:
        raise ValueError("unsupported runtime section tag/version")
    n = runtime["bucket_count"]
    if (runtime["bucket_bytes"] != 64 or not 0 < runtime["runtime_size"] <= 0x10000000
            or not 0 < n <= (runtime["runtime_size"] + 63) // 64
            or (not runtime["flags"] & 8 and n != (runtime["runtime_size"] + 63) // 64)
            or runtime["histogram_count"] != 4
            or runtime["pair_capacity"] != 8192 or runtime["wait_capacity"] != 1024):
        raise ValueError("invalid NTR8/v1 table geometry")
    expected = 96 + n * 16 + runtime["pair_capacity"] * 12 + runtime["wait_capacity"] * 12
    if runtime["bytes"] != expected or offset + expected != len(data):
        raise ValueError("invalid NTR8 section length or trailing data")
    if runtime["pair_count"] > runtime["pair_capacity"] or runtime["wait_count"] > runtime["wait_capacity"]:
        raise ValueError("invalid NTR8 occupied counts")
    offset += 96
    profile.runtime = runtime
    profile.runtime_hist = [words(data, offset + i * n * 4, n) for i in range(4)]
    offset += n * 16
    for capacity, target, is_pair in ((runtime["pair_capacity"], profile.pairs, True),
                                       (runtime["wait_capacity"], profile.waits, False)):
        for row in struct.iter_unpack("<3I", data[offset:offset + capacity * 12]):
            rva, key, samples = row
            if not samples:
                continue
            if rva >= runtime["runtime_size"] or (is_pair and (rva % 64 or key % 64 or key >= count * 64)):
                raise ValueError("invalid runtime/frame RVA")
            if not is_pair and key >= len(WAIT_NAMES):
                raise ValueError("invalid runtime wait kind")
            target.append(row)
        offset += capacity * 12
    return profile


# Fixed-width Windows types, independent of the Python interpreter's bitness.
U32, U64 = C.c_uint32, C.c_uint64


class SymbolInfo(C.Structure):
    _fields_ = [("SizeOfStruct", U32), ("TypeIndex", U32), ("Reserved", U64 * 2),
                ("Index", U32), ("Size", U32), ("ModBase", U64), ("Flags", U32),
                ("Value", U64), ("Address", U64), ("Register", U32), ("Scope", U32),
                ("Tag", U32), ("NameLen", U32), ("MaxNameLen", U32), ("Name", C.c_char * 1)]


class LineInfo(C.Structure):
    _fields_ = [("SizeOfStruct", U32), ("Key", C.c_void_p), ("LineNumber", U32),
                ("FileName", C.c_char_p), ("Address", U64)]


class ModuleInfo(C.Structure):
    _fields_ = [("SizeOfStruct", U32), ("BaseOfImage", U64), ("ImageSize", U32),
                ("TimeDateStamp", U32), ("CheckSum", U32), ("NumSyms", U32), ("SymType", U32),
                ("ModuleName", C.c_char * 32), ("ImageName", C.c_char * 256),
                ("LoadedImageName", C.c_char * 256), ("LoadedPdbName", C.c_char * 256),
                ("CVSig", U32), ("CVData", C.c_char * 780), ("PdbSig", U32),
                ("PdbSig70", C.c_byte * 16), ("PdbAge", U32), ("PdbUnmatched", C.c_int32),
                ("DbgUnmatched", C.c_int32), ("LineNumbers", C.c_int32),
                ("GlobalSymbols", C.c_int32), ("TypeInfo", C.c_int32),
                ("SourceIndexed", C.c_int32), ("Publics", C.c_int32), ("MachineType", U32), ("Reserved", U32)]


@dataclass(frozen=True)
class Symbol:
    rva: int
    name: str
    file: str = ""
    line: int = 0


class DbgHelp:
    def __init__(self, dll: Path, pdb_dir: Path | None = None):
        if sys.platform != "win32":
            raise OSError("DbgHelp symbolization requires Windows (use --no-symbols to inspect RVAs)")
        dll = dll.resolve(strict=True)
        self.dll = C.WinDLL("dbghelp", use_last_error=True)
        kernel = C.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.argtypes = []
        kernel.GetCurrentProcess.restype = C.c_void_p
        self.process = kernel.GetCurrentProcess()
        self.initialized = False
        self.cache: dict[int, Symbol] = {}
        signatures = {
            "SymSetOptions": ([U32], U32),
            "SymInitializeW": ([C.c_void_p, C.c_wchar_p, C.c_int32], C.c_int32),
            "SymLoadModuleExW": ([C.c_void_p, C.c_void_p, C.c_wchar_p, C.c_wchar_p,
                                   U64, U32, C.c_void_p, U32], U64),
            "SymFromAddr": ([C.c_void_p, U64, C.POINTER(U64), C.POINTER(SymbolInfo)], C.c_int32),
            "SymFromName": ([C.c_void_p, C.c_char_p, C.POINTER(SymbolInfo)], C.c_int32),
            "SymGetLineFromAddr64": ([C.c_void_p, U64, C.POINTER(U32), C.POINTER(LineInfo)], C.c_int32),
            "SymGetModuleInfo64": ([C.c_void_p, U64, C.POINTER(ModuleInfo)], C.c_int32),
            "SymCleanup": ([C.c_void_p], C.c_int32),
        }
        for name, (args, result) in signatures.items():
            fn = getattr(self.dll, name)
            fn.argtypes, fn.restype = args, result
        # UNDNAME | DEFERRED_LOADS | LOAD_LINES | FAIL_CRITICAL_ERRORS | EXACT_SYMBOLS | NO_PROMPTS.
        self.dll.SymSetOptions(0x2 | 0x4 | 0x10 | 0x200 | 0x400 | 0x80000)
        search = str(dll.parent) + (";" + str(pdb_dir.resolve()) if pdb_dir else "")
        if not self.dll.SymInitializeW(self.process, search, False):
            raise C.WinError(C.get_last_error())
        self.initialized = True
        try:
            self.base = self.dll.SymLoadModuleExW(self.process, None, str(dll), None, 0x10000000, 0, None, 0)
            if not self.base:
                raise C.WinError(C.get_last_error())
            # Force the deferred PDB load before checking identity/type; RVA 0 need not resolve.
            self.resolve(0)
            module = ModuleInfo()
            module.SizeOfStruct = C.sizeof(module)
            if not self.dll.SymGetModuleInfo64(self.process, self.base, C.byref(module)):
                raise C.WinError(C.get_last_error())
            if module.SymType != 3 or module.PdbUnmatched or module.DbgUnmatched:
                raise OSError(f"matching PDB was not loaded for {dll} (DbgHelp SymType={module.SymType})")
            self.pdb_path = bytes(module.LoadedPdbName).decode("mbcs", errors="replace")
            self.image_size = module.ImageSize
        except BaseException:
            self.close()
            raise

    @staticmethod
    def symbol_buffer():
        buffer = C.create_string_buffer(C.sizeof(SymbolInfo) + 4096)
        symbol = C.cast(buffer, C.POINTER(SymbolInfo))
        symbol.contents.SizeOfStruct = C.sizeof(SymbolInfo)
        symbol.contents.MaxNameLen = 4096
        return buffer, symbol

    def named_rva(self, name: str) -> tuple[int, int]:
        """Resolve a real PDB symbol for fixture construction/debugging."""
        buffer, symbol = self.symbol_buffer()
        if not self.dll.SymFromName(self.process, name.encode("ascii"), symbol):
            raise C.WinError(C.get_last_error())
        return symbol.contents.Address - self.base, symbol.contents.Size

    def resolve(self, rva: int) -> Symbol:
        if rva in self.cache:
            return self.cache[rva]
        buffer, info = self.symbol_buffer()
        displacement = U64()
        if self.dll.SymFromAddr(self.process, self.base + rva, C.byref(displacement), info):
            name = C.string_at(C.addressof(buffer) + SymbolInfo.Name.offset, info.contents.NameLen).decode("mbcs", errors="replace")
            symbol_rva = info.contents.Address - self.base
        else:
            name, symbol_rva = f"<unresolved RVA 0x{rva:08X}>", rva
        line, line_delta = LineInfo(), U32()
        line.SizeOfStruct = C.sizeof(line)
        source, number = "", 0
        if self.dll.SymGetLineFromAddr64(self.process, self.base + rva, C.byref(line_delta), C.byref(line)):
            source, number = (line.FileName or b"").decode("mbcs", errors="replace"), line.LineNumber
        result = Symbol(symbol_rva, name, source, number)
        self.cache[rva] = result
        return result

    def close(self):
        if self.initialized:
            self.dll.SymCleanup(self.process)
            self.initialized = False


def print_chains(name: str, values: array, limit: int):
    print(f"\nMain-image {name} stack chains (first 64 distinct; uncaptured={values[-1]}):")
    for i in heapq.nlargest(limit, (i for i in range(64) if values[i]), key=lambda i: values[i]):
        chain = values[128 + i * 16:128 + i * 16 + values[64 + i]]
        print(f"  {values[i]:10d}  " + " -> ".join(f"0x{va:08X}" for va in chain))


def print_runtime_functions(title: str, rows, symbols: DbgHelp | None, limit: int):
    counts: Counter[tuple[int, str]] = Counter()
    locations = {}
    for rva, count in rows:
        if not count:
            continue
        symbol = symbols.resolve(rva) if symbols else Symbol(rva, f"RVA 0x{rva:08X}")
        key = (symbol.rva, symbol.name)
        counts[key] += count
        if key not in locations or count > locations[key][0]:
            locations[key] = (count, symbol.file, symbol.line)
    total = counts.total()
    print(f"\n{title}: {total} runtime observations; top {limit} functions")
    for (rva, name), count in counts.most_common(limit):
        _, source, line = locations[(rva, name)]
        location = f"  {source}:{line}" if source else ""
        print(f"  {count:10d} {100 * count / total:7.3f}%  RVA 0x{rva:08X}  {name}{location}")


def report(profile: Profile, symbols: DbgHelp | None, limit: int = 20, frame_rva: int | None = None):
    h = profile.header
    denominators = [h[4], h[17], h[17], *h[5788 // 4:5788 // 4 + 3], h[10956 // 4]]
    print(f"Profile ABI {profile.abi}: {h[4]} selected-gate samples, {h[17]} tick samples, {h[5]} failed; {h[18]} rounds")
    print("Main-image addresses use preferred base 0x00400000; 64-byte buckets.")
    for name, histogram, total in zip(IMAGE_NAMES, profile.image, denominators):
        print(f"\nMain-image {name}: {sum(histogram)} hits / {total} observations")
        for bucket in heapq.nlargest(limit, (i for i, count in enumerate(histogram) if count), key=histogram.__getitem__):
            count = histogram[bucket]
            print(f"  0x{0x400000 + bucket * 64:08X}  {count:10d}  {100 * count / total if total else 0:7.3f}%")
    for name, chain in profile.chains:
        print_chains(name, chain, min(limit, 12))
    r = profile.runtime
    if r is None:
        print("\nABI 7: no runtime RVA tables; runtime symbols/site attribution/wait callers are unavailable.")
        return
    print(f"\nRuntime module base=0x{r['runtime_base']:08X}, size=0x{r['runtime_size']:08X}")
    if symbols:
        print(f"PDB: {symbols.pdb_path} (symbol base=0x{symbols.base:08X})")
    print("Worker heuristic: runtime EIP during tick, excluding actual owner and published AI thread; not exact pool membership.")
    print("All threads: actual tick windows plus main-thread observations outside ticks; sampler excluded.")
    print("64-byte bucket-start symbol/line attribution may straddle functions; samples are occupancy, not time.")
    names = ["Runtime all threads", "Runtime tick thread", "Runtime workers (heuristic)",
             f"Runtime tick thread inside site {r['selected_site'] - 1}" if r["selected_site"] else "Runtime tick thread selected gate (whole tick)"]
    for name, histogram in zip(names, profile.runtime_hist):
        print_runtime_functions(name, ((i * 64, n) for i, n in enumerate(histogram)), symbols, limit)
    if r["selected_site"] != 14:
        print("\nSite 13 exact gate unavailable: capture with --profile-site 13, or use --frame-va/--frame-rva for a stack-frame hint.")
    if frame_rva is not None:
        frame_rva = frame_rva // 64 * 64
        print_runtime_functions(f"Runtime tick thread with frame RVA 0x{frame_rva:08X} (stack-scan hint, NOT proven site 13)",
                                ((rva, count) for rva, frame, count in profile.pairs if frame == frame_rva), symbols, limit)
    print(f"\nTick runtime / main-image frame pairs: retained={len(profile.pairs)} header_count={r['pair_count']} dropped={r['pair_overflow']}")
    print("Each sample may have multiple frame pairs; do not sum frame gates. Frames may be stale stack words.")
    for rva, frame, count in heapq.nlargest(limit, profile.pairs, key=lambda row: row[2]):
        symbol = symbols.resolve(rva).name if symbols else ""
        print(f"  {count:10d} runtime RVA 0x{rva:08X}  frame RVA 0x{frame:08X} VA 0x{0x400000 + frame:08X}  {symbol}")
    print_runtime_functions("Tick wait-stub callers inside runtime", ((rva, count) for rva, _, count in profile.waits), symbols, limit)
    print(f"Wait samples={r['wait_samples']} unresolved={r['wait_unresolved']} direct=[ESP]:{r['wait_direct']} scanned={r['wait_scanned']} dropped={r['wait_overflow']}")
    print("Exact return-RVA rows (first call-validated runtime stack return; scanned callers may be stale):")
    for rva, kind, count in heapq.nlargest(limit, profile.waits, key=lambda row: row[2]):
        symbol = symbols.resolve(rva).name if symbols else ""
        print(f"  {count:10d}  RVA 0x{rva:08X}  {WAIT_NAMES[kind]}  {symbol}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("profile", type=Path)
    parser.add_argument("--dll", type=Path, default=Path(__file__).resolve().parents[2] / "build/kntwr/bin/Release/kntwr_runtime.dll")
    parser.add_argument("--pdb-dir", type=Path, help="additional local directory containing the matching PDB")
    parser.add_argument("--no-symbols", action="store_true", help="explicitly print raw RVAs without loading DbgHelp")
    parser.add_argument("--top", type=int, default=20)
    gate = parser.add_mutually_exclusive_group()
    gate.add_argument("--frame-rva", type=lambda value: int(value, 0), help="gate on one main-image frame bucket RVA")
    gate.add_argument("--frame-va", type=lambda value: int(value, 0), help="gate on one preferred-base main-image address")
    args = parser.parse_args(argv)
    if args.top < 1:
        parser.error("--top must be positive")
    symbols = None
    try:
        profile = parse_profile(args.profile)
        frame = args.frame_rva if args.frame_va is None else args.frame_va - 0x400000
        if frame is not None and not 0 <= frame < len(profile.image[0]) * 64:
            raise ValueError("frame address is outside the main-image histograms")
        if profile.runtime and not args.no_symbols:
            symbols = DbgHelp(args.dll, args.pdb_dir)
            if symbols.image_size != profile.runtime["runtime_size"]:
                raise ValueError("DLL image size differs from capture; supply the DLL/PDB from the profiled build")
        report(profile, symbols, args.top, frame)
        return 0
    except (OSError, ValueError) as error:
        print(f"profile_symbolize: {error}", file=sys.stderr)
        return 1
    finally:
        if symbols:
            symbols.close()


if __name__ == "__main__":
    raise SystemExit(main())
