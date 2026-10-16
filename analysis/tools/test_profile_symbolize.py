#!/usr/bin/env python3
"""Offline integration checks: real ABI-7 capture and synthetic ABI-8 + real PDB.

Run under ntw2_run_limited.exe 512 8192 180 -- python this_file.py
  --abi7 ../analysis/ntw2-live-receipt-cc-owned2.json.profile.bin
  --dll build/native/bin/Release/ntw2_runtime.dll
The synthetic file is written into a temporary directory and removed on exit.
No runtime build or live game is required. No symbol mocks are used.
"""
import argparse
from contextlib import redirect_stdout
import io
from pathlib import Path
import struct
import tempfile
import unittest

import profile_symbolize as ps


def fixture(runtime_size, bucket_rva, return_rva, code_bytes=None):
    image_buckets = 8
    header = bytearray(ps.HEADER_BYTES)
    struct.pack_into("<6I", header, 0, 8, len(header), 64, image_buckets, 20, 0)
    struct.pack_into("<I", header, 17 * 4, 9)
    image = bytearray(image_buckets * 4 * 7)
    struct.pack_into("<I", image, 3 * 4, 12)
    runtime_buckets = ((runtime_size if code_bytes is None else code_bytes) + 63) // 64
    runtime = dict.fromkeys(ps.RUNTIME_FIELDS, 0)
    runtime.update(magic=ps.RUNTIME_MAGIC, version=1, bytes=96 + runtime_buckets * 16 + 8192 * 12 + 1024 * 12,
                   runtime_base=0x62000000, runtime_size=runtime_size, bucket_bytes=64,
                   bucket_count=runtime_buckets, histogram_count=4, pair_capacity=8192,
                   pair_count=2, wait_capacity=1024, wait_count=2, wait_samples=5,
                   wait_direct=3, wait_scanned=2, tick_runtime_samples=9,
                   worker_runtime_samples=11, all_runtime_samples=20, selected_runtime_samples=7,
                   selected_site=14, flags=7 if code_bytes is None else 15)
    histograms = bytearray(runtime_buckets * 16)
    bucket = bucket_rva // 64
    for table, count in enumerate((20, 9, 11, 7)):
        struct.pack_into("<I", histograms, (table * runtime_buckets + bucket) * 4, count)
    pairs = bytearray(8192 * 12)
    struct.pack_into("<6I", pairs, 0, bucket_rva, 64, 7, bucket_rva, 128, 2)
    waits = bytearray(1024 * 12)
    struct.pack_into("<6I", waits, 0, return_rva, 0, 3, return_rva, 1, 2)
    return (header + image + bytes(ps.CHAIN_BYTES)
            + ps.RUNTIME_HEADER.pack(*(runtime[key] for key in ps.RUNTIME_FIELDS))
            + histograms + pairs + waits)


class ProfileTests(unittest.TestCase):
    def test_existing_abi7(self):
        profile = ps.parse_profile(ARGS.abi7)
        self.assertEqual(profile.abi, 7)
        self.assertEqual(profile.header[4], 1173821)
        self.assertEqual(sum(profile.image[0]), 39458)
        self.assertEqual(profile.image[0][(0x1202CC0 - 0x400000) // 64], 1426)
        self.assertEqual(sum(profile.image[1]), 10804)
        self.assertIsNone(profile.runtime)
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(ps.main([str(ARGS.abi7), "--top", "3"]), 0)
        self.assertIn("0x01202CC0        1426", output.getvalue())
        self.assertIn("ABI 7: no runtime RVA tables", output.getvalue())
        self.assertIn("Main-image main A2", output.getvalue())
        self.assertIn("Main-image main A1 stack chains", output.getvalue())

    def test_executable_prefix_geometry(self):
        with tempfile.TemporaryDirectory(prefix="ntw2-profile-prefix-") as directory:
            path = Path(directory) / "prefix.profile.bin"
            data = fixture(0x10000, 0x80, 0x81, code_bytes=0x1000)
            path.write_bytes(data)
            profile = ps.parse_profile(path)
            self.assertEqual(profile.runtime["runtime_size"], 0x10000)
            self.assertEqual(profile.runtime["bucket_count"], 0x1000 // 64)
            self.assertEqual([sum(table) for table in profile.runtime_hist], [20, 9, 11, 7])
            offset = ps.HEADER_BYTES + 8 * 4 * 7 + ps.CHAIN_BYTES
            missing_flag = bytearray(data)
            struct.pack_into("<I", missing_flag, offset + 23 * 4, 7)
            path.write_bytes(missing_flag)
            with self.assertRaisesRegex(ValueError, "table geometry"):
                ps.parse_profile(path)
            beyond_image = bytearray(data)
            struct.pack_into("<I", beyond_image, offset + 4 * 4, 0x800)
            path.write_bytes(beyond_image)
            with self.assertRaisesRegex(ValueError, "table geometry"):
                ps.parse_profile(path)

    def test_synthetic_abi8_real_pdb(self):
        symbols = ps.DbgHelp(ARGS.dll)
        try:
            start, size = symbols.named_rva("ntw2_profile_start")
            bucket = (start + 63) // 64 * 64
            self.assertGreater(size, bucket - start + 1)
            symbol = symbols.resolve(bucket)
            self.assertIn("ntw2_profile_start", symbol.name)
            self.assertTrue(symbol.file.endswith("ntw2_profile.cpp"), symbol)
            self.assertGreater(symbol.line, 0)
            runtime_size = symbols.image_size
            expected_name = symbol.name
            pdb = symbols.pdb_path
        finally:
            symbols.close()
        with tempfile.TemporaryDirectory(prefix="ntw2-profile-") as directory:
            path = Path(directory) / "synthetic.profile.bin"
            data = fixture(runtime_size, bucket, bucket + 1)
            path.write_bytes(data)
            profile = ps.parse_profile(path)
            self.assertEqual(profile.runtime["selected_site"], 14)
            self.assertEqual([sum(table) for table in profile.runtime_hist], [20, 9, 11, 7])
            self.assertEqual(profile.pairs, [(bucket, 64, 7), (bucket, 128, 2)])
            self.assertEqual(profile.waits, [(bucket + 1, 0, 3), (bucket + 1, 1, 2)])
            output = io.StringIO()
            with redirect_stdout(output):
                result = ps.main([str(path), "--dll", str(ARGS.dll), "--frame-rva", "0x40", "--top", "3"])
            self.assertEqual(result, 0)
            text = output.getvalue()
            for expected in (expected_name, "Runtime all threads: 20", "Runtime tick thread: 9",
                             "Runtime workers (heuristic): 11", "Runtime tick thread inside site 13: 7",
                             "Tick wait-stub callers inside runtime: 5", "0x004000C0          12",
                             "frame RVA 0x00000040 (stack-scan hint, NOT proven site 13): 7",
                             "direct=[ESP]:3 scanned=2", "ntw2_profile.cpp:"):
                self.assertIn(expected, text)
            # Parse structural failures rather than accepting a partial or wrong table.
            path.write_bytes(data[:-1])
            with self.assertRaisesRegex(ValueError, "section length"):
                ps.parse_profile(path)
            path.write_bytes(data[:ps.HEADER_BYTES + 8 * 4 * 7 + ps.CHAIN_BYTES])
            with self.assertRaisesRegex(ValueError, "missing NTR8"):
                ps.parse_profile(path)
            bad = bytearray(data)
            offset = ps.HEADER_BYTES + 8 * 4 * 7 + ps.CHAIN_BYTES
            struct.pack_into("<I", bad, offset + 9 * 4, 8193)
            path.write_bytes(bad)
            with self.assertRaisesRegex(ValueError, "occupied counts"):
                ps.parse_profile(path)
            # Explicit raw mode must also work without requiring the DLL/PDB.
            path.write_bytes(data)
            raw = io.StringIO()
            with redirect_stdout(raw):
                self.assertEqual(ps.main([str(path), "--no-symbols", "--top", "1"]), 0)
            self.assertIn("Runtime tick thread inside site 13: 7", raw.getvalue())
        print(f"Synthetic ABI 8: resolved RVA 0x{bucket:08X} -> {expected_name}; PDB={pdb}")
        print("Validated all/tick/worker/site13 counts 20/9/11/7, frame gate 7, wait callers 5, source line, and malformed lengths/counts.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--abi7", type=Path, required=True)
    parser.add_argument("--dll", type=Path, required=True)
    ARGS = parser.parse_args()
    unittest.main(argv=[__file__], verbosity=2)
