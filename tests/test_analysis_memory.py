"""Offline regressions for the development tools; no game process is opened."""
import struct
import sys
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / 'tools'))
sys.path.insert(0, str(PROJECT.parents[1] / 'work' / 'pylib'))
import capstone
from native_pe_tools import decode_highlow_relocations, iter_instructions


def block(page, words):
    return struct.pack('<II', page, 8 + 2 * len(words)) + struct.pack('<' + 'H' * len(words), *words)


class AnalysisMemoryTests(unittest.TestCase):
    def setUp(self):
        self.engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.engine.detail = True

    def compare_decode(self, code, count=0):
        base = 0x400000
        def signature(ins):
            return (ins.address, bytes(ins.bytes), ins.mnemonic, ins.op_str,
                    [(op.type, op.imm if op.type == capstone.x86.X86_OP_IMM else
                      (op.mem.base, op.mem.index, op.mem.scale, op.mem.disp) if op.type == capstone.x86.X86_OP_MEM else op.reg)
                     for op in ins.operands])
        expected = [signature(i) for i in self.engine.disasm(code, base, count)]
        actual = [signature(i) for i in iter_instructions(self.engine, lambda va, n: code[va-base:va-base+n], base, len(code), count)]
        self.assertEqual(actual, expected)
        return actual

    def test_instruction_at_batch_boundary_keeps_bytes_and_operands(self):
        # 15-byte instruction at the maximum-size window edge, followed by a call
        # and a memory operand in the next batch.
        code = (b'\x66' * 14 + b'\x90') * 256 + b'\xe8\x12\x34\x00\x00\x8b\x44\x8b\x10\xc3'
        actual = self.compare_decode(code)
        self.assertEqual(actual[-3][0], 0x400000 + 256 * 15)
        self.assertEqual(actual[-3][2], 'call')
        self.assertEqual(actual[-2][2], 'mov')

    def test_count_stops_at_requested_instruction(self):
        actual = self.compare_decode(b'\x90' * 512 + b'\xc3', 257)
        self.assertEqual(actual[-1][0], 0x400100)

    def test_truncated_final_instruction_is_not_skipped(self):
        actual = self.compare_decode(b'\x90' * 257 + b'\xe8\x00')
        self.assertEqual(actual[-1][0], 0x400100)

    def test_relocations_sort_deduplicate_and_ignore_padding(self):
        raw = block(0x2000, [0x3008, 0, 0x3004, 0x3008]) + block(0x1000, [0x300c])
        result = decode_highlow_relocations(raw, 0x3000, 0x400000)
        self.assertEqual(list(result), [0x40100c, 0x402004, 0x402008])
        self.assertEqual(result.itemsize, 4)

    def test_truncated_and_invalid_relocations_fail_closed(self):
        bad = [b'\x00', struct.pack('<II', 0x1000, 7),
               struct.pack('<II', 0x1000, 12) + b'\x00\x30',
               block(0x1000, [0xa004]), block(0x2000, [0x3000]),
               block(0x1000, [0x3ffe])]
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                decode_highlow_relocations(raw, 0x2000)


if __name__ == '__main__':
    unittest.main()
