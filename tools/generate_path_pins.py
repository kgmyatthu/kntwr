#!/usr/bin/env python3
"""Generate src/path/native_path_runtime_pins.inc: source pins for native_path_runtime.cpp.

Build-time only.  The runtime executes ORIGINAL image code (successor 0x800210 and its direct-call closure on the owner
thread, the original 0x8026F0 on every fallback) and mirrors the semantics of 0x8026F0 / 0x802A80 / 0x7E04D0 in
ntw_path_workspace.  Both assumptions are only valid for the pinned bytes, so the runtime refuses to start unless every
pinned span of the LIVE image hashes (FNV-1a64, HIGHLOW relocations rebased to the preferred base) to the value recorded
here and every pinned data word (vtable slots, constants) holds the recorded value.

Function extents are NOT taken from a heuristic: each function is walked as a control-flow graph from its entry
(conditional/unconditional in-function branches followed, call targets recorded, ret/int3 ends a path).  The walk fails on
an indirect jump, on a branch outside 0x4000 bytes, and the extent must be followed by int3/nop padding.

Usage: python generate_path_pins.py [--image PATH] [--output PATH] [--check] [--report PATH]
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import generate_clone_specs as g  # noqa: E402  (Image, ENGINE, fnv1a64, fail, GenerationError)
from capstone import x86  # noqa: E402

DEFAULT_IMAGE = g.DEFAULT_IMAGE
OUTPUT = HERE.parent / 'src' / 'path' / 'native_path_runtime_pins.inc'

# Entries whose bodies the runtime executes live (owner thread) or replaces. Role strings are documentation only.
ROOTS = {
    0x800210: 'successor (ORIGINAL, owner thread, private G)',
    0x8026F0: 'solve driver (ORIGINAL on every fallback; mirrored by Workspace::Begin/Advance/FinishLeg)',
    0x802A80: 'engine prologue mirrored by Workspace::SeedSearch',
    0x7E04D0: 'engine loop mirrored by Workspace::Advance/Relax',
    0x7EB210: 'seed node builder (ORIGINAL, owner thread)',
    0x7EB020: 'G constructor (layout reference)',
    0x807620: 'path unwinding mirrored by Workspace::BuildOutput',
    0x7FE320: 'region flag (ORIGINAL)',
}
# Never followed: reaching any of these means the function is unsupported / not a pure planning step.  They are pinned as
# call targets only when the runtime itself calls them (EXTERNAL_CALLS) so their ABI (first bytes) is guarded.
STOP = {
    0x67A790: 'cell lookup (global scratch, TLS epoch, CRT lock)',
    0x10D3140: 'game heap allocate (new arena block)', 0xFF7F20: 'game heap allocate', 0xFF7EF0: 'game heap free',
    0x444B40: 'vector storage allocate', 0x126DF40: 'CRT lock', 0x126E299: 'CRT atexit', 0x126DEF6: 'CRT epoch',
    0x4C3900: 'EnterCriticalSection thunk', 0x4C3A00: 'LeaveCriticalSection thunk', 0x4C3920: 'CRITICAL_SECTION init',
    0x7F4950: 'object-space transform (80E9D0 tail): read only, followed explicitly below',
    # CRT aligned allocator behind the hash bucket-array helpers 0x4536A0 (called by 7EB020 / 814270) and 0x453A60 (814270).
    # Reached only by the ORIGINAL ctor / fallback 0x8026F0 on the live game heap; the private workspace replaces them with
    # pre-linked buffers.  .text really spans 0x401000..0x1306900, so the 0x1200000 guard below stays untouched.
    0x1271290: 'CRT _aligned_malloc (hash bucket array)', 0x1271276: 'CRT _aligned_free (hash bucket array)',
}
# Functions whose CFG walk ends at `ret` and is immediately followed by ANOTHER function (no int3/nop padding).  The exact
# extent end is pinned here; the walk would have followed any branch past it, so the extent is exact.
ADJACENT_OK = {
    0x7EB5C0: 0x7EB600,   # next: 7EB600 mov [ecx+0x18],0 ...
    0x80B0F0: 0x80B260,   # next: 80B260 mov eax,fs:[0x2c] ...
    0x808D20: 0x808DA0,   # next: 808DA0 push ecx ...
    0x7F70B0: 0x7F7140,   # next: 7F7140 mov [ecx],0xd ...
}
# Pinned as EXACT spans only; their calls are NOT followed.  The runtime executes only the branch it proved pure: 0x816CA0 query
# kind 0 -> 0x815FA0 -> 0x56CF70 with [sub+0xEC]==0 -> 0x53FBD0.  The kind-1 branch (virtual agent getter, 0x7FD730) and the deep
# 0x56CF70 branch (0x7FC950 cell search) are refused by the runtime before they can run, so they must stay unpinned / unwalked.
SHALLOW = {
    0x816CA0: 'start position + via (kind 0 branch only)', 0x56CF70: 'position of sub-object ([+0xEC]==0 branch only)',
    0x815FA0: 'sub-object address', 0x7EAE90: 'position struct init', 0x53FBD0: 'lea eax,[ecx+0x9c]',
}
# Indirect call targets proven by the successor closure (vtable slots of the allow-listed classes).
VCALL_TARGETS = {
    0x7FFD20: 'class 0x1347260 slot +4', 0x6B7F90: 'gateway 0x133ADD0 slot +0x28', 0x7FF170: 'iface 0x1347248 slot 0',
    0x54E920: 'door 0x1338FD0 slot 0 / embedded 0x132B5D8 slot 0', 0x4470B0: 'gateway slot +0x20',
    0x461180: 'gateway slot +0x18', 0x7023E0: 'endpoint 0x1339004 slot +0xC',
}
# Plain data words the runtime relies on (vtable slots, constants).  (address, comment)
DATA_WORDS = [
    (0x1347260 + 4, 'class 0x1347260 slot 1 -> 7FFD20'),
    (0x133ADD0 + 0x18, 'gateway slot 0x18 -> 461180'), (0x133ADD0 + 0x20, 'gateway slot 0x20 -> 4470B0'),
    (0x133ADD0 + 0x28, 'gateway slot 0x28 -> 6B7F90'),
    (0x1347248 + 0, 'iface 0x1347248 slot 0 -> 7FF170'),
    (0x1338FD0 + 0, 'door slot 0 -> 54E920'), (0x132B5D8 + 0, 'embedded slot 0 -> 54E920'),
    (0x1339004 + 0xC, 'endpoint slot 0xC -> 7023E0'),
    (0x1347250, 'graph vtable (G+0)'),
    (0x1318034, 'epsilon 0.01'), (0x1318038, '0.5'), (0x1318048, '1.0'), (0x1325D14, '2.0'), (0x131A7B8, '1.5'),
    # NOT pinned: 0x150FCA0..0x150FCB0 (20-byte sentinel read by 7EB1A0 / 7EAE90 / 8026F0 epilogue / 800210).  The range lies in
    # .data BEYOND its raw data (0x144E000 + 0x1F600), i.e. it is zero-initialised BSS with no file bytes, and it is writable game
    # state.  The runtime therefore reads it LIVE (npr_initialize -> workspace constants), snapshots it per request at planning,
    # adds it to the request's read set, and compares it again at consumption (see native_path_runtime.cpp BuildInputsImpl /
    # ValidateImpl); Materialize writes the live values back, never a baked constant.
]
MAX_FUNC = 0x4000


def walk(image, entry):
    """CFG walk. Returns (end, sorted instruction list, call targets, indirect calls[(va, text)])."""
    seen = {}
    work = [entry]
    calls = set()
    icalls = []
    limit = entry + MAX_FUNC
    code = image.read(entry, MAX_FUNC)
    while work:
        a = work.pop()
        while True:
            if a in seen:
                break
            if not (entry <= a < limit):
                g.fail(f'{entry:#x}: control flow leaves the function window at {a:#x}')
            ins = next(g.ENGINE.disasm(code[a - entry:a - entry + 16], a, 1), None)
            if ins is None:
                g.fail(f'{entry:#x}: undecodable bytes at {a:#x}')
            seen[a] = ins
            m = ins.mnemonic
            if m == 'int3':
                g.fail(f'{entry:#x}: int3 reached inside the walk at {a:#x}')
            if m == 'call':
                o = ins.operands[0]
                if o.type == x86.X86_OP_IMM:
                    calls.add(o.imm & 0xFFFFFFFF)
                else:
                    icalls.append((a, f'{ins.mnemonic} {ins.op_str}'))
            if m == 'ret':
                break
            if m == 'jmp':
                o = ins.operands[0]
                if o.type != x86.X86_OP_IMM:
                    icalls.append((a, f'tail {ins.mnemonic} {ins.op_str}'))   # e.g. 7FF170 `jmp eax` into an embedded slot
                    break
                t = o.imm & 0xFFFFFFFF
                if not (entry <= t < limit):
                    # tail jump to another function: record as a call target and end the path
                    calls.add(t)
                    break
                work.append(t)
                break
            if m.startswith('j') and m not in ('jmp',):
                o = ins.operands[0]
                if o.type != x86.X86_OP_IMM:
                    g.fail(f'{entry:#x}: indirect jcc at {a:#x}')
                t = o.imm & 0xFFFFFFFF
                if not (entry <= t < limit):
                    g.fail(f'{entry:#x}: conditional branch outside window at {a:#x} -> {t:#x}')
                work.append(t)
            a += ins.size
    end = max(i.address + i.size for i in seen.values())
    pad = image.read(end, 1)[0]
    if pad not in (0xCC, 0x90) and ADJACENT_OK.get(entry) != end:
        # a function may be followed by a data table or another function without padding; require explicit review
        g.fail(f'{entry:#x}: extent {end:#x} is not followed by int3/nop padding (byte {pad:#x})')
    return end, sorted(seen.values(), key=lambda i: i.address), calls, icalls


def closure(image):
    funcs = {}
    order = []
    work = list(ROOTS) + list(VCALL_TARGETS) + list(SHALLOW) + [0x7F4950]
    stops = []
    while work:
        va = work.pop()
        if va in funcs or va in STOP and va != 0x7F4950:
            if va in STOP and va != 0x7F4950 and va not in stops:
                stops.append(va)
            continue
        if va < 0x401000 or va >= 0x1200000:
            g.fail(f'call target {va:#x} is outside the analysed code range')
        end, ins, calls, icalls = walk(image, va)
        funcs[va] = dict(va=va, size=end - va, calls=sorted(calls), icalls=icalls)
        order.append(va)
        if va in SHALLOW:
            continue   # exact span only
        for c in calls:
            if c not in funcs:
                work.append(c)
    return funcs, sorted(set(stops))


def build(image_path):
    image = g.Image(image_path)
    funcs, stops = closure(image)
    spans = []
    for va in sorted(funcs):
        f = funcs[va]
        data = image.read(va, f['size'])
        relocs = [r - va for r in image.span_relocs(va, f['size'])]
        spans.append(dict(va=va, size=f['size'], hash=g.fnv1a64(_rebase(data, relocs)), relocs=relocs))
    words = []
    for va, comment in DATA_WORDS:
        v = struct.unpack('<I', image.read(va, 4))[0]
        words.append(dict(va=va, value=v, reloc=int(image.span_relocs(va, 4) == [va]), comment=comment))
    return image, funcs, stops, spans, words


def _rebase(data, relocs):
    # the stored bytes are the file bytes (already preferred-base values), identical to a live span with delta subtracted
    return data


def render(spans, words, sha):
    out = []
    out.append(f'// GENERATED by tools/generate_path_pins.py from the approved Napoleon.exe (SHA-256 {sha}).  Do not edit.')
    out.append('// kSources: FNV-1a64 over the span with each HIGHLOW dword rebased to the preferred base; kWords: pinned data words.')
    rel_all = []
    out.append('static const NprSourceSpan kSources[%d] = {' % len(spans))
    for s in spans:
        start = len(rel_all)
        rel_all.extend(s['relocs'])
        out.append('    {0x%08Xu, 0x%Xu, 0x%016XULL, %d, %d},' % (s['va'], s['size'], s['hash'], start, len(s['relocs'])))
    out.append('};')
    out.append('static const uint32_t kSourceRelocs[%d] = {' % max(1, len(rel_all)))
    line = '   '
    for r in rel_all or [0]:
        item = ' 0x%Xu,' % r
        if len(line) + len(item) > 118:
            out.append(line)
            line = '   '
        line += item
    out.append(line)
    out.append('};')
    out.append('static const NprDataWord kWords[%d] = {' % len(words))
    for w in words:
        out.append('    {0x%08Xu, 0x%08Xu, %d},  // %s' % (w['va'], w['value'], w['reloc'], w['comment']))
    out.append('};')
    return '\n'.join(out) + '\n'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--image', default=DEFAULT_IMAGE)
    ap.add_argument('--output', default=str(OUTPUT))
    ap.add_argument('--report')
    ap.add_argument('--check', action='store_true')
    a = ap.parse_args()
    image, funcs, stops, spans, words = build(a.image)
    text = render(spans, words, image.sha256)
    if a.report:
        Path(a.report).write_text(json.dumps(dict(
            functions={hex(v): dict(size=f['size'], calls=[hex(c) for c in f['calls']], icalls=f['icalls'])
                       for v, f in sorted(funcs.items())}, stops=[hex(s) for s in stops]), indent=1))
    out = Path(a.output)
    if a.check:
        if not out.exists() or out.read_text() != text:
            print('DRIFT: pins differ', file=sys.stderr)
            return 1
        return 0
    out.write_text(text)
    print(f'{len(spans)} spans, {sum(s["size"] for s in spans)} bytes, {len(words)} words, stops {[hex(s) for s in stops]}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
