#!/usr/bin/env python3
"""Per-section identity report for two builds of the same PE32 image (before/after the source-layout move).

For every PE pair it prints the COFF/optional-header facts that legitimately move (link timestamp, checksum), then the
section table with raw size, virtual size and SHA-256 of the raw bytes of each side, and a verdict per section.

A differing section is not accepted on sight.  Every differing byte run is attributed to one of the known
build-identity fields:
  - the IMAGE_DEBUG_DIRECTORY table itself (TimeDateStamp per entry)
  - the raw data of a debug entry (CodeView RSDS: PDB GUID, age, PDB path; repro / POGO / feature entries)
  - an embedded source/build path string (a byte run inside a NUL-terminated ASCII string that contains a backslash or
    slash path of this repository or its build directory, i.e. __FILE__ / __FILEW__ / assert text)
Any differing run that is none of these is reported as UNEXPLAINED and makes the exit status non-zero.  .text must be
byte-identical outright (no attribution is attempted for it).  Also lists every source-path string present in each
image so the effect of the move on __FILE__ literals is visible (and the image-wide count of such strings).

usage: pe_section_compare.py [--out report.txt] before.dll after.dll [before.exe after.exe ...]
"""
import hashlib
import re
import struct
import sys


class PE:
    def __init__(self, path):
        self.path = path
        self.data = open(path, "rb").read()
        d = self.data
        e = struct.unpack_from("<I", d, 0x3C)[0]
        assert d[e:e + 4] == b"PE\0\0", path
        (self.machine, nsec, self.timestamp, _, _, optsz, self.characteristics) = struct.unpack_from("<HHIIIHH", d, e + 4)
        o = e + 24
        magic = struct.unpack_from("<H", d, o)[0]
        assert magic == 0x10B, "PE32 only"
        self.entry_rva = struct.unpack_from("<I", d, o + 16)[0]
        self.image_base = struct.unpack_from("<I", d, o + 28)[0]
        self.size_of_image = struct.unpack_from("<I", d, o + 56)[0]
        self.checksum = struct.unpack_from("<I", d, o + 64)[0]
        self.checksum_off = o + 64
        ndd = struct.unpack_from("<I", d, o + 92)[0]
        self.datadirs = [struct.unpack_from("<II", d, o + 96 + 8 * i) for i in range(ndd)]
        so = o + optsz
        self.sections = []
        for i in range(nsec):
            name, vsize, va, rsize, rptr = struct.unpack_from("<8sIIII", d, so + 40 * i)
            self.sections.append({"name": name.rstrip(b"\0").decode("latin1"), "vsize": vsize, "va": va,
                                  "rsize": rsize, "rptr": rptr})
        self.header_end = so + 40 * nsec

    def raw(self, s):
        return self.data[s["rptr"]:s["rptr"] + s["rsize"]]

    def rva_to_off(self, rva):
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
                return s["rptr"] + rva - s["va"]
        raise ValueError(hex(rva))

    def debug_entries(self):
        """[(table_off, entry_index, type, raw_off, size)]"""
        if len(self.datadirs) <= 6 or self.datadirs[6][0] == 0:
            return []
        rva, size = self.datadirs[6]
        off = self.rva_to_off(rva)
        out = []
        for i in range(size // 28):
            eo = off + 28 * i
            (_, _, _, _, typ, sz, _, ptr) = struct.unpack_from("<IIHHIIII", self.data, eo)
            out.append((eo, i, typ, ptr, sz))
        return out


DEBUG_TYPES = {1: "COFF", 2: "CODEVIEW", 4: "MISC", 9: "BORLAND", 12: "VC_FEATURE", 13: "POGO", 14: "ILTCG",
               16: "REPRO", 20: "EX_DLLCHARACTERISTICS"}
PATH_RE = re.compile(rb"[ -~]{0,400}(?:[A-Za-z]:[\\/]|[\\/]ntw2[\\/]|\bsrc[\\/])[ -~]{0,400}")


WIDE_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def diff_runs(a, b):
    """maximal [start,end) runs where equal-length a and b differ (runs closer than 4 bytes are merged)."""
    runs = []
    i, n = 0, len(a)
    while i < n:
        if a[i] != b[i]:
            j = i + 1
            last = i
            while j < n and j - last <= 4:
                if a[j] != b[j]:
                    last = j
                j += 1
            runs.append((i, last + 1))
            i = last + 1
        else:
            i += 1
    return runs


def cstring_bounds(buf, pos):
    s = pos
    while s > 0 and buf[s - 1] != 0:
        s -= 1
    e = pos
    while e < len(buf) and buf[e] != 0:
        e += 1
    return s, e


def source_paths(pe):
    out = []
    for s in pe.sections:
        raw = pe.raw(s)
        for m in PATH_RE.finditer(raw):
            t = m.group(0)
            if b"ntw2" in t.lower() or b"src" in t.lower():
                out.append((s["name"], s["rptr"] + m.start(), t.decode("latin1")))
        for m in WIDE_RE.finditer(raw):  # __FILEW__ / wide literals
            t = m.group(0).decode("utf-16-le")
            if re.search(r"(?:[A-Za-z]:[\\/]|[\\/]ntw2[\\/]|\bsrc[\\/])", t):
                out.append((s["name"] + "(wide)", s["rptr"] + m.start(), t))
    return out


def compare(pa, pb, w):
    A, B = PE(pa), PE(pb)
    bad = []
    w(f"=== {pa}\n    vs {pb}")
    w(f"link timestamp  before {A.timestamp:#010x}  after {B.timestamp:#010x}"
      f"{'' if A.timestamp == B.timestamp else '   (differs: expected, the linker stamps the build)'}")
    w(f"header checksum before {A.checksum:#010x}  after {B.checksum:#010x}"
      f"{'' if A.checksum == B.checksum else '   (differs: derived from the differing bytes below)'}")
    w(f"entry RVA {A.entry_rva:#x}/{B.entry_rva:#x}  image base {A.image_base:#x}/{B.image_base:#x}  "
      f"SizeOfImage {A.size_of_image:#x}/{B.size_of_image:#x}  machine {A.machine:#x}/{B.machine:#x}")
    if (A.entry_rva, A.image_base, A.size_of_image, A.machine) != (B.entry_rva, B.image_base, B.size_of_image, B.machine):
        bad.append("header layout differs")
    if [(s["name"], s["va"], s["vsize"], s["rsize"]) for s in A.sections] != \
       [(s["name"], s["va"], s["vsize"], s["rsize"]) for s in B.sections]:
        bad.append("section table (names/VA/sizes) differs")
    w("")
    w(f"{'section':9} {'VA':>8} {'vsize':>9} {'rawsize':>9}  {'sha256(before)':16} {'sha256(after)':16}  verdict")
    w("-" * 100)
    for sa, sb in zip(A.sections, B.sections):
        ra, rb = A.raw(sa), B.raw(sb)
        ha, hb = hashlib.sha256(ra).hexdigest(), hashlib.sha256(rb).hexdigest()
        verdict = "IDENTICAL" if ra == rb else "differs"
        w(f"{sa['name']:9} {sa['va']:#8x} {sa['vsize']:9d} {sa['rsize']:9d}  {ha[:16]} {hb[:16]}  {verdict}")
        if ra != rb:
            if sa["name"] == ".text" or len(ra) != len(rb):
                bad.append(f"{sa['name']} differs and is not attributable")
                continue
            # attribution of the differing runs
            known = []  # (file_off_start, end, label)
            for eo, i, typ, ptr, sz in A.debug_entries():
                known.append((eo, eo + 28, f"debug directory entry {i} header"))
                if ptr:
                    known.append((ptr, ptr + sz, f"debug entry {i} data ({DEBUG_TYPES.get(typ, typ)})"))
            base = sa["rptr"]
            for s0, e0 in diff_runs(ra, rb):
                fo0, fo1 = base + s0, base + e0
                label = None
                for k0, k1, lab in known:
                    if k0 <= fo0 and fo1 <= k1:
                        label = lab
                        break
                if label is None:
                    cs, ce = cstring_bounds(ra, s0)
                    ta, tb = ra[cs:ce], rb[cs:ce]
                    if PATH_RE.search(ta) or PATH_RE.search(tb):
                        label = "source/build path string"
                w(f"    diff {sa['name']}+{s0:#x} (file {fo0:#x}) len {e0 - s0}: "
                  f"{label or 'UNEXPLAINED'}")
                if label is None:
                    bad.append(f"{sa['name']}+{s0:#x} len {e0 - s0} unexplained")
                    w(f"        before: {ra[s0:e0][:48].hex()}\n        after : {rb[s0:e0][:48].hex()}")
                elif label.startswith("source/build path"):
                    w(f"        before: {ta.decode('latin1')}\n        after : {tb.decode('latin1')}")
    # CodeView entries (PDB path/GUID/age) for the record
    for tag, pe in (("before", A), ("after", B)):
        for eo, i, typ, ptr, sz in pe.debug_entries():
            if typ == 2:
                d = pe.data[ptr:ptr + sz]
                guid = d[4:20].hex()
                age = struct.unpack_from("<I", d, 20)[0]
                path = d[24:].split(b"\0")[0].decode("latin1")
                w(f"CodeView {tag}: GUID {guid} age {age} pdb {path}")
    # every source-path literal in each image
    for tag, pe in (("before", A), ("after", B)):
        sp = source_paths(pe)
        w(f"source/build path strings in {tag}: {len(sp)}")
        for sec, off, t in sp:
            w(f"    {sec}+{off:#x}: {t}")
    w("")
    return bad


def main():
    args = sys.argv[1:]
    out = None
    if args and args[0] == "--out":
        out = args[1]
        args = args[2:]
    assert args and len(args) % 2 == 0, __doc__
    lines = []

    def w(s=""):
        lines.append(s)
        print(s)

    bad = []
    for i in range(0, len(args), 2):
        bad += [f"{args[i + 1]}: {b}" for b in compare(args[i], args[i + 1], w)]
    w("VERDICT: " + ("FUNCTIONALLY IDENTICAL - .text byte-identical, every other difference attributed to debug-directory / path fields"
                     if not bad else "DEFECT: " + "; ".join(bad)))
    if out:
        open(out, "w", encoding="utf-8", newline="\n").write("\n".join(lines) + "\n")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
