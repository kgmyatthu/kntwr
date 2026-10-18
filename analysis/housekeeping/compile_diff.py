#!/usr/bin/env python3
"""Diff two extract_compile.py dumps (before/after the source-layout move).

Projects are matched by file name (CMake may place a target's .vcxproj in a sub-directory after composing per domain).
The before-side source paths are rewritten through the git rename map of <base>..<head>, so the ONLY accepted
difference is the source path itself.  Everything else - every compile/link setting, include directory, per-item
metadata, item (= link) order, project reference - must be equal.

<head-rev> is the commit that performed the pure moves (100 % renames); later commits only edit contents.
Intermediate object dirs of object libraries (<build>/src/<domain>/<target>.dir) are folded to <build>/<target>.dir.

usage: compile_diff.py <before.json> <after.json> <base-rev> <head-rev>
exit status 0 = identical modulo moved paths, 1 = differences (printed)
"""
import json
import os
import re
import subprocess
import sys


def rename_map(root, base, head):
    out = subprocess.run(["git", "diff", "--name-status", "-M100%", base, head],
                         cwd=root, capture_output=True, text=True, check=True).stdout
    m = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if parts[0].startswith("R"):
            m["<ROOT>/" + parts[1]] = "<ROOT>/" + parts[2]
    return m


def remap(text, m):
    for old, new in m.items():
        text = text.replace(old, new)
    return text


def by_name(d):
    return {os.path.basename(k): v for k, v in d.items()}


def main():
    before_p, after_p, base, head = sys.argv[1:5]
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    m = rename_map(root, base, head)
    before = json.loads(remap(open(before_p, encoding="utf-8").read(), m))
    # per-domain object libraries keep their intermediate dir under <BUILD>/src/<domain>/; that location is not a setting
    after = json.loads(re.sub(r"<BUILD>/src/[a-z0-9_]+/", "<BUILD>/", open(after_p, encoding="utf-8").read()))
    b, a = by_name(before), by_name(after)
    bad = 0
    for name in sorted(set(b) | set(a)):
        if name not in b or name not in a:
            print(f"PROJECT only on one side: {name} (before={name in b}, after={name in a})")
            bad += 1
            continue
        pb, pa = b[name], a[name]
        for section in ("defs", "props", "refs", "items"):
            if pb[section] != pa[section]:
                bad += 1
                print(f"DIFF {name} [{section}]")
                if section in ("refs", "items"):
                    print("  before:", json.dumps(pb[section])[:1500])
                    print("  after :", json.dumps(pa[section])[:1500])
                else:
                    for k in sorted(set(pb[section]) | set(pa[section])):
                        if pb[section].get(k) != pa[section].get(k):
                            print(f"  {k}:\n    before: {pb[section].get(k)}\n    after : {pa[section].get(k)}")
    n_items = sum(len(p["items"]) for p in a.values())
    print(f"{len(a)} projects / {n_items} source items compared; {len(m)} renamed paths mapped; "
          f"{'IDENTICAL modulo moved source paths' if not bad else str(bad) + ' differing sections'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
