#!/usr/bin/env python3
"""Dump the effective build recipe of every Visual Studio project in a CMake build tree to normalised JSON.

The VS generator has no compile_commands.json, so the recipe is read from the generated *.vcxproj files:
  - every ItemDefinitionGroup (ClCompile / MASM / Link / Lib / ...) setting  -> compile + link command lines
  - every source / object item (ClCompile, MASM, CLInclude-less) with its per-item metadata, IN ORDER (item order is
    link order, which decides the .text layout)
  - project references and the output name/type
Absolute paths are normalised to <ROOT> (source tree) and <BUILD> (this build dir) so two trees can be compared.

usage: extract_compile.py <build-dir> <out.json>
"""
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

NS = "{http://schemas.microsoft.com/developer/msbuild/2003}"
SKIP_ITEMS = {"CustomBuild", "ProjectReference", "ProjectConfiguration"}
# CMake bookkeeping that legitimately differs between two build trees / CMakeLists layouts
SKIP_PROPS = {"ProjectGuid"}


def make_normaliser(build_dir, root):
    pats = [
        (os.path.abspath(build_dir), "<BUILD>"),
        (os.path.abspath(root), "<ROOT>"),
    ]

    def norm(text):
        if text is None:
            return ""
        t = text.replace("\\", "/")
        for path, tag in pats:
            p = path.replace("\\", "/")
            t = re.sub(re.escape(p), tag, t, flags=re.IGNORECASE)
        return t.strip()

    return norm


def local(tag):
    return tag[len(NS):] if tag.startswith(NS) else tag


def dump_project(path, norm):
    tree = ET.parse(path).getroot()
    out = {"defs": {}, "items": [], "refs": [], "props": {}}
    for el in tree:
        t = local(el.tag)
        if t == "ItemDefinitionGroup":
            for grp in el:
                out["defs"][local(grp.tag)] = {local(c.tag): norm(c.text) for c in grp}
        elif t == "ItemGroup":
            for it in el:
                k = local(it.tag)
                if k == "ProjectReference":
                    n = it.find(NS + "Name")
                    out["refs"].append(n.text if n is not None else norm(it.get("Include")))
                elif k not in SKIP_ITEMS:
                    meta = {local(c.tag): norm(c.text) for c in it}
                    out["items"].append({"kind": k, "path": norm(it.get("Include")), "meta": meta})
        elif t == "PropertyGroup" and el.get("Label") in (None, "Configuration"):
            for c in el:
                n = local(c.tag)
                if n not in SKIP_PROPS:
                    out["props"][n] = norm(c.text)
    return out


def main():
    build_dir, out_json = sys.argv[1], sys.argv[2]
    # the source tree is the parent of analysis/housekeeping
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    norm = make_normaliser(build_dir, root)
    result = {}
    for dp, dns, fns in os.walk(build_dir):
        dns[:] = [d for d in dns if d not in ("CMakeFiles", "Testing") and not d.endswith(".dir")]
        for fn in fns:
            if fn.endswith(".vcxproj"):
                full = os.path.join(dp, fn)
                rel = norm(full)
                result[rel] = dump_project(full, norm)
    with open(out_json, "w", encoding="utf-8", newline="\n") as f:
        json.dump(result, f, indent=1, sort_keys=True)
        f.write("\n")
    n_items = sum(len(p["items"]) for p in result.values())
    print(f"{len(result)} projects, {n_items} source items -> {out_json}")


if __name__ == "__main__":
    main()
