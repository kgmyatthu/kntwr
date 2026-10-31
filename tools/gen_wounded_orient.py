#!/usr/bin/env python3
"""Generate src/animation/kntwr_wounded_orient.h from the stock NTW data.pack.

For every men death animation that carries no FACE_UP/FACE_DOWN trailer tag,
classify the body orientation at the final frame by forward kinematics and
emit a {name-hash -> orientation} table. The --wounded runtime detour uses the
table at anim-table build time to tag untagged death clips in memory so the
native wounded state machine (state 0x4B) accepts them.

Anim file format (verified in runtime/animation.cpp):
  f32 fps, f32 duration, u32 bone_count,
  bone_count x { u16 name_chars, UTF-16LE name, i32 parent },
  u32 frame_count, frame_count x bone_count x 40 bytes
  { f32 pos[3]; f32 quat x,y,z,w; f32 motion[3] },
  trailer: u32 tag_count x { u32 n; n x (u16 chars, UTF-16LE) }.
Model space is Y-up, a standing man faces +Z.

Classification: take the belly axis (world +Z at a standing reference frame)
expressed in the local space of the Spine/Spine1/Spine2 bones, rotate it by
each bone's global rotation at the clip's final frame, and average the Y
component. bellyY > +0.3 ends face-up, < -0.3 ends face-down, otherwise the
clip is left alone (side/kneeling poses stay static corpses).

Validation against the 131 natively tagged men death clips with a nonzero
FACE param: 126 agree, 5 disagree -- each disagreement is a clip whose tag
contradicts its own final pose (e.g. mus_poised_die_f_5 tagged FACE_UP with
belly -0.99), i.e. upstream mislabels.

Hash: FNV-1a 32 over the UTF-16LE bytes of the lowercased path with forward
slashes, exactly as the engine stores clip names (verified live: full path,
lowercase, '/', '.anim' suffix, e.g.
"animations/men/musket/mus_deaths/mus_standt_deaths/mus_stand_t_death_001.anim").

Usage: python tools/gen_wounded_orient.py "F:/NTW2/Napoleon Total War/data/data.pack"
Writes src/animation/kntwr_wounded_orient.h next to this repo.
"""
import struct
import sys
import os

def fnv1a32_utf16(name: str) -> int:
    h = 0x811C9DC5
    for b in name.encode('utf-16-le'):
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h

def parse_pack(path):
    raw = open(path, 'rb').read()
    magic, _ptype, _pfc, pfsz, fc, _fisz = struct.unpack_from('<4sIIIII', raw, 0)
    if magic != b'PFH0':
        raise SystemExit('not a PFH0 pack: %s' % path)
    pos = 24 + pfsz
    entries = []
    for _ in range(fc):
        size = struct.unpack_from('<I', raw, pos)[0]
        pos += 4
        end = raw.index(b'\x00', pos)
        entries.append((raw[pos:end].decode('latin1'), size))
        pos = end + 1
    idx = {}
    cur = pos
    for p, size in entries:
        idx[p.replace('\\', '/').lower()] = (cur, size)
        cur += size
    return raw, idx

def parse_anim(raw, off, size):
    b = memoryview(raw)[off:off + size]
    bc = struct.unpack_from('<I', b, 8)[0]
    p = 12
    names, parents = [], []
    for _ in range(bc):
        n = struct.unpack_from('<H', b, p)[0]
        p += 2
        names.append(bytes(b[p:p + 2 * n]).decode('utf-16-le'))
        p += 2 * n
        parents.append(struct.unpack_from('<i', b, p)[0])
        p += 4
    fcount = struct.unpack_from('<I', b, p)[0]
    p += 4
    need = p + fcount * bc * 40
    if fcount == 0 or need > len(b):
        raise ValueError('truncated frames')
    return b, names, parents, fcount, p

def frame_locals(b, p0, bc, f):
    out = []
    p = p0 + f * bc * 40
    for bi in range(bc):
        v = struct.unpack_from('<10f', b, p + bi * 40)
        out.append(((v[0], v[1], v[2]), (v[3], v[4], v[5], v[6])))
    return out

def quat_mul(a, q):
    ax, ay, az, aw = a
    bx, by, bz, bw = q
    return (aw * bx + ax * bw + ay * bz - az * by,
            aw * by - ax * bz + ay * bw + az * bx,
            aw * bz + ax * by - ay * bx + az * bw,
            aw * bw - ax * bx - ay * by - az * bz)

def quat_rot(q, v):
    t = quat_mul(q, (v[0], v[1], v[2], 0.0))
    x, y, z, _ = quat_mul(t, (-q[0], -q[1], -q[2], q[3]))
    return (x, y, z)

def global_quats(locals_, parents):
    gq = [None] * len(parents)
    for i, (_t, q) in enumerate(locals_):
        par = parents[i]
        gq[i] = q if par < 0 else quat_mul(gq[par], q)
    return gq

def read_tags(b, p0, bc, fcount):
    p = p0 + fcount * bc * 40
    tags = []
    tc = struct.unpack_from('<I', b, p)[0]
    p += 4
    for _ in range(tc):
        sc = struct.unpack_from('<I', b, p)[0]
        p += 4
        strs = []
        for _ in range(sc):
            n = struct.unpack_from('<H', b, p)[0]
            p += 2
            strs.append(bytes(b[p:p + 2 * n]).decode('utf-16-le'))
            p += 2 * n
        tags.append(strs)
    return tags

SPINES = ('spine', 'spine1', 'spine2')
STANDING_REF = 'animations/men/musket/mus_deaths/mus_standt_deaths/mus_stand_t_death_001.anim'

def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__.strip().splitlines()[-2].strip())
    raw, idx = parse_pack(sys.argv[1])

    off, size = idx[STANDING_REF]
    b, names, parents, fcount, p0 = parse_anim(raw, off, size)
    gq0 = global_quats(frame_locals(b, p0, len(names), 0), parents)
    belly_local = {}
    for i, n in enumerate(names):
        if n.lower() in SPINES:
            q = gq0[i]
            belly_local[n.lower()] = quat_rot((-q[0], -q[1], -q[2], q[3]), (0.0, 0.0, 1.0))
    if len(belly_local) != 3:
        raise SystemExit('standing reference lost its spine bones')

    rows, skipped = [], {'tagged': 0, 'unclear': 0, 'parse_fail': 0}
    for path in sorted(idx):
        if not path.endswith('.anim') or '/men/' not in path or 'death' not in path:
            continue
        off, size = idx[path]
        try:
            b, names, parents, fcount, p0 = parse_anim(raw, off, size)
            if any(t and t[0] in ('FACE_UP', 'FACE_DOWN') for t in read_tags(b, p0, len(names), fcount)):
                skipped['tagged'] += 1
                continue
            gq = global_quats(frame_locals(b, p0, len(names), fcount - 1), parents)
            ys = [quat_rot(gq[i], belly_local[n.lower()])[1]
                  for i, n in enumerate(names) if n.lower() in SPINES]
        except Exception:
            skipped['parse_fail'] += 1
            continue
        if not ys:
            skipped['parse_fail'] += 1
            continue
        belly = sum(ys) / len(ys)
        if belly > 0.3:
            rows.append((path, 0, belly))   # ends face-up -> FACE_UP param
        elif belly < -0.3:
            rows.append((path, 1, belly))   # ends face-down -> FACE_DOWN param
        else:
            skipped['unclear'] += 1

    entries = sorted((fnv1a32_utf16(p), fd, p) for p, fd, _ in rows)
    seen = {}
    for h, fd, p in entries:
        if h in seen and seen[h] != fd:
            raise SystemExit('hash collision with conflicting orientation: %08x %s' % (h, p))
        seen[h] = fd

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..',
                       'src', 'animation', 'kntwr_wounded_orient.h')
    sample_up = next((h, p) for h, fd, p in entries if fd == 0)
    sample_down = next((h, p) for h, fd, p in entries if fd == 1)
    with open(os.path.abspath(out), 'w', newline='\n') as f:
        f.write('// Generated by tools/gen_wounded_orient.py -- do not edit by hand.\n')
        f.write('// End-of-clip body orientation for men death animations that carry no\n')
        f.write('// FACE_UP/FACE_DOWN trailer tag in the stock data.pack (see the generator\n')
        f.write('// for the classification method and its validation against native tags).\n')
        f.write('// face_down==1 -> FACE_DOWN (front wounded loop), 0 -> FACE_UP (back).\n')
        f.write('#pragma once\n\n')
        f.write('// FNV-1a 32 over UTF-16LE bytes of the lowercased clip path.\n')
        f.write('#define KNTWR_WOUNDED_ORIENT_COUNT %du\n\n' % len(entries))
        f.write('// Oracle samples (first entry of each orientation):\n')
        f.write('#define KNTWR_WOUNDED_ORIENT_SAMPLE_UP_NAME L"%s"\n' % sample_up[1])
        f.write('#define KNTWR_WOUNDED_ORIENT_SAMPLE_UP_HASH 0x%08Xu\n' % sample_up[0])
        f.write('#define KNTWR_WOUNDED_ORIENT_SAMPLE_DOWN_NAME L"%s"\n' % sample_down[1])
        f.write('#define KNTWR_WOUNDED_ORIENT_SAMPLE_DOWN_HASH 0x%08Xu\n\n' % sample_down[0])
        f.write('struct kntwr_wounded_orient_entry { unsigned hash; unsigned char face_down; };\n\n')
        f.write('// Sorted by hash for binary search.\n')
        f.write('static const kntwr_wounded_orient_entry kntwr_wounded_orient[KNTWR_WOUNDED_ORIENT_COUNT] = {\n')
        for h, fd, p in entries:
            f.write('    { 0x%08Xu, %d }, // %s\n' % (h, fd, p))
        f.write('};\n')
    print('entries:', len(entries), 'skipped:', skipped)
    print('wrote', os.path.abspath(out))

if __name__ == '__main__':
    main()
