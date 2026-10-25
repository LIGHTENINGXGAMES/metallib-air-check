#!/usr/bin/env python3
"""Report the AIR versions and notable intrinsics inside Metal libraries.

Reads only the metallib container: the header, the function list tags
(NAME, TYPE, VERS, MDSZ, OFFT) and the bitcode modules they point to. From
each module it records the AIR target triple and any `agx` names, which mark
Apple GPU specific intrinsics that a non-Apple translator may refuse.
No Apple code is written out; the report holds names and counts only.
"""
import argparse
import collections
import json
import os
import re
import struct
import sys

FUNCTION_TYPES = {0: 'vertex', 1: 'fragment', 2: 'kernel', 3: 'unqualified',
                  4: 'visible', 5: 'extern', 6: 'intersection', 7: 'mesh', 8: 'object'}
TRIPLE = re.compile(rb'air64_v\d+-apple-[a-z]+[0-9.]*')
# Bitcode is bit-packed, so a bare "agx" can occur by chance; require it to sit
# between name separators, as it does in intrinsic and symbol names.
AGX = re.compile(rb'[A-Za-z0-9_.]*[._]agx[._][A-Za-z0-9_.]*')
NAME_CHARS = re.compile(rb'[A-Za-z0-9_.]*')


def air_names(blob):
    """Names in a bitcode string table are stored back to back, so split on the
    prefix itself; a name followed by a non-AIR name keeps that tail."""
    return {('air.' + NAME_CHARS.match(piece).group().decode('ascii')).rstrip('.')
            for piece in blob.split(b'air.')[1:]}


def parse_header(d):
    if len(d) < 88 or d[:4] != b'MTLB':
        return None
    platform, major, minor = struct.unpack_from('<HHH', d, 4)
    kind, target_os = d[10], d[11]
    os_major, os_minor = struct.unpack_from('<HH', d, 12)
    fields = struct.unpack_from('<9Q', d, 16)
    return {'platform': hex(platform), 'file_version': f'{major}.{minor}', 'type': kind,
            'os': hex(target_os), 'os_version': f'{os_major}.{os_minor}',
            'file_size': fields[0], 'function_list': fields[1:3],
            'public_metadata': fields[3:5], 'private_metadata': fields[5:7],
            'bitcode': fields[7:9]}


def parse_functions(d, offset, size):
    """Function list: u32 count, then per entry u32 size and tags up to ENDT."""
    end = min(len(d), offset + size + 4)
    count = struct.unpack_from('<I', d, offset)[0]
    p = offset + 4
    out = []
    for _ in range(count):
        if p + 4 > end:
            break
        p += 4  # entry size
        fn = {}
        while p + 4 <= end:
            tag = d[p:p + 4]
            p += 4
            if tag == b'ENDT':
                break
            if p + 2 > end:
                break
            length = struct.unpack_from('<H', d, p)[0]
            value = d[p + 2:p + 2 + length]
            p += 2 + length
            if tag == b'NAME':
                fn['name'] = value.rstrip(b'\0').decode('utf-8', 'replace')
            elif tag == b'TYPE' and value:
                fn['type'] = value[0]
            elif tag == b'VERS' and len(value) >= 8:
                fn['vers'] = struct.unpack_from('<4H', value)
            elif tag == b'MDSZ' and len(value) >= 8:
                fn['module_size'] = struct.unpack_from('<Q', value)[0]
            elif tag == b'OFFT' and len(value) >= 24:
                fn['offsets'] = struct.unpack_from('<3Q', value)
        out.append(fn)
    return out


def scan_module(blob):
    names = air_names(blob)
    agx = {m.decode('ascii') for m in AGX.findall(blob)} | {n for n in names if 'agx' in n}
    return {
        'triples': sorted({m.decode() for m in TRIPLE.findall(blob)}),
        'agx': sorted(agx),
        'air': names,
    }


FAT_MAGICS = {b'\xca\xfe\xba\xbe': False, b'\xca\xfe\xba\xbf': True}


def fat_slices(d):
    """Slices of a universal (fat) Mach-O: (cputype, cpusubtype, offset, size)."""
    wide = FAT_MAGICS[d[:4]]
    count = struct.unpack_from('>I', d, 4)[0]
    out, p = [], 8
    for _ in range(count):
        if wide:
            cpu, sub, off, size = struct.unpack_from('>IIQQ', d, p)
            p += 32
        else:
            cpu, sub, off, size = struct.unpack_from('>IIII', d, p)
            p += 20
        out.append((cpu, sub, off, size))
    return out


def analyse(path):
    d = open(path, 'rb').read()
    report = {'path': path, 'bytes': len(d), 'magic': d[:8].hex()}
    if d[:4] in FAT_MAGICS:
        # System libraries ship as universal files: an AIR slice plus GPU binaries.
        report['container'] = 'fat'
        report['slices'] = []
        for cpu, sub, off, size in fat_slices(d):
            part = d[off:off + size]
            entry = {'cputype': hex(cpu), 'cpusubtype': hex(sub), 'bytes': len(part),
                     'magic': part[:8].hex()}
            if part[:4] == b'MTLB':
                entry['metallib'] = analyse_bytes(part, {})
            report['slices'].append(entry)
        return report
    if d[:4] != b'MTLB':
        embedded = [m.start() for m in re.finditer(b'MTLB', d) if m.start() % 4 == 0]
        report['embedded_mtlb'] = embedded[:16]
        if embedded:
            report['container'] = 'embedded'
            report['slices'] = [{'offset': o, 'metallib': analyse_bytes(d[o:], {})}
                                for o in embedded[:16]]
            return report
    return analyse_bytes(d, report)


def analyse_bytes(d, report):
    report.setdefault('bytes', len(d))
    header = parse_header(d)
    report['header'] = header
    if header is None:
        report['error'] = 'not a metallib (no MTLB header)'
        return report
    if header['file_size'] > len(d):
        report['truncated'] = True
    functions = []
    try:
        functions = parse_functions(d, *header['function_list'])
    except struct.error as exc:
        report['error'] = f'function list: {exc}'
    bc_start = header['bitcode'][0]
    triples = collections.Counter()
    agx = collections.Counter()
    air = collections.Counter()
    for fn in functions:
        offsets, size = fn.get('offsets'), fn.get('module_size')
        if not offsets or not size:
            continue
        blob = d[bc_start + offsets[2]:bc_start + offsets[2] + size]
        found = scan_module(blob)
        fn['triples'] = found['triples']
        fn['agx'] = found['agx']
        triples.update(found['triples'])
        agx.update(found['agx'])
        air.update(found['air'])
    if not functions:
        # Fall back to a plain scan so damaged or unusual files still report something.
        found = scan_module(d)
        triples.update(found['triples'])
        agx.update(found['agx'])
        air.update(found['air'])
    vers = collections.Counter(
        f"AIR {v[0]}.{v[1]} / MSL {v[2]}.{v[3]}" for v in (fn.get('vers') for fn in functions) if v)
    report.update({
        'functions': len(functions),
        'function_types': dict(collections.Counter(
            FUNCTION_TYPES.get(fn.get('type'), str(fn.get('type'))) for fn in functions)),
        'versions': dict(vers),
        'triples': dict(triples),
        'agx_names': dict(agx),
        'functions_with_agx': sum(1 for fn in functions if fn.get('agx')),
        'agx_functions_sample': [fn.get('name') for fn in functions if fn.get('agx')][:20],
        'air_names': len(air),
        'air_families': dict(collections.Counter(
            '.'.join(n.split('.')[:2]) for n in air).most_common(40)),
    })
    return report


def flatten(reports):
    """One entry per metallib, with fat slices and embedded libraries listed separately."""
    rows = []
    for r in reports:
        if 'slices' not in r:
            rows.append(r)
            continue
        for s in r['slices']:
            where = f"cpu {s['cputype']}/{s['cpusubtype']}" if 'cputype' in s else f"@{s['offset']:#x}"
            entry = dict(s.get('metallib') or {'bytes': s.get('bytes', 0),
                                               'error': f"非 metallib 切片，头部 {s.get('magic')}"})
            entry['label'] = f"{r['label']} [{where}]"
            rows.append(entry)
    return rows


def render(reports):
    out = ['# Metal 库 AIR 检查', '',
           '| 文件 | 大小 | 文件格式 | 目标系统 | 函数 | AIR / MSL 版本 | 目标三元组 | 含 agx 名称的函数 |',
           '|---|---|---|---|---|---|---|---|']
    rows = flatten(reports)
    for r in rows:
        h = r.get('header') or {}
        name = r['label']
        if 'error' in r and not r.get('functions'):
            detail = r['error'] + (f"，头部 {r['magic']}" if r.get('magic') else '')
            out.append(f"| `{name}` | {r['bytes']} | — | — | — | {detail} | — | — |")
            continue
        out.append(
            f"| `{name}` | {r['bytes']} | {h.get('file_version')}{' (截断)' if r.get('truncated') else ''} | "
            f"{h.get('os')} {h.get('os_version')} | {r['functions']} | "
            f"{', '.join(f'{k} ×{v}' for k, v in r['versions'].items()) or '—'} | "
            f"{', '.join(r['triples']) or '—'} | {r['functions_with_agx']} |")
    out.append('')
    for r in rows:
        if not r.get('agx_names') and not r.get('air_families'):
            continue
        out += [f"## `{r['label']}`", '']
        if r.get('function_types'):
            out.append('函数类型：' + ', '.join(f'{k} {v}' for k, v in r['function_types'].items()))
            out.append('')
        if r.get('agx_names'):
            out.append(f"含 agx 的名称（{len(r['agx_names'])} 种）：")
            out += [f'- `{n}` ×{c}' for n, c in sorted(r['agx_names'].items(), key=lambda kv: -kv[1])[:40]]
            out.append('')
            if r.get('agx_functions_sample'):
                out.append('用到它们的函数（前 20 个）：' + ', '.join(
                    f'`{n}`' for n in r['agx_functions_sample']))
                out.append('')
        if r.get('air_families'):
            out.append(f"AIR 名称前缀（共 {r['air_names']} 个不同名称，按前两段归类，前 40）：")
            out.append(', '.join(f'`{k}` {v}' for k, v in r['air_families'].items()))
            out.append('')
    return '\n'.join(out) + '\n'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('paths', nargs='+', help='metallib files or directories to scan')
    ap.add_argument('--out', required=True, help='output prefix (.json and .md)')
    args = ap.parse_args()
    files = []
    for p in args.paths:
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                files += [os.path.join(root, n) for n in sorted(names) if '.metallib' in n]
        else:
            files.append(p)
    if not files:
        sys.exit('no metallib files found')
    base = os.path.commonpath([os.path.abspath(f) for f in files]) if len(files) > 1 else ''
    reports = []
    for f in sorted(files):
        r = analyse(f)
        r['label'] = os.path.relpath(os.path.abspath(f), base) if base else os.path.basename(f)
        reports.append(r)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out + '.json', 'w', encoding='utf-8') as fh:
        json.dump(reports, fh, indent=1, ensure_ascii=False, default=list)
    with open(args.out + '.md', 'w', encoding='utf-8') as fh:
        fh.write(render(reports))
    for r in flatten(reports):
        print(f"{r['label']}: {r.get('versions') or r.get('error')} triples={list(r.get('triples', {}))} "
              f"agx_functions={r.get('functions_with_agx')}")


if __name__ == '__main__':
    main()
