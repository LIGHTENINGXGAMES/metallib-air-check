#!/usr/bin/env python3
"""Extract files matching a pattern from an APFS image, including compressed ones.

7-Zip reads APFS and most transparent compression, but not LZBITMAP (decmpfs
types 13 and 14, which 7-Zip lists as ZBM-attr and ZBM-rsrc). For those files
the com.apple.decmpfs attribute and the resource fork are read as alternate
streams and decoded with libzbitmap.
"""
import argparse
import ctypes
import json
import os
import re
import struct
import subprocess
import sys

DECMPFS_MAGIC = 0x636D7066  # 'fpmc'
CHUNK = 65536


def sevenzip(args, **kwargs):
    """7-Zip exits 1 for warnings, such as opening a DMG as raw APFS."""
    result = subprocess.run(args, **kwargs)
    if result.returncode > 1:
        raise RuntimeError(f'{args[0]} exited {result.returncode}: {" ".join(args[1:4])}')
    return result


def stream(tool, image, path, attribute):
    return sevenzip([tool, 'x', '-so', '-sns', '-spd', image, f'{path}:{attribute}'],
                    capture_output=True).stdout


class Zbitmap:
    def __init__(self, library):
        self.decode = ctypes.CDLL(os.path.abspath(library)).zbm_decompress
        self.decode.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_char_p,
                                ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
        self.decode.restype = ctypes.c_int
        self.buffer = ctypes.create_string_buffer(CHUNK)

    def chunk(self, data, expected):
        # A leading 0xff marks a chunk stored without compression.
        if data[:1] == b'\xff':
            return data[1:]
        size = ctypes.c_size_t()
        error = self.decode(self.buffer, len(self.buffer), data, len(data), ctypes.byref(size))
        if error:
            raise ValueError(f'LZBITMAP error {error}')
        out = self.buffer.raw[:size.value]
        if len(out) != expected:
            raise ValueError(f'chunk decoded to {len(out)} bytes, expected {expected}')
        return out


def decode(header, fork, zbm):
    magic, kind, length = struct.unpack_from('<IIQ', header)
    if magic != DECMPFS_MAGIC:
        raise ValueError('not a decmpfs header')
    if kind == 13:  # data follows the header inside the attribute
        return zbm.chunk(header[16:], length)
    if kind != 14:
        raise ValueError(f'unexpected decmpfs type {kind}')
    count = (length + CHUNK - 1) // CHUNK
    offsets = struct.unpack_from(f'<{count + 1}I', fork)
    if offsets[0] != (count + 1) * 4 or offsets[-1] != len(fork):
        raise ValueError('invalid resource-fork offset table')
    out = bytearray()
    for index, (start, end) in enumerate(zip(offsets, offsets[1:])):
        if not start < end <= len(fork):
            raise ValueError(f'invalid bounds for chunk {index}')
        out += zbm.chunk(fork[start:end], min(CHUNK, length - index * CHUNK))
    return bytes(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('image')
    ap.add_argument('output')
    ap.add_argument('--pattern', required=True, help='regex matched against member paths')
    ap.add_argument('--sevenzip', default='7zz')
    ap.add_argument('--zbitmap', required=True, help='libzbitmap shared library')
    args = ap.parse_args()

    listing = sevenzip([args.sevenzip, 'l', '-slt', '-sns', '-sccUTF-8', args.image],
                       capture_output=True, encoding='utf-8', errors='replace').stdout
    records = [dict(line.split(' = ', 1) for line in block.splitlines() if ' = ' in line)
               for block in listing.replace('\r\n', '\n').split('\n\n')]
    pattern = re.compile(args.pattern)
    members = [r for r in records if pattern.search(r.get('Path', ''))
               and r.get('Alternate Stream', '-') == '-' and r.get('Folder', '-') == '-']
    if not members:
        sys.exit(f'no members match {args.pattern}')
    os.makedirs(args.output, exist_ok=True)

    compressed = {'ZBM-rsrc', 'ZBM-attr'}
    ordinary = [r['Path'] for r in members if r.get('Method') not in compressed]
    if ordinary:
        names = os.path.join(args.output, '.members.txt')
        with open(names, 'w', encoding='utf-8') as f:
            f.write('\n'.join(ordinary))
        sevenzip([args.sevenzip, 'x', '-y', '-sns-', '-spd', '-scsUTF-8',
                  f'-o{args.output}', args.image, f'@{names}'],
                 stdout=subprocess.DEVNULL)
        os.remove(names)

    zbm = Zbitmap(args.zbitmap)
    manifest = []
    for r in members:
        path = os.path.join(args.output, *re.split(r'[\\/]', r['Path']))
        if r.get('Method') in compressed:
            header = stream(args.sevenzip, args.image, r['Path'], 'com.apple.decmpfs')
            fork = stream(args.sevenzip, args.image, r['Path'], 'com.apple.ResourceFork') \
                if r['Method'] == 'ZBM-rsrc' else b''
            data = decode(header, fork, zbm)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, 'wb') as f:
                f.write(data)
        size = os.path.getsize(path) if os.path.exists(path) else None
        manifest.append({'path': r['Path'], 'method': r.get('Method'),
                         'size': int(r.get('Size') or 0), 'extracted': size})
        if size != int(r.get('Size') or 0):
            print(f"size mismatch for {r['Path']}: {size} != {r.get('Size')}", file=sys.stderr)
    with open(os.path.join(args.output, '.manifest.json'), 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=1)
    bad = [m for m in manifest if m['extracted'] != m['size']]
    print(f'extracted {len(manifest) - len(bad)}/{len(manifest)} files')
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
