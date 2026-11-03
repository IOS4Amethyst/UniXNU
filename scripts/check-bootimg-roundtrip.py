#!/usr/bin/env python3
"""Regression: legacy header offset, v3, and both kernel encodings."""
import gzip
import struct
import tempfile
from pathlib import Path
from unixnu.bootimg import verify

with tempfile.TemporaryDirectory() as work:
    work = Path(work)
    ramdisk = work / 'ramdisk'
    ramdisk.write_bytes(b'ramdisk')
    combined, tree = b'shim-firmware-embedded-payload', b'dtb'
    for version in (0, 3):
        for compression in ('gzip', 'none'):
            kernel = (gzip.compress(combined) if compression == 'gzip' else combined) + tree
            header = bytearray(4096)
            header[:8] = b'ANDROID!'
            if version == 0:
                struct.pack_into('<10I', header, 8, len(kernel), 0x8000, 7, 0, 0, 0,
                                 0x1e00000, 4096, 0, 0)
            else:
                struct.pack_into('<4I', header, 8, len(kernel), 7, 0, 1580)
                struct.pack_into('<I', header, 40, version)
            image = work / 'boot.img'
            image.write_bytes(header + kernel + bytes(-len(kernel) % 4096) + b'ramdisk')
            result = verify(image, combined, tree, ramdisk,
                            dict(header_version=version, pagesize=4096, base=0,
                                 kernel_offset=0x8000, tags_offset=0x1e00000), compression)
            assert result['ramdisk_bytes'] == 7
print('PASS: v0/v3 gzip/raw boot-image round trips')
