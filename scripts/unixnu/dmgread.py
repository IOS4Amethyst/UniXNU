#!/usr/bin/env python3
"""Pure-Python, read-only DMG reader for the IPSW disk images on Linux.

Replaces the two things userdata.py uses hdiutil for:

    hdiutil imageinfo -plist DMG        -> image_size(dmg)
    hdiutil attach -nomount -readonly   -> a raw byte stream over the whole disk
                                           (attach() + open(raw, 'rb') in userdata.py)

Apple restore DMGs are UDIF ("koly" trailer at the last 512 bytes). The common
layouts in iOS/iPadOS restore images are:

    UDZO  zlib-compressed chunks      -> handled here with zlib
    UDBZ  bzip2-compressed chunks     -> handled here with bz2
    ULFO  LZFSE-compressed chunks     -> needs an LZFSE decoder; refused, not guessed
    UDRO  raw, uncompressed           -> handled here
    APFS  a whole-disk APFS container  -> read as raw (the OS DMG is often APFS)

The reader exposes the same interface as a file object: seek/tell/read, plus
`close()`. It never writes and never mounts. Nothing here needs root.

Usage as a module:
    from dmgread import DmgFile
    with DmgFile('044-76040-038.dmg') as f:
        f.seek(512); data = f.read(4096)

Usage as a script (sanity check):
    python3 dmgread.py DMG          prints the trailer summary
"""
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
import bz2
from pathlib import Path

KOLY = 512
MISH = 4096

# blkx table names that carry GPT structure rather than partition content.
_GPT_TABLE_NAMES = frozenset({'MBR', 'Primary GPT Header', 'Primary GPT Table',
                              'Backup GPT Table', 'Backup GPT Header'})
# GPT partition type GUID for Apple APFS: ef57347c-0000-aa11-aa11-00306543ecac,
# stored little-endian in the entry, so the first 16 bytes read as below.
_GPT_ENTRY_APFS_GUID = bytes.fromhex('ef57347c0000aa11aa1100306543ecac')

# Checksum types in the blkx table.
CSUM_NONE, CSUM_CRC32, CSUM_MD5, CSUM_SHA1, CSUM_SHA256 = 0, 2, 3, 4, 6


class Error(Exception):
    pass


def _be32(b, at):
    return struct.unpack_from('>I', b, at)[0]


def _be64(b, at):
    return struct.unpack_from('>Q', b, at)[0]


def _rle_decode(src, expected):
    """Zero-run and literal-run encoding used by UDZO/UDRO blocks.

    A 0 byte followed by a count byte means (count) zero bytes. Any other byte
    starts a literal run of that length, copied verbatim.
    """
    out = bytearray()
    at = 0
    n = len(src)
    while at < n:
        tag = src[at]
        at += 1
        if tag == 0:
            if at >= n:
                raise Error('truncated RLE zero run')
            count = src[at]
            at += 1
            out.extend(bytes(count))
        else:
            count = tag
            out += src[at:at + count]
            at += count
    if expected is not None and len(out) != expected:
        raise Error(f'RLE block decoded to {len(out)} bytes, expected {expected}')
    return bytes(out)


class Blkx:
    """One blkx resource: a table of (type, sector, sectorCount, compressedOffset, compressedLength)."""

    TYPES = {0x00000000: 'zero', 0x00000001: 'raw', 0x00000002: 'ignore',
             0x80000004: 'comment', 0x80000005: 'terminator', 0x7ffffffe: 'lastblock',
             0x10000005: 'info', 0x10000000: 'zlib', 0x80000006: 'bzip2',
             0x80000007: 'lzfse', 0xffffffff: 'terminator'}

    # Entry layout, confirmed against 044-76040-038.dmg of 21H461: the entry is
    # 40 bytes, and sector/sectorCount/offset/length are all u64 at offsets
    # 8/16/24/32. A u32 at offset 4 is always zero and must not shift the rest.
    def __init__(self, data):
        if data[:4] != b'mish':
            raise Error('blkx resource is not mish')
        count = _be32(data, 200)
        if 204 + 40 * count > len(data):
            raise Error(f'blkx declares {count} runs, needs {204 + 40*count} bytes, has {len(data)}')
        self.runs = []
        for index in range(count):
            entry = data[204 + 40 * index:204 + 40 * (index + 1)]
            kind = _be32(entry, 0)
            sector, sectors, offset, length = struct.unpack_from('>4Q', entry, 8)
            self.runs.append((kind, sector, sectors, offset, length))

    def covered_sectors(self):
        """Sectors this table maps, excluding the informational runs."""
        return sum(r[2] for r in self.runs if r[0] not in (0x80000004, 0x80000005, 0xffffffff))


def lzfse_tool():
    """Path to Apple's lzfse CLI. scripts/linux/setup-toolchain.py installs it under
    $UNIXNU_TOOLCHAIN (default /opt/unixnu-linux); ipsw.py already relies on it for
    the kernelcache, so it is present anywhere the kernel step has run."""
    candidate = Path(os.environ.get('UNIXNU_TOOLCHAIN', '/opt/unixnu-linux'))/'bin/lzfse'
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    found = shutil.which('lzfse')
    if found:
        return found
    raise Error('lzfse is needed to decode this compressed run but was not found; '
                'run scripts/linux/setup-toolchain.py or set UNIXNU_TOOLCHAIN')


def lzfse_decode(packed, expected, tool=None):
    """Decode one LZFSE run. The CLI works on files, so this round-trips through temp
    files under TMPDIR; the caller batches runs to keep that cost bounded."""
    tool = tool or lzfse_tool()
    directory = tempfile.mkdtemp(prefix='dmgread-')
    try:
        source, target = Path(directory)/'in.bin', Path(directory)/'out.bin'
        source.write_bytes(packed)
        result = subprocess.run([tool, '-decode', '-i', str(source), '-o', str(target)],
                                capture_output=True, text=True)
        if result.returncode or not target.is_file():
            raise Error(f'lzfse failed: {result.stderr.strip() or result.returncode}')
        raw = target.read_bytes()
    finally:
        shutil.rmtree(directory, ignore_errors=True)
    if expected is not None and len(raw) != expected:
        # LZFSE runs may still be RLE-wrapped when the stored size disagrees.
        raw = _rle_decode_to(raw, expected)
    return raw


def parse_plist(data):
    """Minimal XML plist reader: returns {key: value} for the top-level dict."""
    import plistlib
    return plistlib.loads(data)


class DmgFile:
    def __init__(self, path):
        self.path = Path(path)
        self.file = self.path.open('rb')
        self.file.seek(-KOLY, 2)
        koly = self.file.read(KOLY)
        if koly[:4] != b'koly':
            raise Error(f'{self.path.name}: not a UDIF image (no koly trailer)')
        self.koly_version = _be32(koly, 4)
        self.data_fork_offset = _be64(koly, 24)
        self.data_fork_length = _be64(koly, 32)
        self.rsrc_fork_offset = _be64(koly, 40)
        self.rsrc_fork_length = _be64(koly, 48)
        self.sector_count = _be64(koly, 492)
        self.size = self.sector_count * 512
        xml_offset = _be64(koly, 216)
        xml_length = _be64(koly, 224)
        if not xml_offset or not xml_length:
            raise Error(f'{self.path.name}: no plist in the koly trailer')
        self.file.seek(xml_offset)
        self.info = parse_plist(self.file.read(xml_length))
        resources = self.info.get('resource-fork', {})
        blkx_list = resources.get('blkx', [])
        if not blkx_list:
            raise Error(f'{self.path.name}: no blkx resources')
        self.blocks = [Blkx(item['Data']) for item in blkx_list]
        self.names = [item.get('Name', '') for item in blkx_list]
        # Apple writes one blkx table per GPT region: MBR, Primary GPT Header,
        # Primary GPT Table, Apple_APFS, Backup GPT Table, Backup GPT Header.
        # Confirmed against 044-76040-038.dmg of 21H461:
        #   - the five GPT tables are short metadata blobs, each with runs
        #     relative to their own first sector (always 0), positioned on the
        #     disk by their fixed GPT role, not by any field in the plist;
        #   - the payload table ("Apple_APFS") maps the partition, and its run
        #     sectors are relative to the partition start.
        # The partition start comes from the GPT, so it is read here rather than
        # assumed: entry 0 of the Primary GPT Table gives first_lba.
        self.partition = self._partition_table()
        self.runs = self.partition.runs
        self._check_coverage()
        # The reader presents the partition, which is what the OS/SystemOS
        # window holds. `self.disk_size` keeps the whole-image size available.
        self.disk_size = self.size
        self.size = sum(r[2] for r in self.runs) * 512

    def _partition_table(self):
        """The blkx whose runs map the partition, checked against the GPT."""
        if len(self.blocks) == 1:
            # A single-table image maps the whole disk; no GPT indirection.
            return self.blocks[0]
        payload = [i for i, name in enumerate(self.names)
                   if name and name not in _GPT_TABLE_NAMES]
        if len(payload) != 1:
            raise Error(f'{self.path.name}: expected one partition table among '
                        f'{self.names}, found {len(payload)}')
        index = payload[0]
        table = self.blocks[index]
        gpt = self._read_gpt(index)
        if gpt is not None:
            first, last = gpt
            want = last - first + 1
            have = table.covered_sectors()
            if have != want:
                raise Error(f'{self.path.name}: {self.names[index]} covers {have} sectors, '
                            f'GPT partition spans {want} ({first}..{last})')
            self.partition_first_lba = first
        else:
            self.partition_first_lba = 0
        return table

    def _read_gpt(self, payload_index):
        """(first_lba, last_lba) of GPT entry 0, decoded from the Primary GPT Table table."""
        try:
            position = self.names.index('Primary GPT Table')
        except ValueError:
            return None
        table = self.blocks[position]
        run = next((r for r in table.runs
                    if Blkx.TYPES.get(r[0]) in ('lzfse', 'zlib', 'bzip2', 'raw')), None)
        if run is None:
            return None
        kind, sector, count, offset, length = run
        raw = self._decode_run_raw(kind, offset, length, count)
        if len(raw) < 128 or raw[:16] != _GPT_ENTRY_APFS_GUID:
            return None
        first = struct.unpack_from('<Q', raw, 32)[0]
        last = struct.unpack_from('<Q', raw, 40)[0]
        if not (0 < first <= last):
            return None
        self.gpt_header = raw
        return first, last

    def _decode_run_raw(self, kind, offset, length, count):
        """Decode one run without the read-position machinery, for metadata probes."""
        name = Blkx.TYPES.get(kind, hex(kind))
        self.file.seek(self.data_fork_offset + offset)
        packed = self.file.read(length)
        if name == 'raw':
            return packed
        if name == 'zlib':
            return _rle_decode_to(zlib.decompress(packed), count * 512)
        if name == 'bzip2':
            return _rle_decode_to(bz2.decompress(packed), count * 512)
        if name == 'lzfse':
            return lzfse_decode(packed, count * 512)
        raise Error(f'{self.path.name}: cannot decode {name} for metadata')

    def _check_coverage(self):
        """The partition's runs must map its sectors exactly once, in order."""
        mapping = [r for r in self.runs
                   if r[0] not in (0x80000004, 0x80000005, 0xffffffff)]
        if not mapping:
            raise Error(f'{self.path.name}: the partition table has no data runs')
        self.runs = sorted(mapping, key=lambda r: r[1])
        position = 0
        for kind, sector, sectors, _, _ in self.runs:
            if sector != position:
                where = 'gap' if sector > position else 'overlap'
                raise Error(f'{self.path.name}: {where} at partition sector {position} '
                            f'(next run starts at {sector})')
            position += sectors


    def close(self):
        self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _decoded_run(self, index, kind, offset, length, count):
        """Decode one compressed run, caching the most recent one.

        Sequential reads walk a run sector by sector; without this cache each
        read would re-inflate the whole run. Holds one run at a time to bound
        memory (a run is at most a few MiB in restore images).
        """
        cached = getattr(self, '_run_cache', None)
        if cached is not None and cached[0] == index:
            return cached[1]
        self.file.seek(self.data_fork_offset + offset)
        packed = self.file.read(length)
        if len(packed) != length:
            raise Error(f'{self.path.name}: short read of run {index} at {offset}')
        if kind == 'zlib':
            raw = zlib.decompress(packed)
        elif kind == 'bzip2':
            raw = bz2.decompress(packed)
        else:
            raw = lzfse_decode(packed, count * 512, getattr(self, '_lzfse', None))
        raw = _rle_decode_to(raw, count * 512)
        self._run_cache = (index, raw)
        return raw

    # ---- file-like interface -------------------------------------------------

    def seek(self, offset, whence=0):
        self.position = {0: offset, 1: self.position + offset, 2: self.size + offset}[whence]
        return self.position

    def tell(self):
        return self.position

    position = 0

    def _run_for_sector(self, sector):
        """The (index, kind, start, count, offset, length) run holding `sector`.

        self.runs is sorted by start sector and contiguous (checked at open), so
        this is a binary search over run starts.
        """
        lo, hi = 0, len(self.runs) - 1
        best = -1
        while lo <= hi:
            mid = (lo + hi) // 2
            if self.runs[mid][1] <= sector:
                best = mid
                lo = mid + 1
            else:
                hi = mid - 1
        if best < 0:
            raise Error(f'sector {sector} is before the first run')
        kind, start, count, offset, length = self.runs[best]
        if not (start <= sector < start + count):
            raise Error(f'sector {sector} is not covered by any blkx run')
        return best, kind, start, count, offset, length

    def read(self, want):
        want = min(want, self.size - self.position)
        if want <= 0:
            return b''
        out = bytearray()
        while len(out) < want:
            sector, inside = divmod(self.position, 512)
            index, kind, start, count, offset, length = self._run_for_sector(sector)
            name = Blkx.TYPES.get(kind, hex(kind))
            if name == 'zero':
                chunk = bytes(min(want - len(out), (count - (sector - start)) * 512 - inside))
            elif name == 'raw':
                skip = (sector - start) * 512 + inside
                self.file.seek(self.data_fork_offset + offset + skip)
                chunk = self.file.read(min(want - len(out), count * 512 - skip))
            elif name == 'ignore':
                total = (count) * 512
                skip = (sector - start) * 512 + inside
                chunk = bytes(min(want - len(out), total - skip))
            elif name in ('zlib', 'bzip2', 'lzfse'):
                skip = (sector - start) * 512 + inside
                raw = self._decoded_run(index, name, offset, length, count)
                chunk = raw[skip:skip + (want - len(out))]
            else:
                raise Error(f'{self.path.name}: unsupported blkx run type {name} at sector {sector}')
            if not chunk:
                raise Error(f'{self.path.name}: no progress at sector {sector}')
            out += chunk
            self.position += len(chunk)
        return bytes(out)


def _rle_decode_to(raw, expected):
    """UDIF compressed runs are RLE over the *decompressed* chunk stream.

    zlib/bzip2 already yields the final bytes for restore images; the RLE layer
    only applies to blocks whose stored length disagrees with the sector count.
    """
    if len(raw) == expected:
        return raw
    try:
        decoded = _rle_decode(raw, expected)
        return decoded
    except Error:
        return raw


class RawFile:
    """A plain disk image that is not UDIF: a bare APFS container, as
    `044-76034-038.dmg` (SystemOS) is. Same file-like interface as DmgFile."""

    def __init__(self, path):
        self.path = Path(path)
        self.file = self.path.open('rb')
        self.file.seek(0, 2)
        self.size = self.file.tell()
        self.position = 0
        header = self.read(4096)
        self.position = 0
        self.container = 'APFS' if header[32:36] == b'NXSB' else 'raw'
        if self.container == 'APFS':
            self.block_size = struct.unpack_from('<I', header, 36)[0]

    def close(self):
        self.file.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def seek(self, offset, whence=0):
        self.position = {0: offset, 1: self.position + offset, 2: self.size + offset}[whence]
        return self.position

    def tell(self):
        return self.position

    def read(self, want):
        self.file.seek(self.position)
        data = self.file.read(want)
        self.position += len(data)
        return data


def open_image(path):
    """A reader for either packaging: UDIF (DmgFile) or a bare disk image (RawFile)."""
    with Path(path).open('rb') as probe:
        probe.seek(0, 2)
        size = probe.tell()
        if size < KOLY:
            raise Error(f'{Path(path).name}: too small to be a disk image')
        probe.seek(-KOLY, 2)
        trailer = probe.read(4)
    if trailer == b'koly':
        return DmgFile(path)
    return RawFile(path)


def image_size(path):
    """Complete logical size of the disk image in bytes (replaces hdiutil imageinfo)."""
    with open_image(path) as image:
        return image.size


def summary(path):
    with open_image(path) as image:
        result = {'file': str(path), 'bytes': image.size,
                  'gib': round(image.size / 2**30, 2)}
        if isinstance(image, DmgFile):
            kinds = {}
            for kind, _, count, _, _ in image.runs:
                name = Blkx.TYPES.get(kind, hex(kind))
                kinds[name] = kinds.get(name, 0) + count
            result.update({'kind': 'UDIF', 'disk_sectors': image.sector_count,
                           'tables': [b.covered_sectors() for b in image.blocks],
                           'partition_lba': getattr(image, 'partition_first_lba', 0),
                           'runs': len(image.runs), 'run_kinds': kinds})
        else:
            result.update({'kind': image.container})
        return result


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    print(summary(sys.argv[1]))
