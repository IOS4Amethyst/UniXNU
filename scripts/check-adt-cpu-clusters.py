#!/usr/bin/env python3
"""Check CPU cluster export using an existing compiled hardware DTB."""
from pathlib import Path
import struct
import sys

from unixnu.devicetree import generate, read_fdt
from unixnu.util import Error

path = Path(sys.argv[1])
hardware = read_fdt(path.read_bytes())
cpus = next(n for n in hardware.children if n.name == 'cpus')
expected = [n.strings('unixnu,cluster-type') for n in cpus.children if n.enabled()]
assert expected and all(v in (['E'], ['P']) for v in expected)


def decode(data, at=0):
    count, children = struct.unpack_from('<II', data, at)
    at += 8
    props = {}
    for _ in range(count):
        key, size = struct.unpack_from('<32sI', data, at)
        at += 36
        props[key.split(b'\0')[0].decode()] = data[at:at+size]
        at += (size + 3) & ~3
    nodes = []
    for _ in range(children):
        child, at = decode(data, at)
        nodes.append(child)
    return (props, nodes), at


tree, end = decode(generate(path, {}))
cpu_tree = next(n for n in tree[1] if n[0]['name'] == b'cpus\0')
assert [n[0]['cluster-type'] for n in cpu_tree[1]] == [struct.pack('<I', ord(v[0])) for v in expected]
# Invalid declarations must fail instead of silently becoming SMP CPUs.
import unixnu.devicetree as module
original = module.read_fdt
cpus.children[0].properties['unixnu,cluster-type'] = b'invalid\0'
module.read_fdt = lambda _: hardware
try:
    try:
        generate(path, {})
    except Error as error:
        assert 'unixnu,cluster-type must be E or P' in str(error)
    else:
        raise AssertionError('Invalid CPU cluster accepted')
finally:
    module.read_fdt = original
print('PASS: declared E/P CPU clusters survive ADT export; invalid clusters refuse')
