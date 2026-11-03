#!/usr/bin/env python3
"""Check nonzero arm-io translation with a compiled hardware DTB."""
from pathlib import Path
import struct
import sys
from unixnu.devicetree import generate
from unixnu.util import Error

# Reuse the existing ADT decoder without running its command-line checks.
import ast
source = Path(__file__).with_name('check-adt-cpu-clusters.py').read_text()
decoder = next(n for n in ast.parse(source).body if isinstance(n, ast.FunctionDef) and n.name == 'decode')
exec(compile(ast.Module(body=[decoder], type_ignores=[]), '<decoder>', 'exec'))
path = Path(sys.argv[1])
def armio(base):
    tree, _ = decode(generate(path, {'payload': {'adt': {'arm_io_base': hex(base)}}}))
    return next(n for n in tree[1] if n[0]['name'] == b'arm-io\0')
old, new = armio(0), armio(0x1000000)
assert struct.unpack('<QQQ', new[0]['ranges'])[1] == 0x1000000
for a, b in zip(old[1], new[1]):
    if 'reg' not in a[0]: continue
    before = list(struct.iter_unpack('<QQ', a[0]['reg']))
    after = list(struct.iter_unpack('<QQ', b[0]['reg']))
    assert before == [(address + 0x1000000, size) for address, size in after]
try:
    armio(0xffffffff)
except Error:
    pass
else:
    raise AssertionError('MMIO below parent base accepted')
print('PASS: nonzero SoC base; all exported physical MMIO ranges preserved; underflow refused')
