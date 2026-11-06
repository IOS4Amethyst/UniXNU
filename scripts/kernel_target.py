"""Target of objects linked into the kernel: architecture and iOS deployment of the kernel build.

The kernel build exports UNIXNU_XNU_ARCH and UNIXNU_IOS_VERSION from the selected profiles. Without them
the arm64 iOS 17.0 target is used.

The kernel configuration level is exported as UNIXNU_XNU_CONFIG_LEVEL by build-xnu-4k-baseline.sh, which
defaults to DEVELOPMENT. Scripts that read the kernel's object tree or a per-object compile recipe take
their path from here so a RELEASE build of the same source finds its own objects.
"""
import os
import struct

ARCH = os.environ.get('UNIXNU_XNU_ARCH', 'arm64')
IOS_VERSION = os.environ.get('UNIXNU_IOS_VERSION', '17.0')
TRIPLE = f'{ARCH}-apple-ios{IOS_VERSION}'
_major, _minor = (IOS_VERSION.split('.') + ['0'])[:2]
DEPLOYMENT = (2, int(_major) << 16 | int(_minor) << 8)
_SUBTYPES = {'arm64': 0, 'arm64e': 2}
if ARCH not in _SUBTYPES:
    raise SystemExit(f'Unsupported kernel architecture {ARCH}')
SUBTYPE = _SUBTYPES[ARCH]

# Kernel configuration level, mirroring build-xnu-4k-baseline.sh's XNU_CONFIG_LEVEL.
CONFIG_LEVEL = os.environ.get('UNIXNU_XNU_CONFIG_LEVEL', 'DEVELOPMENT')
CONFIG_LEVEL_LC = CONFIG_LEVEL.lower()
# The xnu object tree of a BCM2837 kernel build, relative to the tree root.
OBJECT_TREE = f'build/xnu/ios-obj/{CONFIG_LEVEL}_ARM64_BCM2837'
# The linked kernel image of that build, relative to the tree root.
KERNEL_IMAGE = f'{OBJECT_TREE}/mach.{CONFIG_LEVEL_LC}.bcm2837.unstripped'


def check_object(data, what):
    """Refuse a relocatable object whose architecture or deployment differs from the kernel target."""
    magic, cpu, subtype, kind, count = struct.unpack_from('<5I', data)
    if (magic, cpu, subtype & 0xff, kind) != (0xfeedfacf, 0x100000c, SUBTYPE, 1):
        raise SystemExit(f'{what}: not an {ARCH} object')
    offset, deployment = 32, None
    for _ in range(count):
        command, length = struct.unpack_from('<II', data, offset)
        if command == 0x32:
            deployment = struct.unpack_from('<II', data, offset + 8)
        offset += length
    if deployment != DEPLOYMENT:
        raise SystemExit(f'{what}: deployment {deployment}, expected {DEPLOYMENT}')
