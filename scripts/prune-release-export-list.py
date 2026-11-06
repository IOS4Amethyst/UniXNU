#!/usr/bin/env python3
"""Drop the exported names a RELEASE kernel cannot provide, so the relink can succeed.

RELEASE alone links with -Wl,-exported_symbols_list,all-kpi.exp
(makedefs/MakeInc.def: LDFLAGS_KERNEL_ONLY_CONFIG_RELEASEARM64; the DEVELOPMENT
entry is empty). all-kpi.exp is the union of config/*.exports, and the private
lists name exclave and SPTM symbols - IOUnifiedAddressTranslator, sptm_gen3dart_*,
t8110dart_*, uat_* - that this source tree does not build at any level. The link
therefore stops on the export list, not on the code.

This removes only the names no built object defines, from the private copies of
Private.exports and Private.arm64.exports in the prepared tree, and records them
next to the kernel so the difference from Apple's list is reviewable. The names are
undefined either way: nothing that links here loses an export it used to have.

Exit status 0 means the lists changed and the link should be retried. A non-zero
exit means there was nothing to prune, so the failure was something else.
"""
import argparse
import fnmatch
import json
from pathlib import Path
import subprocess
import sys

# The two private lists are the ones that name symbols this tree does not build.
PRIVATE_LISTS = ('Private.exports', 'Private.arm64.exports')


def linked_objects(obj_dir, level):
    """The objects the kernel link consumed, as named by the file list it wrote."""
    directory = obj_dir / f'{level}_ARM64_BCM2837'
    filelist = directory / 'link.filelist'
    if not filelist.is_file():
        raise SystemExit(f'no {filelist}: the link did not get far enough to write its object list')
    objects = [name.strip() for name in filelist.read_text().splitlines() if name.strip()]
    # version.o and the two trailing constant objects are linked without being listed.
    objects += [str(directory / name) for name in
                ('version.o', 'lastkerneldataconst.o', 'lastkernelconstructor.o')
                if (directory / name).is_file()]
    # A pass whose compile failed leaves its file list naming objects it did not produce.
    return [name for name in objects if Path(name).is_file()]


def defined_names(objects):
    """Defined symbol names of the objects, in batches the command line can hold.

    Anything less than a clean read aborts: an unread object would look like it defines
    no symbol, and every name in the export list would then be pruned.
    """
    names = set()
    for start in range(0, len(objects), 100):
        batch = objects[start:start + 100]
        result = subprocess.run(['xcrun', 'nm', '-gUj', *batch], capture_output=True, text=True)
        if result.returncode:
            raise SystemExit(f'xcrun nm failed on {batch[0]} and others: {result.stderr.strip()}')
        names |= {symbol for symbol in result.stdout.splitlines() if symbol.startswith('_') and ' ' not in symbol}
    return names


def prunable(lines, names):
    """Exported names in this list that no object defines.

    An entry is a name, or an alias `name:alias`. config/generate_linker_aliases.sh turns
    each alias into `alias  name` in all-alias.exp, and every name it lists is exported, so
    an entry is only unusable when *both* sides are undefined: `_kalloc_data:_kalloc_data_external`
    survives on its alias even though nothing defines `_kalloc_data`. Glob patterns cover a
    family of names and are kept.
    """
    rejected = set()
    for line in lines:
        entry = line.strip()
        if not entry.startswith('_'):
            continue
        names_of_entry = [name for name in entry.split(':', 1) if name]
        defined = [any(fnmatch.fnmatchcase(symbol, name) for symbol in names) for name in names_of_entry]
        if any(defined):
            continue
        rejected.update(names_of_entry)
    return rejected


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--tree', required=True, type=Path, help='tree root of the kernel build')
    parser.add_argument('--obj-dir', required=True, type=Path,
                        help='object tree of the build, relative to the tree or absolute')
    parser.add_argument('--level', required=True, help='kernel configuration level, e.g. RELEASE')
    options = parser.parse_args()

    tree = options.tree.resolve()
    obj_dir = options.obj_dir if options.obj_dir.is_absolute() else tree / options.obj_dir
    source = tree / '.cache/xnu-work' / 'config'

    objects = linked_objects(obj_dir, options.level)
    if not objects:
        raise SystemExit('the link file list names no objects that exist; the compile did not finish')
    names = defined_names(objects)

    removed = set()
    changed = []
    for filename in PRIVATE_LISTS:
        path = source / filename
        if not path.is_file():
            continue
        lines = path.read_text().splitlines(keepends=True)
        rejected = prunable(lines, names)
        if not rejected:
            continue
        removed |= rejected
        changed.append(filename)

        def keep(line):
            entry = line.strip()
            if not entry.startswith('_'):
                return True
            # An alias entry is dropped only when both of its names are unavailable.
            return any(name not in rejected for name in entry.split(':', 1))

        path.write_text(''.join(line for line in lines if keep(line)))
    if not removed:
        print('prune-release-export-list: nothing to prune; the failure is not the export list',
              file=sys.stderr)
        return 1

    # Keep every run's removals: a later relink starts from the lists this one wrote, so the
    # record accumulates the names dropped from Apple's lists for this kernel.
    directory = obj_dir / f'{options.level}_ARM64_BCM2837'
    record = directory / 'omitted-unavailable-forced-exports.json'
    previous = json.loads(record.read_text()) if record.is_file() else {}
    earlier = previous.get('removed', []) if isinstance(previous, dict) else []
    record.write_text(json.dumps({
        'level': options.level,
        'lists': changed,
        'removed': sorted({*earlier, *removed}),
    }, indent=2) + '\n')
    print(f'prune-release-export-list: removed {len(removed)} unavailable exports from '
          f'{", ".join(changed)}; link again', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
