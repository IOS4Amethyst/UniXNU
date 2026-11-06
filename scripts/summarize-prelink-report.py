"""Summarise a prelink report: match counts, unresolved references and the segment layout."""
import json
import sys
from pathlib import Path

out = Path(sys.argv[1])  # the directory holding kernel.json and kernel.map.json
record = json.loads((out / 'kernel.json').read_text())
pairing = json.loads((out / 'kernel.map.json').read_text())
stats = pairing['stats']
print('kernel.macho   ', record['candidate_sha256'])
print('kernelcache    ', record['inputs']['kernelcache_sha256'])
print('native         ', record['inputs']['native_sha256'])
print('collection base', record['collection_base'], 'slide', record['collection_slide'])
print('functions      ', stats['functions_matched'], '/', stats['functions_original'],
      'native', stats['functions_native'])
print('data           ', stats['data_matched'])
print('kext targets   ', stats['kext_targets_named'], '/', stats['kext_targets'], 'named')
print('conflicts      ', stats['conflicts'])
missing = sum(sum(v.values()) for v in record['missing'].values())
stubbed = sum(len(v) for v in record['stubbed'].values())
print('missing refs   ', missing, 'stubbed targets', stubbed)
print('states         ', {k: record[k] for k in ('mapping_complete', 'runtime_qualified', 'loadable',
                                                 'allow_missing', 'stub_symbol')})
for name in ('segment_layout',):
    for seg, how in record['statistics'][name].items():
        print('  %-12s %s -> %s size %s' % (seg, how['old'], how['new'], how['size']))
