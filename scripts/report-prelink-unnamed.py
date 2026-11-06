"""List the unnamed data operands the iOS 27 prelink could not map.

These are the addresses whose containing object has no symbol in the built kernel
(mostly string literals and C++ data inside kernel text), so the matcher cannot
name them. They may only come from a new matcher method, never from a guessed
address; this script is the review input for that.
"""
import json
import sys
from collections import Counter
from pathlib import Path

record = json.loads(Path(sys.argv[1]).read_text())
pairing = json.loads(Path(sys.argv[2]).read_text())
data = {int(k, 16): v for k, v in pairing['data'].items()}
funcs = {int(k, 16): v for k, v in pairing['functions'].items()}
data_va = sorted(data)
text_va = sorted(funcs)
mapped = set(data) | set(funcs)


def containing(table, address, starts):
    below = None
    for start in starts:
        if start <= address:
            below = start
        else:
            break
    return below


rows = []
for owner in sorted(record['missing']):
    for target in sorted(record['missing'][owner]):
        address = int(target, 16)
        below = containing(data, address, data_va)
        holder = data.get(below, {})
        rows.append((owner, address, holder.get('name') or '', address - below if below else 0))
counts = Counter((name, offset) for _, _, name, offset in rows)
for (name, offset), count in counts.most_common():
    print(f'{count:3d} {name or "?":60} +{offset:#06x}')
print(f'total {len(rows)} references over {len({row[1] for row in rows})} addresses')
