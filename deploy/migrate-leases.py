#!/usr/bin/env python3
"""Import the pre-upgrade nft snapshots without reusing any issued fake IP.
Unknown domain owners become permanent migration reservations ('-').
Usage: migrate-leases.py CIDR old-list.tsv before.json stopped.json leases.txt
"""
import ipaddress, json, os, sys, tempfile
from pathlib import Path
cidr, listing, before, stopped, target = sys.argv[1:]
pool = ipaddress.ip_network(cidr)
static, interfaces = {}, {}
for line in Path(listing).read_text().splitlines()[1:]:
    fake, iface, mark, domain = line.split()
    setname = 'fake_' + ''.join(c if c.isascii() and (c.isalnum() or c == '_') else '_' for c in iface)
    if setname in interfaces and interfaces[setname] != iface:
        raise SystemExit('ambiguous legacy interface set: '+setname)
    interfaces[setname] = iface
    static[fake] = (iface, '-' if domain.startswith('*.') else domain)

mapping, membership = {}, {}
for path in (before, stopped):
    table = json.loads(Path(path).read_text())
    for obj in table['nftables']:
        if 'set' in obj:
            s = obj['set']; iface = interfaces.get(s['name'])
            if iface is None: continue
            for fake in s.get('elem', []):
                if not isinstance(fake, str): raise SystemExit('unexpected legacy set element')
                if fake in membership and membership[fake] != iface: raise SystemExit('ambiguous legacy mapping')
                membership[fake] = iface
        if 'map' in obj and obj['map']['name'] == 'fake_to_real':
            for elem in obj['map'].get('elem', []):
                if isinstance(elem, dict): elem = elem['elem']['val']
                fake, real = elem
                mapping[fake] = real
# Include unresolved static/set entries as non-reusable reservations too.
rows = []
for fake in sorted(set(static) | set(membership) | set(mapping), key=ipaddress.ip_address):
    if ipaddress.ip_address(fake) not in pool: raise SystemExit('legacy address outside pool')
    iface, domain = static.get(fake, (membership.get(fake), '-'))
    if not iface: raise SystemExit('legacy mapping without interface: '+fake)
    real = mapping.get(fake, '0.0.0.0')
    ipaddress.IPv4Address(real)
    rows.append(f'{fake} {real} {iface} {domain}\n')
path = Path(target)
if path.exists(): raise SystemExit('refusing to overwrite an existing lease store')
path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
fd, tmp = tempfile.mkstemp(dir=path.parent)
try:
    with os.fdopen(fd, 'w') as file:
        file.write(f'NFR1 {pool}\n'+''.join(rows)); file.flush(); os.fsync(file.fileno())
    os.replace(tmp, path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try: os.fsync(parent)
    finally: os.close(parent)
finally:
    if os.path.exists(tmp): os.unlink(tmp)
print(f'Imported {len(rows)} reservations, {len(mapping)} real destinations; unknown owners stay pinned')
