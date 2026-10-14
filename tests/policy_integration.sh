#!/usr/bin/env bash
# Run only inside a disposable network namespace (sudo unshare --net ...).
set -euo pipefail
helper=$1
binary=$2
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir "$work/domains"
printf 'example.com\n' > "$work/domains/wg-de.txt"
printf 'DOMAINS_DIR=%s/domains\nFAKE_CIDR=198.18.0.0/15\nDEFAULT_IF=eth0\n' "$work" > "$work/defaults"
python3 - "$helper" "$work" "$binary" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[2]); s=Path(sys.argv[1]).read_text()
s=s.replace('/etc/default/nfqueue-router',str(p/'defaults')).replace('BIN=/usr/local/bin/nfqueue-router', 'BIN='+sys.argv[3])
(p/'policy').write_text(s)
PY
ip link add wg-de type dummy
ip link add other type dummy
ip link set wg-de up
ip link set other up
ip -4 rule add priority 10102 fwmark 0xdeadbeef table 1102
ip -4 route add table 1102 default dev other
ip -4 rule add priority 10101 fwmark 0x52000001 table 1101
for attempt in 1 2; do bash "$work/policy" apply --no-networkd; done
ip -details -j -4 rule show > "$work/rules.json"
ip -j -4 route show table 1102 > "$work/routes.json"
python3 - "$work" <<'PY'
import json,sys
from pathlib import Path
p=Path(sys.argv[1]); rules=json.loads((p/'rules.json').read_text())
ours=[r for r in rules if r['priority']==10101]
assert sum(r.get('protocol')=='static' for r in ours)==1 and len(ours)<=2, ours
assert any(r['priority']==10102 and r['fwmark']=='0xdeadbeef' for r in rules)
assert any(r.get('dev')=='other' for r in json.loads((p/'routes.json').read_text()))
PY
# A conflicting priority is an error, not permission to wipe it.
ip -4 rule add priority 10101 fwmark 0x123 table 1102
if bash "$work/policy" apply --no-networkd; then echo 'Expected conflict rejection' >&2; exit 1; fi
ip -4 rule show | grep -q 'fwmark 0x123'
echo 'PASS policy adoption/idempotency, unrelated rules/routes preserved, conflicts rejected'
