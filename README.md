# nfqueue-router

A Zig domain-based IPv4 router. The deployed gateway uses a concurrent DNS server
and kernel nftables DNAT/SNAT/conntrack (`dns --nft-map`). A legacy NFQUEUE worker
is also available.

## What it does

- Reads a configuration directory containing files named after Linux interfaces.
  - `awg0.txt` means domains in that file are routed with mark for `awg0`.
  - `eth1.list` means domains in that file are routed with mark for `eth1`.
- Assigns every configured domain a deterministic fake IPv4 address from `127.128.0.0/9` by default.
- Runs a UDP + TCP DNS server (also usable as an upstream for Knot Resolver):
  - A query for a configured domain returns its fake IP.
  - AAAA query for a configured domain returns NODATA to avoid IPv6 bypass.
  - HTTPS/SVCB and ANY are also suppressed for routed names to prevent bypass.
  - Other record types are proxied to `--upstream-dns`.
  - Upstream UDP replies are source-pinned and validated against randomized IDs
    and the question; truncated replies are retried over TCP.
  - A records are selected only from the requested owner/CNAME chain and cached
    for their upstream TTL (maximum 1 hour; TTL=0 is not cached).
  - NXDOMAIN, NODATA and temporary failures remain distinct.
  - Synthetic answers do not claim DNSSEC authentication (AD).
- Runs a Linux NFQUEUE worker:
  - outbound TCP/UDP packets to fake IPs are rewritten to the real upstream A address;
  - packet mark is set according to the selected interface;
  - reply packets are rewritten back from real source IP to fake source IP.

Unlisted domains are not faked, so they use normal DNS and the system default route.

> Important: `127.0.0.0/8` is loopback space. The requested default `127.128.0.0/9` is suitable for local-host routing. For router/gateway use, prefer a non-loopback fake range such as `198.18.0.0/15` and pass `--fake-cidr`.

## Build

```sh
zig build
zig build -Dtarget=x86_64-linux
```

The NFQUEUE worker is Linux-only. The DNS/list/generator commands also run on macOS for development.

```sh
zig build test
python3 tests/dns_integration.py zig-out/bin/nfqueue-router
# Linux only; isolated netns is mandatory (the test creates its own nft table):
sudo unshare --net bash -c 'ip link set lo up; python3 tests/dns_integration.py zig-out/bin/nfqueue-router --kernel'
```

The integration suite covers DNS transports/errors/cache/concurrency, spoofed
responses, CNAMEs, durable/offline restarts, interface changes, nft rollback and
actual TCP/UDP DNAT with reverse conntrack translation.

## Domain configuration

```text
/etc/nfqueue-router/domains/
  awg0.txt
  wg1.txt
```

`awg0.txt`:

```text
example.com
*.video.example.com
yandex.ru
# comments and blank lines are ignored
```

Domains are exact names unless prefixed with `*.`. When multiple wildcard entries
match, the most specific suffix wins, including the wildcard's apex.

**Kernel mode:** all issued domain-to-fake-IP leases are durable and never
recycled automatically. DNS TTL/idle time does not bound application caches or
conntrack lifetimes, so recycling an idle fake IP could send an old connection
to a different domain. `--wildcard-idle-timeout` applies only to legacy NFQUEUE.
The finite fake pool returns SERVFAIL on exhaustion; reclaim leases only during
a planned reset after clearing client caches and relevant conntrack state.

## Inspect mapping

```sh
nfqueue-router list --domains-dir /etc/nfqueue-router/domains
```

## Knot Resolver integration

Run `nfqueue-router` DNS worker on localhost and tell Knot Resolver to forward through it:

```sh
nfqueue-router gen-kresd --dns-listen 127.0.0.1:53053
```

Example generated snippet:

```lua
modules = { 'policy' }
policy.add(policy.all(policy.FORWARD({ '127.0.0.1@53053' })))
```

Make sure `nfqueue-router --upstream-dns` points to an external resolver, not back to the same Knot Resolver instance.

## Kernel gateway deployment

Production helpers are in `deploy/`. `nfqueue-router.service` uses
`/etc/default/nfqueue-router`, creates its state directory, checks both DNS
transports for readiness, and preserves kernel maps across daemon stops/crashes.
The refresh helper owns only `inet nfqueue_router`; ordinary restarts do not
flush it. It redirects UDP/TCP DNS from the input interface and drops forwarded
fake destinations that have no DNAT mapping. It retains the existing gateway's
MSS/SNAT settings for `WG_IF` and `DEFAULT_IF`.

```sh
zig build -Dtarget=x86_64-linux -Doptimize=ReleaseSafe
# With the kernel base rules and policy routes installed:
nfqueue-router dns --nft-map \
  --domains-dir /etc/nfqueue-router/domains \
  --fake-cidr 198.18.0.0/15 --dns-listen 10.66.66.1:53 \
  --upstream-dns 1.1.1.1:53 \
  --state-file /var/lib/nfqueue-router/leases.txt
```

The state directory must already exist and be private/writable. A process lock
prevents two daemons sharing a lease store. Snapshot writes use fsync + atomic
rename + directory fsync **before** a fake answer is released. Both nft maps
(`fake_to_real`, `fake_to_mark`) are changed in a single transaction; failed
transactions return SERVFAIL and leave kernel state unchanged. Startup restores
saved destinations without waiting for upstream DNS. Interface names are
reconciled against current configuration, while old IP reservations are retained.
Invalid state or a different fake CIDR prevents startup rather than silently
reusing addresses. Do not delete/edit the state file while clients use fake IPs.

When upgrading from the old service, snapshot its nft table and import leases
with `deploy/migrate-leases.py` **before** deleting the old table. Unknown old
wildcard owners remain pinned migration reservations so cached clients keep
working; future queries may receive a different, non-conflicting lease.

Install `deploy/nfqueue-router-policy` as `/usr/local/sbin/nfqueue-router-policy`.
It applies policy routes idempotently, uses `protocol static`, checks priority
conflicts, and does not flush ranges of unrelated rules/tables. When networkd
manages `DEFAULT_IF`, it also generates a `90-nfqueue-router.conf` drop-in for
that interface's active `.network` file with matching `[RoutingPolicyRule]`
sections. This prevents networkd's default `ManageForeignRoutingPolicyRules=yes`
cleanup from deleting the VPN rule during reloads/restarts/package upgrades.
A changed drop-in triggers `networkctl reload` (which may renew DHCP); an
unchanged configuration does not. Re-run the helper if the active `.network`
filename changes. `apply --no-networkd` is for hosts managed by another network
manager and isolated test namespaces. Automatic range-wide `cleanup` is no
longer supported.

Test policy adoption, repeated apply, priority conflicts and preservation of
unrelated routes/rules in a disposable Linux namespace:

```sh
sudo unshare --net bash tests/policy_integration.sh \
  deploy/nfqueue-router-policy /usr/local/bin/nfqueue-router
```

`gen-nft` still generates legacy local-host NFQUEUE rules, not these gateway
rules. DNSSEC validation and IPv6 routing are not implemented.

## Legacy NFQUEUE Linux routing setup

Generate nftables rules. For real packet interception on a local host, prefer a non-loopback fake range:

```sh
nfqueue-router gen-nft \
  --domains-dir /etc/nfqueue-router/domains \
  --fake-cidr 198.18.0.0/15 \
  --queue-num 100 > /etc/nftables.d/nfqueue-router.nft
nft -f /etc/nftables.d/nfqueue-router.nft
```

Generate policy-routing rules for marks:

```sh
nfqueue-router gen-ip-rules --domains-dir /etc/nfqueue-router/domains > /tmp/nfqueue-router-routes.sh
sh /tmp/nfqueue-router-routes.sh
```

Then run the worker:

```sh
nfqueue-router run \
  --domains-dir /etc/nfqueue-router/domains \
  --fake-cidr 198.18.0.0/15 \
  --queue-num 100 \
  --dns-listen 127.0.0.1:53053 \
  --upstream-dns 1.1.1.1:53
```

## Notes

- Only IPv4 A records and IPv4 TCP/UDP packets are currently rewritten.
- Fragmented packets are dropped by the worker; keep MTU/MSS sane on tunnels.
- The worker sets Linux `fwmark`; actual interface selection is done by `ip rule`/routing tables.
- This is a low-level prototype; test in a network namespace before using on a real host.
