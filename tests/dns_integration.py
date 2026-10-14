#!/usr/bin/env python3
"""Standard-library DNS integration tests. --kernel must run in a disposable Linux netns."""
import argparse, collections, concurrent.futures, json, os, socket, struct, subprocess, tempfile, threading, time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument('binary')
parser.add_argument('--kernel', action='store_true')
args = parser.parse_args()

def name(n):
    return b''.join(bytes([len(x)]) + x.encode() for x in n.split('.')) + b'\0' if n else b'\0'
def question(n, kind=1, ident=0x1234, flags=0x0100):
    return struct.pack('!6H', ident, flags, 1, 0, 0, 0) + name(n) + struct.pack('!HH', kind, 1)
def read_question(q):
    pos, labels = 12, []
    while q[pos]:
        size = q[pos]; labels.append(q[pos+1:pos+1+size].decode()); pos += size+1
    return '.'.join(labels), struct.unpack('!H', q[pos+1:pos+3])[0], pos+5

def rr(owner, kind, data, ttl=60):
    return owner + struct.pack('!HHIH', kind, 1, ttl, len(data)) + data

def response(q, records=(), rcode=0, tc=False):
    _, _, end = read_question(q)
    return q[:2] + struct.pack('!5H', 0x8180 | rcode | (0x200 if tc else 0), 1, len(records), 0, 0) + q[12:end] + b''.join(records)
def rcode(r): return r[3] & 15

def exact(s, size):
    b = b''
    while len(b) < size:
        part = s.recv(size - len(b))
        if not part: raise EOFError()
        b += part
    return b

def frame(s): return exact(s, struct.unpack('!H', exact(s, 2))[0])
def framed_send(s, q): s.sendall(struct.pack('!H', len(q)) + q)

class Upstream:
    def __init__(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(('127.0.0.1', 0))
        self.port = self.udp.getsockname()[1]
        self.tcp = socket.socket(); self.tcp.bind(('127.0.0.1', self.port)); self.tcp.listen()
        self.rogue = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); self.rogue.bind(('127.0.0.1', 0))
        self.count = collections.Counter()
        self.slow = threading.Event()
        self.enabled = True
        self.real = '203.0.113.10'
        self.pool = concurrent.futures.ThreadPoolExecutor(16)
        threading.Thread(target=self.udp_loop, daemon=True).start()
        threading.Thread(target=self.tcp_loop, daemon=True).start()
    def reply(self, q, tcp=False):
        n, kind, _ = read_question(q)
        self.count[(n, kind, tcp)] += 1
        if not self.enabled or n.startswith('timeout.'):
            return None
        if n.startswith('nx.'): return response(q, rcode=3)
        if n.startswith('fail.'): return response(q, rcode=2)
        if n.startswith('empty.'): return response(q)
        if n.startswith('slow.'):
            self.slow.set(); time.sleep(0.6)
        if n.startswith('big.'):
            if not tcp: return response(q, tc=True)
            return response(q, [rr(b'\xc0\x0c', 16, (b'\xfa'+b'x'*250)*4)])
        if n.startswith('alias.'):
            # Deliberately unrelated A first; only the CNAME chain is eligible.
            return response(q, [rr(name('unrelated.invalid'), 1, socket.inet_aton('203.0.113.66')), rr(b'\xc0\x0c', 5, name('target.example.com'), 30), rr(name('target.example.com'), 1, socket.inet_aton(self.real), 60)])
        if n.startswith('chase.'):
            return response(q, [rr(b'\xc0\x0c', 5, name('target.example.com'), 30)])
        if n.startswith('loop.'):
            return response(q, [rr(b'\xc0\x0c', 5, name(n))])
        if kind == 1:
            ttl = 0 if n.startswith('zero.') else 60
            return response(q, [rr(b'\xc0\x0c', 1, socket.inet_aton(self.real), ttl)])
        data = {16: b'\x02ok', 2: name('ns.example.net'), 15: b'\0\x0a'+name('mx.example.net'), 33: b'\0\0\0\0\x01\xbb'+name('srv.example.net')}.get(kind, b'\x02ok')
        return response(q, [rr(b'\xc0\x0c', kind, data)])
    def udp_one(self, q, peer):
        n, _, _ = read_question(q)
        if n.startswith('forged.'):
            fake = response(q, [rr(b'\xc0\x0c', 1, socket.inet_aton('203.0.113.66'))])
            self.rogue.sendto(fake, peer)  # correct ID, wrong source port
            self.udp.sendto(b'\x99\x99'+fake[2:], peer)  # wrong ID
            wrong = question('attacker.invalid', ident=struct.unpack('!H', q[:2])[0])
            self.udp.sendto(response(wrong, [rr(b'\xc0\x0c', 1, socket.inet_aton('203.0.113.66'))]), peer)
            time.sleep(0.03)
        reply = self.reply(q)
        if reply is not None: self.udp.sendto(reply, peer)
    def udp_loop(self):
        while True:
            q, peer = self.udp.recvfrom(65535)
            self.pool.submit(self.udp_one, q, peer)
    def tcp_one(self, s):
        with s:
            s.settimeout(2)
            try:
                q = frame(s); reply = self.reply(q, True)
                if reply is not None: framed_send(s, reply)
            except (OSError, EOFError): pass
    def tcp_loop(self):
        while True:
            s, _ = self.tcp.accept(); self.pool.submit(self.tcp_one, s)

up = Upstream()
with tempfile.TemporaryDirectory(prefix='nfr-integration-') as tmp:
    root = Path(tmp); domains = root/'domains'; domains.mkdir()
    (domains/'wg-de.txt').write_text('example.com\n*.example.com\n')
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]; probe.close()
    cmd = [str(Path(args.binary).resolve()), 'dns', '--domains-dir', str(domains), '--fake-cidr', '198.18.0.0/15', '--dns-listen', f'127.0.0.1:{port}', '--upstream-dns', f'127.0.0.1:{up.port}', '--dns-timeout-ms', '1000']
    if args.kernel:
        subprocess.run(['nft', '-f', '-'], input='table inet nfqueue_router {\n map fake_to_real { type ipv4_addr : ipv4_addr; }\n map fake_to_mark { type ipv4_addr : mark; }\n}\n', text=True, check=True)
        cmd += ['--nft-map', '--state-file', str(root/'leases.txt')]
    log = open(root/'service.log', 'w+')
    proc = None
    def ask(n, kind=1, tcp=False, flags=0x100):
        q = question(n, kind, flags=flags)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
            s.settimeout(3); s.connect(('127.0.0.1', port))
            if tcp: framed_send(s, q); r = frame(s)
            else: s.send(q); r = s.recv(65535)
            assert r[:2] == q[:2]
            return r
    def start():
        global proc
        proc = subprocess.Popen(cmd, stdout=log, stderr=log)
        deadline = time.monotonic()+3
        while time.monotonic() < deadline:
            try:
                assert rcode(ask('', 2, tcp=True, flags=0x7900)) == 4
                return
            except OSError:
                if proc.poll() is not None: break
                time.sleep(0.03)
        raise AssertionError('daemon did not become ready')
    def stop():
        proc.terminate(); proc.wait(timeout=5)
    def fake(n):
        r = ask(n); assert rcode(r) == 0 and struct.unpack('!H', r[6:8])[0] == 1, (n, r)
        return socket.inet_ntoa(r[-4:])
    def nft_map(n):
        raw = json.loads(subprocess.check_output(['nft', '-j', 'list', 'map', 'inet', 'nfqueue_router', n]))
        m = next(x['map'] for x in raw['nftables'] if 'map' in x)
        result = {}
        for item in m.get('elem', []):
            if isinstance(item, dict): item = item['elem']['val']
            result[item[0]] = item[1]
        return result
    try:
        start()
        for tcp in (False, True):
            for n, code in [('nx.example.com', 3), ('fail.example.com', 2), ('timeout.example.com', 2), ('empty.example.com', 0)]:
                assert rcode(ask(n, tcp=tcp)) == code, (n, tcp)
            assert rcode(ask('', 2, tcp=tcp)) == 0
            for kind in (2, 15, 16, 33):
                r = ask('records.example.com', kind, tcp=tcp)
                assert rcode(r) == 0 and struct.unpack('!H', r[6:8])[0] == 1
        print('PASS UDP/TCP, root NS, NXDOMAIN/SERVFAIL/NODATA, TXT/MX/SRV/NS forwarding')
        r = ask('big.unlisted.net', 16)
        assert r[2] & 2
        r = ask('big.unlisted.net', 16, tcp=True)
        assert not r[2] & 2 and len(r) > 1000
        print('PASS upstream TCP fallback + client UDP truncation + TCP full response')
        for _ in range(5):
            r = ask('forged.unlisted.net')
            assert socket.inet_ntoa(r[-4:]) == up.real
        print('PASS wrong source-port / transaction ID / question rejection')
        cached = fake('cached.example.com')
        before = up.count[('cached.example.com', 1, False)]
        assert fake('cached.example.com') == cached
        assert up.count[('cached.example.com', 1, False)] == before
        fake('zero.example.com'); fake('zero.example.com')
        assert up.count[('zero.example.com', 1, False)] == 2
        with concurrent.futures.ThreadPoolExecutor(2) as pool:
            slow = pool.submit(fake, 'slow.example.com')
            assert up.slow.wait(2)
            t = time.monotonic(); fake('cached.example.com'); ask('fast.unlisted.net', 16)
            assert time.monotonic()-t < 0.3
            slow.result()
        print('PASS cached A answers, TTL=0 honored, no global head-of-line blocking')
        alias = fake('alias.example.com'); fake('chase.example.com')
        assert rcode(ask('loop.example.com')) == 2
        print('PASS CNAME-chain resolution, unrelated A ignored, CNAME loop rejected')
        if args.kernel:
            assert nft_map('fake_to_real')[alias] == up.real
            assert nft_map('fake_to_mark')[cached] in (0x52000001, '0x52000001')
            state = (root/'leases.txt').read_bytes()
            stop(); up.enabled = False
            before = time.monotonic(); start(); assert time.monotonic()-before < 2
            assert nft_map('fake_to_real')[cached] == up.real
            assert (root/'leases.txt').read_bytes() == state
            up.enabled = True
            assert fake('cached.example.com') == cached
            print('PASS durable leases and offline restart restore')
            # Interface changes must change marks even when the real IP is identical.
            stop(); (domains/'eth0.txt').write_text('placeholder.invalid\n')
            start(); assert fake('cached.example.com') == cached
            assert nft_map('fake_to_mark')[cached] in (0x52000002, '0x52000002')
            print('PASS interface/mark reconciliation with unchanged real IP')
            # Force the SECOND map operation to fail. First map must remain unchanged.
            old = nft_map('fake_to_real').copy()
            subprocess.run(['nft', 'delete', 'map', 'inet', 'nfqueue_router', 'fake_to_mark'], check=True)
            assert rcode(ask('atomic-new.example.com')) == 2
            assert nft_map('fake_to_real') == old
            subprocess.run(['nft', '-f', '-'], input='add map inet nfqueue_router fake_to_mark { type ipv4_addr : mark; }\n', text=True, check=True)
            stop(); start()
            assert rcode(ask('atomic-new.example.com')) == 0
            print('PASS atomic nft rollback on second-map failure, SERVFAIL and recovery')
            # Kernel DNAT + conntrack reverse NAT, both transports, in this netns.
            subprocess.run(['ip', 'address', 'add', up.real+'/32', 'dev', 'lo'], check=True)
            subprocess.run(['ip', 'route', 'add', '198.18.0.0/15', 'dev', 'lo'], check=True)
            subprocess.run(['nft', '-f', '-'], input='add chain inet nfqueue_router local_nat { type nat hook output priority dstnat; }\nadd rule inet nfqueue_router local_nat ip daddr 198.18.0.0/15 dnat ip to ip daddr map @fake_to_real\n', text=True, check=True)
            for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
                with socket.socket(socket.AF_INET, kind) as target:
                    target.bind((up.real, 18443)); target.settimeout(3)
                    if kind == socket.SOCK_STREAM: target.listen()
                    def echo():
                        if kind == socket.SOCK_DGRAM:
                            data, peer = target.recvfrom(1024); target.sendto(data, peer)
                        else:
                            s, _ = target.accept()
                            with s: s.sendall(s.recv(1024))
                    t = threading.Thread(target=echo); t.start()
                    with socket.socket(socket.AF_INET, kind) as client:
                        client.settimeout(3); client.connect((cached, 18443)); client.sendall(b'kernel-nat-ok'); assert client.recv(1024) == b'kernel-nat-ok'
                    t.join()
            print('PASS real kernel TCP/UDP DNAT + reverse NAT')
        print('ALL INTEGRATION TESTS PASSED')
    except BaseException:
        log.flush(); log.seek(0); print(log.read()); raise
    finally:
        if proc is not None and proc.poll() is None: stop()
