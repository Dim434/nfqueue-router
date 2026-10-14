const std = @import("std");
const ip = @import("ip.zig");
const config = @import("config.zig");
const nftctl = @import("nftctl.zig");
const registry = @import("registry.zig");
const net = @import("netio.zig");
const wire = @import("dnswire.zig");
const sys = std.posix.system;
pub const Question = wire.Question;
pub const parseQuestion = wire.parseQuestion;
pub const AAnswer = wire.AAnswer;
pub const ServerOptions = struct {
    listen: ip.IpPort,
    upstream: ip.IpPort,
    fake_ttl: u32 = 60,
    timeout_ms: i32 = 1500,
    leases: ?*registry.Registry = null,
};
const CacheEntry = struct { answer: AAnswer, expires_ms: i64 };
pub const Resolver = struct {
    allocator: std.mem.Allocator,
    upstream: ip.IpPort,
    timeout_ms: i32,
    mutex: std.atomic.Mutex = .unlocked,
    cache: std.StringHashMap(CacheEntry),
    pub fn init(a: std.mem.Allocator, upstream: ip.IpPort, timeout_ms: i32) Resolver {
        return .{ .allocator = a, .upstream = upstream, .timeout_ms = timeout_ms, .cache = std.StringHashMap(CacheEntry).init(a) };
    }
    pub fn deinit(self: *Resolver) void {
        self.clear();
        self.cache.deinit();
    }
    fn clear(self: *Resolver) void {
        var it = self.cache.iterator();
        while (it.next()) |e| self.allocator.free(e.key_ptr.*);
        self.cache.clearRetainingCapacity();
    }
    pub fn resolveA(self: *Resolver, domain: []const u8) !ip.Ipv4 {
        return (try self.resolve(domain)).addr;
    }
    pub fn resolve(self: *Resolver, domain: []const u8) !AAnswer {
        while (!self.mutex.tryLock()) std.Thread.yield() catch {};
        const cached = self.cache.get(domain);
        self.mutex.unlock();
        const now = net.nowMs();
        if (cached) |e| if (e.expires_ms > now) return .{ .addr = e.answer.addr, .ttl = @intCast(@divTrunc(e.expires_ms - now, 1000)) };
        // Never hold a global cache lock over network I/O.
        const answer = try queryA(self.allocator, self.upstream, domain, self.timeout_ms);
        while (!self.mutex.tryLock()) std.Thread.yield() catch {};
        defer self.mutex.unlock();
        if (self.cache.count() >= 4096) self.clear();
        if (self.cache.fetchRemove(domain)) |old| self.allocator.free(old.key);
        if (answer.ttl > 0) {
            const owned = try self.allocator.dupe(u8, domain);
            errdefer self.allocator.free(owned);
            try self.cache.put(owned, .{ .answer = answer, .expires_ms = net.nowMs() + @as(i64, @min(answer.ttl, 3600)) * 1000 });
        }
        return answer;
    }
};

pub fn queryA(a: std.mem.Allocator, upstream: ip.IpPort, domain: []const u8, timeout_ms: i32) !AAnswer {
    var current = try a.dupe(u8, domain);
    defer a.free(current);
    const deadline = net.nowMs() + timeout_ms;
    var ttl: u32 = std.math.maxInt(u32);
    for (0..8) |_| {
        const q = try wire.query(a, current, try net.randomId());
        defer a.free(q);
        const r = try exchange(a, upstream, q, deadline);
        defer a.free(r);
        switch (try wire.extractA(a, r)) {
            .answer => |answer| return .{ .addr = answer.addr, .ttl = @min(ttl, answer.ttl) },
            .alias => |alias| {
                a.free(current);
                current = alias.domain;
                ttl = @min(ttl, alias.ttl);
            },
        }
    }
    return error.CnameLoop;
}

/// Connected UDP pins source IP AND port; randomize the upstream transaction
/// ID even for forwarded client requests. Discard mismatched packets only up
/// to the original deadline. Validate TCP responses identically.
fn exchange(a: std.mem.Allocator, upstream: ip.IpPort, request: []const u8, deadline: i64) ![]u8 {
    const q = try a.dupe(u8, request);
    defer a.free(q);
    wire.put16(q, 0, try net.randomId());
    const fd = try net.socket(false);
    defer net.close(fd);
    try net.connect(fd, upstream, deadline);
    try net.send(fd, q, deadline);
    var buf: [65535]u8 = undefined;
    while (true) {
        const n = try net.recv(fd, &buf, deadline);
        const r = buf[0..n];
        wire.validateResponse(a, q, r) catch continue;
        if ((wire.u16at(r, 2) & 0x0200) != 0) {
            const tcp = try net.socket(true);
            defer net.close(tcp);
            try net.connect(tcp, upstream, deadline);
            try net.writeFrame(tcp, q, deadline);
            const full = try net.readFrame(a, tcp, deadline);
            errdefer a.free(full);
            try wire.validateResponse(a, q, full);
            if ((wire.u16at(full, 2) & 0x0200) != 0) return error.TruncatedDnsResponse;
            wire.put16(full, 0, wire.u16at(request, 0));
            return full;
        }
        const result = try a.dupe(u8, r);
        wire.put16(result, 0, wire.u16at(request, 0));
        return result;
    }
}

const Server = struct {
    allocator: std.mem.Allocator,
    table: *const config.Table,
    dynamic: ?*config.DynamicMap,
    nft: ?*nftctl.Controller,
    opts: ServerOptions,
    resolver: Resolver,
    udp: net.fd_t,
    tcp_active: std.atomic.Value(u32) = .init(0),

    fn handle(self: *Server, request: []const u8) ![]u8 {
        const a = self.allocator;
        if (request.len < 12 or (wire.u16at(request, 2) & 0x8000) != 0) return error.NotDnsQuery;
        if ((wire.u16at(request, 2) & 0x7800) != 0) return wire.response(a, request, 4, null, 0, false);
        const q = wire.parseQuestion(a, request) catch return wire.response(a, request, 1, null, 0, false);
        defer a.free(q.name);
        const edns = wire.ednsInfo(a, request) catch return wire.response(a, request, 1, null, 0, false);
        if (edns) |opt| if (opt.version != 0) return wire.response(a, request, 0, null, 0, false);
        if (q.qclass == 1) if (self.table.lookupDomain(q.name)) |route| {
            // Only address/bypass-bearing record types are intentionally hidden.
            // TXT/MX/SRV/NS/DS/DNSKEY/etc retain upstream DNS semantics.
            if (q.qtype == 1 or q.qtype == 28 or q.qtype == 64 or q.qtype == 65 or q.qtype == 255) {
                const real = self.resolver.resolve(q.name) catch |err| switch (err) {
                    error.DnsNxDomain => return wire.response(a, request, 3, null, 0, false),
                    error.NoARecord => return wire.response(a, request, 0, null, 0, false),
                    else => return err,
                };
                if (q.qtype != 1) return wire.response(a, request, 0, null, 0, false);
                const fake = if (self.nft) |ctl| blk: {
                    const leases = self.opts.leases orelse return error.MissingLeaseStore;
                    break :blk try leases.ensure(q.name, route, real.addr, ctl);
                } else if (route.wildcard) blk: {
                    const dyn = self.dynamic orelse return error.MissingDynamicMap;
                    break :blk try dyn.getOrCreate(q.name, route.interface_index);
                } else route.fake_ip;
                return wire.response(a, request, 0, fake, self.opts.fake_ttl, false);
            }
        };
        return exchange(a, self.opts.upstream, request, net.nowMs() + self.opts.timeout_ms);
    }
    fn answer(self: *Server, request: []const u8) ![]u8 {
        return self.handle(request) catch |err| {
            std.debug.print("DNS request failed: {s}\n", .{@errorName(err)});
            return wire.response(self.allocator, request, 2, null, 0, false);
        };
    }
    fn udpWorker(self: *Server) void {
        var buf: [65535]u8 = undefined;
        while (true) {
            net.wait(self.udp, false, net.nowMs() + 60_000) catch continue;
            var src: std.posix.sockaddr.storage = undefined;
            var len: std.posix.socklen_t = @sizeOf(@TypeOf(src));
            const rc = sys.recvfrom(self.udp, &buf, buf.len, 0, @ptrCast(&src), &len);
            if (std.posix.errno(rc) != .SUCCESS) continue;
            const request = buf[0..@intCast(rc)];
            if (request.len < 12 or (wire.u16at(request, 2) & 0x8000) != 0) continue;
            const limit = wire.udpLimit(self.allocator, request) catch 512;
            const full = self.answer(request) catch continue;
            defer self.allocator.free(full);
            const truncated = if (full.len > limit) wire.response(self.allocator, request, @truncate(wire.u16at(full, 2)), null, 0, true) catch continue else null;
            defer if (truncated) |t| self.allocator.free(t);
            const result = truncated orelse full;
            _ = sys.sendto(self.udp, result.ptr, result.len, 0, @ptrCast(&src), len);
        }
    }
    fn tcpWorker(self: *Server, fd: net.fd_t) void {
        defer net.close(fd);
        defer _ = self.tcp_active.fetchSub(1, .monotonic);
        net.nonblocking(fd) catch return;
        // Bounded lifetime + bounded thread count, including slow-loris clients.
        const lifetime = net.nowMs() + 30_000;
        for (0..64) |_| {
            const request = net.readFrame(self.allocator, fd, @min(lifetime, net.nowMs() + 5000)) catch return;
            defer self.allocator.free(request);
            if ((wire.u16at(request, 2) & 0x8000) != 0) return;
            const result = self.answer(request) catch return;
            defer self.allocator.free(result);
            net.writeFrame(fd, result, @min(lifetime, net.nowMs() + 5000)) catch return;
        }
    }
};

/// Binds both transports before launching workers. No upstream priming before
/// readiness: persisted kernel mappings were restored by main, offline.
pub fn serveUdp(a: std.mem.Allocator, table: *const config.Table, dynamic: ?*config.DynamicMap, nft: ?*nftctl.Controller, opts: ServerOptions) !void {
    if (opts.timeout_ms < 1 or opts.timeout_ms > 30_000) return error.InvalidTimeout;
    const udp = try net.socket(false);
    defer net.close(udp);
    try net.bind(udp, opts.listen, false);
    const tcp = try net.socket(true);
    defer net.close(tcp);
    try net.bind(tcp, opts.listen, true);
    if (std.posix.errno(sys.listen(tcp, 128)) != .SUCCESS) return error.SocketListenFailed;
    var server = Server{ .allocator = a, .table = table, .dynamic = dynamic, .nft = nft, .opts = opts, .resolver = Resolver.init(a, opts.upstream, opts.timeout_ms), .udp = udp };
    defer server.resolver.deinit();
    for (0..16) |_| {
        const worker = std.Thread.spawn(.{}, Server.udpWorker, .{&server}) catch |err| {
            std.debug.print("DNS worker startup failed: {s}\n", .{@errorName(err)});
            std.process.exit(1); // Do not unwind stack storage underneath live workers.
        };
        worker.detach();
    }
    std.debug.print("DNS ready: UDP+TCP, 16 UDP workers, persistent kernel leases={}\n", .{opts.leases != null});
    while (true) {
        net.wait(tcp, false, net.nowMs() + 60_000) catch continue;
        const rc = sys.accept(tcp, null, null);
        if (std.posix.errno(rc) != .SUCCESS) continue;
        const fd: net.fd_t = @intCast(rc);
        if (server.tcp_active.fetchAdd(1, .monotonic) >= 32) {
            _ = server.tcp_active.fetchSub(1, .monotonic);
            net.close(fd);
            continue;
        }
        const worker = std.Thread.spawn(.{}, Server.tcpWorker, .{ &server, fd }) catch {
            _ = server.tcp_active.fetchSub(1, .monotonic);
            net.close(fd);
            continue;
        };
        worker.detach();
    }
}

test {
    _ = wire;
    _ = net;
}
