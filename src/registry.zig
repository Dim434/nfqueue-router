//! Durable kernel-mode leases. Addresses are NEVER automatically recycled:
//! DNS TTL does not bound application caches or conntrack lifetime.
const std = @import("std");
const ip = @import("ip.zig");
const config = @import("config.zig");
const nft = @import("nftctl.zig");

const Lease = struct { fake: ip.Ipv4, real: ip.Ipv4, iface: []const u8, domain: []const u8 };
pub const Registry = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    table: *const config.Table,
    leases: std.ArrayList(Lease) = .empty,
    by_fake: std.AutoHashMap(ip.Ipv4, usize),
    by_domain: std.StringHashMap(usize),
    mutex: std.atomic.Mutex = .unlocked,
    unhealthy: bool = false,
    lock_file: ?std.Io.File = null,

    pub fn init(a: std.mem.Allocator, io: std.Io, path: []const u8, table: *const config.Table) Registry {
        return .{ .allocator = a, .io = io, .path = path, .table = table, .by_fake = std.AutoHashMap(ip.Ipv4, usize).init(a), .by_domain = std.StringHashMap(usize).init(a) };
    }
    pub fn deinit(self: *Registry) void {
        if (self.lock_file) |file| file.close(self.io);
        for (self.leases.items) |l| {
            self.allocator.free(l.domain);
            self.allocator.free(l.iface);
        }
        self.leases.deinit(self.allocator);
        self.by_fake.deinit();
        self.by_domain.deinit();
    }
    pub fn load(self: *Registry) !void {
        const lock_path = try std.fmt.allocPrint(self.allocator, "{s}.lock", .{self.path});
        defer self.allocator.free(lock_path);
        self.lock_file = try std.Io.Dir.cwd().createFile(self.io, lock_path, .{ .truncate = false, .lock = .exclusive, .lock_nonblocking = true });
        const text = std.Io.Dir.cwd().readFileAlloc(self.io, self.path, self.allocator, .limited(128 * 1024 * 1024)) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer self.allocator.free(text);
        try self.decode(text);
    }
    fn decode(self: *Registry, text: []const u8) !void {
        if (text.len == 0 or text[text.len - 1] != '\n') return error.InvalidLeaseState;
        var lines = std.mem.splitScalar(u8, text, '\n');
        const header = lines.next() orelse return error.InvalidLeaseState;
        var h = std.mem.tokenizeScalar(u8, header, ' ');
        if (!std.mem.eql(u8, h.next() orelse "", "NFR1")) return error.InvalidLeaseState;
        const cidr = try ip.parseCidr(h.next() orelse return error.InvalidLeaseState);
        if (cidr.base != self.table.cidr.base or cidr.prefix != self.table.cidr.prefix or h.next() != null) return error.LeasePoolMismatch;
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            var fields = std.mem.tokenizeAny(u8, line, " \t");
            const fake = try ip.parseIpv4(fields.next() orelse return error.InvalidLeaseState);
            const real = try ip.parseIpv4(fields.next() orelse return error.InvalidLeaseState);
            const iface = fields.next() orelse return error.InvalidLeaseState;
            const domain = fields.next() orelse return error.InvalidLeaseState;
            if (fields.next() != null or !self.table.cidr.contains(fake) or self.by_fake.contains(fake)) return error.InvalidLeaseState;
            if (!std.mem.eql(u8, domain, "-")) {
                const canonical = try config.canonicalizeDomain(self.allocator, domain);
                defer self.allocator.free(canonical);
                if (!std.mem.eql(u8, canonical, domain) or self.by_domain.contains(domain)) return error.InvalidLeaseState;
            }
            try self.insert(.{ .fake = fake, .real = real, .iface = iface, .domain = domain });
        }
    }
    fn insert(self: *Registry, lease: Lease) !void {
        try self.leases.ensureUnusedCapacity(self.allocator, 1);
        try self.by_fake.ensureUnusedCapacity(1);
        try self.by_domain.ensureUnusedCapacity(1);
        const domain = try self.allocator.dupe(u8, lease.domain);
        errdefer self.allocator.free(domain);
        const iface = try self.allocator.dupe(u8, lease.iface);
        const idx = self.leases.items.len;
        self.leases.appendAssumeCapacity(.{ .fake = lease.fake, .real = lease.real, .domain = domain, .iface = iface });
        self.by_fake.putAssumeCapacity(lease.fake, idx);
        if (!std.mem.eql(u8, domain, "-")) self.by_domain.putAssumeCapacity(domain, idx);
    }
    fn save(self: *Registry) !void {
        var b: std.ArrayList(u8) = .empty;
        defer b.deinit(self.allocator);
        var addr: [16]u8 = undefined;
        try b.print(self.allocator, "NFR1 {s}/{}\n", .{ ip.formatIpv4(&addr, self.table.cidr.base), self.table.cidr.prefix });
        for (self.leases.items) |l| {
            var real: [16]u8 = undefined;
            try b.print(self.allocator, "{s} {s} {s} {s}\n", .{ ip.formatIpv4(&addr, l.fake), ip.formatIpv4(&real, l.real), l.iface, l.domain });
        }
        var file = try std.Io.Dir.cwd().createFileAtomic(self.io, self.path, .{ .replace = true, .make_path = true });
        defer file.deinit(self.io);
        try file.file.writeStreamingAll(self.io, b.items);
        try file.file.sync(self.io);
        try file.replace(self.io);
        // Persist the rename as well as file contents before releasing a lease.
        // Atomic.dir may be AT_FDCWD or an O_PATH descriptor, neither of which
        // can be fsynced. Open the actual parent with read access explicitly.
        var parent = try std.Io.Dir.cwd().openDir(self.io, std.fs.path.dirname(self.path) orelse ".", .{ .iterate = true });
        defer parent.close(self.io);
        const rc = std.posix.system.fsync(parent.handle);
        if (std.posix.errno(rc) != .SUCCESS) return error.LeaseDirectorySyncFailed;
    }
    pub fn restore(self: *Registry, controller: *nft.Controller) !void {
        var records: std.ArrayList(nft.Record) = .empty;
        defer records.deinit(self.allocator);
        for (self.leases.items) |l| {
            if (l.real == 0) continue; // migration reservation with no resolved destination
            const mark = if (std.mem.eql(u8, l.domain, "-")) blk: {
                for (self.table.interfaces.items) |iface| {
                    if (std.mem.eql(u8, iface.name, l.iface)) break :blk iface.mark;
                }
                continue;
            } else blk: {
                const route = self.table.lookupDomain(l.domain) orelse continue;
                break :blk self.table.ifaceFor(route).mark;
            };
            try records.append(self.allocator, .{ .fake = l.fake, .real = l.real, .mark = mark });
        }
        try controller.restore(records.items);
    }
    pub fn ensure(self: *Registry, domain: []const u8, route: *const config.Route, real: ip.Ipv4, controller: *nft.Controller) !ip.Ipv4 {
        while (!self.mutex.tryLock()) std.Thread.yield() catch {};
        defer self.mutex.unlock();
        if (self.unhealthy) return error.LeaseStoreUnhealthy;
        const iface = self.table.ifaceFor(route);
        var dirty = false;
        const idx = self.by_domain.get(domain) orelse blk: {
            const fake = try self.allocate(domain, route);
            const idx = self.leases.items.len;
            try self.insert(.{ .fake = fake, .real = real, .iface = iface.name, .domain = domain });
            dirty = true;
            break :blk idx;
        };
        const l = &self.leases.items[idx];
        if (l.real != real or !std.mem.eql(u8, l.iface, iface.name)) {
            const owned = try self.allocator.dupe(u8, iface.name);
            self.allocator.free(l.iface);
            l.iface = owned;
            l.real = real;
            dirty = true;
        }
        if (dirty) self.save() catch |err| {
            // The rename may have succeeded: retain ALL reservations and fail
            // closed until restart rather than risking address reassignment.
            self.unhealthy = true;
            return err;
        };
        try controller.ensureMapping(l.fake, real, iface.mark);
        return l.fake;
    }
    fn allocate(self: *Registry, domain: []const u8, route: *const config.Route) !ip.Ipv4 {
        if (!route.wildcard and !self.by_fake.contains(route.fake_ip)) return route.fake_ip;
        var slot = (std.hash.Fnv1a_64.hash(domain) ^ 0xd1f0f00d8badf00d) % self.table.cidr.size();
        var probes: u64 = 0;
        while (probes < self.table.cidr.size()) : (probes += 1) {
            const fake = try self.table.cidr.nth(slot);
            if (!self.by_fake.contains(fake) and !self.table.by_fake.contains(fake)) return fake;
            slot = (slot + 1) % self.table.cidr.size();
        }
        return error.FakeCidrExhausted;
    }
};

test "persisted leases and migration tombstones reserve addresses independent of lookup order" {
    const a = std.testing.allocator;
    var table = config.Table.init(a, try ip.parseCidr("198.18.0.0/30"));
    defer table.deinit();
    var r = Registry.init(a, std.testing.io, "unused", &table);
    defer r.deinit();
    try r.decode("NFR1 198.18.0.0/30\n198.18.0.0 1.1.1.1 wg-de a.example.com\n198.18.0.1 1.1.1.1 wg-de -\n");
    try std.testing.expectEqual(@as(usize, 0), r.by_domain.get("a.example.com").?);
    const route = config.Route{ .domain = "example.com", .wildcard = true, .interface_index = 0, .fake_ip = 0 };
    const fake = try r.allocate("e.example.com", &route);
    try std.testing.expect(fake != 0xc6120000 and fake != 0xc6120001);
    try std.testing.expectError(error.InvalidLeaseState, r.decode("NFR1 198.18.0.0/30\n198.18.0.2 1.1.1.1 wg-de broken"));
}
