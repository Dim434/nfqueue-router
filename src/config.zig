const std = @import("std");
const ip = @import("ip.zig");
const timeutil = @import("timeutil.zig");

pub const Interface = struct {
    name: []const u8,
    mark: u32,
};

pub const Route = struct {
    /// Canonical base domain. For wildcard routes this omits the leading "*.".
    domain: []const u8,
    wildcard: bool = false,
    interface_index: usize,
    fake_ip: ip.Ipv4,
};

pub const DynamicHit = struct {
    domain: []u8,
    interface_index: usize,
};

const DynamicEntry = struct {
    domain: []const u8,
    interface_index: usize,
    expires_at: u64,
};

pub const DynamicMap = struct {
    pub const default_idle_ttl_seconds: u64 = 60 * 60;
    const cleanup_interval_seconds: u64 = 60;

    allocator: std.mem.Allocator,
    table: *const Table,
    idle_ttl_seconds: u64,
    next_cleanup_at: u64 = 0,
    mutex: std.atomic.Mutex = .unlocked,
    by_fake: std.AutoHashMap(ip.Ipv4, DynamicEntry),
    by_domain: std.StringHashMap(ip.Ipv4),

    pub fn init(allocator: std.mem.Allocator, table: *const Table) DynamicMap {
        return initWithIdleTtl(allocator, table, default_idle_ttl_seconds);
    }

    pub fn initWithIdleTtl(allocator: std.mem.Allocator, table: *const Table, idle_ttl_seconds: u64) DynamicMap {
        return .{
            .allocator = allocator,
            .table = table,
            .idle_ttl_seconds = idle_ttl_seconds,
            .by_fake = std.AutoHashMap(ip.Ipv4, DynamicEntry).init(allocator),
            .by_domain = std.StringHashMap(ip.Ipv4).init(allocator),
        };
    }

    pub fn deinit(self: *DynamicMap) void {
        var it = self.by_fake.iterator();
        while (it.next()) |entry| self.allocator.free(entry.value_ptr.domain);
        self.by_fake.deinit();
        self.by_domain.deinit();
    }

    pub fn getOrCreate(self: *DynamicMap, domain: []const u8, interface_index: usize) !ip.Ipv4 {
        self.lock();
        defer self.unlock();

        const now = timeutil.nowSeconds();
        try self.maybeCleanupLocked(now);

        if (self.by_domain.get(domain)) |existing| {
            self.by_fake.getPtr(existing).?.expires_at = self.expirationFrom(now);
            return existing;
        }

        const owned = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(owned);
        const fake = try self.allocateFakeLocked(domain);
        try self.by_domain.put(owned, fake);
        errdefer _ = self.by_domain.remove(owned);
        try self.by_fake.put(fake, .{
            .domain = owned,
            .interface_index = interface_index,
            .expires_at = self.expirationFrom(now),
        });
        return fake;
    }

    pub fn lookupFakeCopy(self: *DynamicMap, allocator: std.mem.Allocator, fake: ip.Ipv4) !?DynamicHit {
        self.lock();
        defer self.unlock();

        const now = timeutil.nowSeconds();
        try self.maybeCleanupLocked(now);
        const entry = self.by_fake.getPtr(fake) orelse return null;
        entry.expires_at = self.expirationFrom(now);
        return .{
            .domain = try allocator.dupe(u8, entry.domain),
            .interface_index = entry.interface_index,
        };
    }

    pub fn cleanupExpired(self: *DynamicMap) !void {
        self.lock();
        defer self.unlock();
        try self.cleanupExpiredLocked(timeutil.nowSeconds());
    }

    fn maybeCleanupLocked(self: *DynamicMap, now: u64) !void {
        if (now < self.next_cleanup_at) return;
        try self.cleanupExpiredLocked(now);
        self.next_cleanup_at = now +| @min(cleanup_interval_seconds, @max(self.idle_ttl_seconds, 1));
    }

    fn cleanupExpiredLocked(self: *DynamicMap, now: u64) !void {
        var expired: std.ArrayList(ip.Ipv4) = .empty;
        defer expired.deinit(self.allocator);

        var it = self.by_fake.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.expires_at <= now) try expired.append(self.allocator, entry.key_ptr.*);
        }

        for (expired.items) |fake| {
            const removed = self.by_fake.fetchRemove(fake) orelse continue;
            _ = self.by_domain.remove(removed.value.domain);
            self.allocator.free(removed.value.domain);
        }
    }

    fn expirationFrom(self: *const DynamicMap, now: u64) u64 {
        return now +| self.idle_ttl_seconds;
    }

    fn allocateFakeLocked(self: *DynamicMap, domain: []const u8) !ip.Ipv4 {
        var slot = (std.hash.Fnv1a_64.hash(domain) ^ 0xd1f0f00d8badf00d) % self.table.cidr.size();
        var probes: u64 = 0;
        while (probes < self.table.cidr.size()) : (probes += 1) {
            const candidate = try self.table.cidr.nth(slot);
            if (!self.table.by_fake.contains(candidate) and !self.by_fake.contains(candidate)) return candidate;
            slot = (slot + 1) % self.table.cidr.size();
        }
        return error.FakeCidrExhausted;
    }

    fn lock(self: *DynamicMap) void {
        while (!self.mutex.tryLock()) std.Thread.yield() catch {};
    }

    fn unlock(self: *DynamicMap) void {
        self.mutex.unlock();
    }
};

pub const Table = struct {
    allocator: std.mem.Allocator,
    cidr: ip.Cidr,
    interfaces: std.ArrayList(Interface),
    routes: std.ArrayList(Route),
    by_fake: std.AutoHashMap(ip.Ipv4, usize),
    by_domain: std.StringHashMap(usize),

    pub fn init(allocator: std.mem.Allocator, cidr: ip.Cidr) Table {
        return .{
            .allocator = allocator,
            .cidr = cidr,
            .interfaces = .empty,
            .routes = .empty,
            .by_fake = std.AutoHashMap(ip.Ipv4, usize).init(allocator),
            .by_domain = std.StringHashMap(usize).init(allocator),
        };
    }

    pub fn deinit(self: *Table) void {
        for (self.interfaces.items) |iface| self.allocator.free(iface.name);
        for (self.routes.items) |route| self.allocator.free(route.domain);
        self.interfaces.deinit(self.allocator);
        self.routes.deinit(self.allocator);
        self.by_fake.deinit();
        self.by_domain.deinit();
    }

    pub fn lookupFake(self: *const Table, fake: ip.Ipv4) ?*const Route {
        const idx = self.by_fake.get(fake) orelse return null;
        return &self.routes.items[idx];
    }

    pub fn lookupDomainExact(self: *const Table, domain: []const u8) ?*const Route {
        const idx = self.by_domain.get(domain) orelse return null;
        return &self.routes.items[idx];
    }

    pub fn lookupDomain(self: *const Table, domain: []const u8) ?*const Route {
        if (self.lookupDomainExact(domain)) |route| return route;

        var best: ?*const Route = null;
        for (self.routes.items) |*route| {
            if (!route.wildcard or !wildcardMatches(route.domain, domain)) continue;
            if (best == null or route.domain.len > best.?.domain.len) best = route;
        }
        return best;
    }

    pub fn ifaceFor(self: *const Table, route: *const Route) *const Interface {
        return &self.interfaces.items[route.interface_index];
    }

    pub fn load(
        allocator: std.mem.Allocator,
        io_impl: std.Io,
        dir_path: []const u8,
        cidr: ip.Cidr,
        mark_base: u32,
    ) !Table {
        var table = Table.init(allocator, cidr);
        errdefer table.deinit();

        var dir = try std.Io.Dir.cwd().openDir(io_impl, dir_path, .{ .iterate = true, .access_sub_paths = true });
        defer dir.close(io_impl);

        var file_names: std.ArrayList([]const u8) = .empty;
        defer {
            for (file_names.items) |name| allocator.free(name);
            file_names.deinit(allocator);
        }

        var it = dir.iterate();
        while (try it.next(io_impl)) |entry| {
            if (entry.kind != .file and entry.kind != .sym_link) continue;
            if (entry.name.len == 0 or entry.name[0] == '.') continue;
            try file_names.append(allocator, try allocator.dupe(u8, entry.name));
        }
        std.mem.sort([]const u8, file_names.items, {}, lessStrings);

        for (file_names.items) |file_name| {
            const iface_name = try interfaceNameFromFile(allocator, file_name);
            var iface_name_needs_free = true;
            errdefer if (iface_name_needs_free) allocator.free(iface_name);
            const iface_index = table.interfaces.items.len;
            const mark = mark_base + @as(u32, @intCast(iface_index + 1));
            try table.interfaces.append(allocator, .{ .name = iface_name, .mark = mark });
            iface_name_needs_free = false;

            const content = try dir.readFileAlloc(io_impl, file_name, allocator, .limited(16 * 1024 * 1024));
            defer allocator.free(content);
            try parseDomainFile(&table, content, iface_index);
        }

        try assignFakeIps(&table);
        std.mem.sort(Route, table.routes.items, table.interfaces.items, lessRoutesByInterfaceThenDomain);
        try rebuildIndexes(&table);
        return table;
    }
};

fn lessStrings(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

fn lessRoutesByInterfaceThenDomain(ifaces: []const Interface, a: Route, b: Route) bool {
    const ai = ifaces[a.interface_index].name;
    const bi = ifaces[b.interface_index].name;
    const iface_order = std.mem.order(u8, ai, bi);
    if (iface_order != .eq) return iface_order == .lt;
    const domain_order = std.mem.order(u8, a.domain, b.domain);
    if (domain_order != .eq) return domain_order == .lt;
    return !a.wildcard and b.wildcard;
}

fn parseDomainFile(table: *Table, content: []const u8, iface_index: usize) !void {
    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line_raw| {
        const hash_pos = std.mem.findScalar(u8, line_raw, '#') orelse line_raw.len;
        const trimmed = std.mem.trim(u8, line_raw[0..hash_pos], " \t\r");
        if (trimmed.len == 0) continue;

        const wildcard = std.mem.startsWith(u8, trimmed, "*.");
        const domain_text = if (wildcard) trimmed[2..] else trimmed;
        const domain = try canonicalizeDomain(table.allocator, domain_text);
        errdefer table.allocator.free(domain);

        var duplicate = false;
        for (table.routes.items) |existing| {
            if (existing.wildcard == wildcard and std.mem.eql(u8, existing.domain, domain)) {
                if (existing.interface_index != iface_index) return error.DuplicateDomainInDifferentInterfaces;
                table.allocator.free(domain);
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;

        const idx = table.routes.items.len;
        try table.routes.append(table.allocator, .{
            .domain = domain,
            .wildcard = wildcard,
            .interface_index = iface_index,
            .fake_ip = 0,
        });
        if (!wildcard) try table.by_domain.put(table.routes.items[idx].domain, idx);
    }
}

fn assignFakeIps(table: *Table) !void {
    table.by_fake.clearRetainingCapacity();
    for (table.routes.items, 0..) |*route, idx| {
        var h = std.hash.Fnv1a_64.hash(route.domain);
        if (route.wildcard) h ^= 0x9e3779b97f4a7c15;
        var slot = h % table.cidr.size();
        var probes: u64 = 0;
        while (probes < table.cidr.size()) : (probes += 1) {
            const candidate = try table.cidr.nth(slot);
            if (!table.by_fake.contains(candidate)) {
                route.fake_ip = candidate;
                try table.by_fake.put(candidate, idx);
                break;
            }
            slot = (slot + 1) % table.cidr.size();
        } else return error.FakeCidrExhausted;
    }
}

fn rebuildIndexes(table: *Table) !void {
    table.by_domain.clearRetainingCapacity();
    table.by_fake.clearRetainingCapacity();
    for (table.routes.items, 0..) |route, idx| {
        if (!route.wildcard) try table.by_domain.put(route.domain, idx);
        try table.by_fake.put(route.fake_ip, idx);
    }
}

pub fn wildcardMatches(base: []const u8, domain: []const u8) bool {
    if (std.mem.eql(u8, base, domain)) return true;
    if (domain.len <= base.len + 1) return false;
    if (domain[domain.len - base.len - 1] != '.') return false;
    return std.mem.eql(u8, domain[domain.len - base.len ..], base);
}

pub fn interfaceNameFromFile(allocator: std.mem.Allocator, file_name: []const u8) ![]u8 {
    const ext = std.fs.path.extension(file_name);
    const base = if (std.mem.eql(u8, ext, ".txt") or
        std.mem.eql(u8, ext, ".list") or
        std.mem.eql(u8, ext, ".domains") or
        std.mem.eql(u8, ext, ".conf"))
        file_name[0 .. file_name.len - ext.len]
    else
        file_name;
    if (base.len == 0) return error.InvalidInterfaceFileName;
    return allocator.dupe(u8, base);
}

pub fn canonicalizeDomain(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
    var s = std.mem.trim(u8, raw, " \t\r\n");
    while (s.len > 0 and s[s.len - 1] == '.') s = s[0 .. s.len - 1];
    if (s.len == 0 or s.len > 253) return error.InvalidDomain;

    var out = try allocator.alloc(u8, s.len);
    errdefer allocator.free(out);

    var label_len: usize = 0;
    var prev_dot = true;
    for (s, 0..) |c, i| {
        const lc: u8 = if (c >= 'A' and c <= 'Z') c + ('a' - 'A') else c;
        const ok = (lc >= 'a' and lc <= 'z') or (lc >= '0' and lc <= '9') or lc == '-' or lc == '_' or lc == '.';
        if (!ok) return error.InvalidDomain;
        if (lc == '.') {
            if (prev_dot or label_len == 0 or label_len > 63) return error.InvalidDomain;
            label_len = 0;
            prev_dot = true;
        } else {
            label_len += 1;
            prev_dot = false;
        }
        out[i] = lc;
    }
    if (prev_dot or label_len == 0 or label_len > 63) return error.InvalidDomain;
    return out;
}

test "canonical domains" {
    const a = std.testing.allocator;
    const d = try canonicalizeDomain(a, "  Example.COM. \r");
    defer a.free(d);
    try std.testing.expectEqualStrings("example.com", d);
    try std.testing.expect(wildcardMatches("youtube.com", "youtube.com"));
    try std.testing.expect(wildcardMatches("youtube.com", "m.youtube.com"));
    try std.testing.expect(!wildcardMatches("youtube.com", "notyoutube.com"));
}

test "interface names" {
    const a = std.testing.allocator;
    const iface = try interfaceNameFromFile(a, "awg0.txt");
    defer a.free(iface);
    try std.testing.expectEqualStrings("awg0", iface);
}

test "domain lookup prefers the most specific wildcard" {
    const a = std.testing.allocator;
    var table = Table.init(a, ip.Cidr.defaultFake());
    defer table.deinit();

    try table.interfaces.append(a, .{ .name = try a.dupe(u8, "first"), .mark = 1 });
    try table.interfaces.append(a, .{ .name = try a.dupe(u8, "second"), .mark = 2 });
    try table.routes.append(a, .{
        .domain = try a.dupe(u8, "example.com"),
        .wildcard = true,
        .interface_index = 0,
        .fake_ip = 1,
    });
    try table.routes.append(a, .{
        .domain = try a.dupe(u8, "sub.example.com"),
        .wildcard = true,
        .interface_index = 1,
        .fake_ip = 2,
    });

    const route = table.lookupDomain("host.sub.example.com") orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(usize, 1), route.interface_index);
}

test "expired dynamic mappings are removed" {
    const a = std.testing.allocator;
    var table = Table.init(a, try ip.parseCidr("198.18.0.0/30"));
    defer table.deinit();

    var dynamic = DynamicMap.initWithIdleTtl(a, &table, 60);
    defer dynamic.deinit();

    const fake = try dynamic.getOrCreate("host.example.com", 0);
    dynamic.by_fake.getPtr(fake).?.expires_at = 0;
    try dynamic.cleanupExpired();

    try std.testing.expect(!dynamic.by_fake.contains(fake));
    try std.testing.expect(!dynamic.by_domain.contains("host.example.com"));
}
