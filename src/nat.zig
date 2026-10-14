const std = @import("std");
const ip = @import("ip.zig");
const packet = @import("packet.zig");
const config = @import("config.zig");
const dns = @import("dns.zig");
const timeutil = @import("timeutil.zig");

pub const FlowKey = struct {
    proto: u8,
    local_ip: ip.Ipv4,
    local_port: u16,
    remote_ip: ip.Ipv4,
    remote_port: u16,
};

const FlowEntry = struct {
    fake_ip: ip.Ipv4,
    mark: u32,
    expires_at: u64,
};

pub const AcceptDecision = struct {
    modified: bool = false,
    mark: u32 = 0,
};

pub const Decision = union(enum) {
    accept: AcceptDecision,
    drop,
};

pub const Router = struct {
    allocator: std.mem.Allocator,
    table: *const config.Table,
    dynamic: *config.DynamicMap,
    resolver: *dns.Resolver,
    flows: std.AutoHashMap(FlowKey, FlowEntry),
    packets_seen: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, table: *const config.Table, dynamic: *config.DynamicMap, resolver: *dns.Resolver) Router {
        return .{
            .allocator = allocator,
            .table = table,
            .dynamic = dynamic,
            .resolver = resolver,
            .flows = std.AutoHashMap(FlowKey, FlowEntry).init(allocator),
        };
    }

    pub fn deinit(self: *Router) void {
        self.flows.deinit();
    }

    pub fn process(self: *Router, pkt: []u8) !Decision {
        self.packets_seen += 1;
        if ((self.packets_seen & 0x3ff) == 0) try self.cleanupExpired();

        const info = packet.parseIpv4Transport(pkt) catch |err| switch (err) {
            error.NotIpv4, error.NotTcpUdp => return .{ .accept = .{} },
            error.FragmentedPacketUnsupported => return .drop,
            else => return .{ .accept = .{} },
        };

        var owned_domain: ?[]u8 = null;
        defer if (owned_domain) |d| self.allocator.free(d);
        var route_domain: ?[]const u8 = null;
        var route_iface_index: usize = 0;

        if (self.table.lookupFake(info.dst_ip)) |route| {
            route_domain = route.domain;
            route_iface_index = route.interface_index;
        } else if (try self.dynamic.lookupFakeCopy(self.allocator, info.dst_ip)) |hit| {
            owned_domain = hit.domain;
            route_domain = hit.domain;
            route_iface_index = hit.interface_index;
        } else if (self.table.cidr.contains(info.dst_ip)) {
            // Traffic to a fake address that is not in our table should never be leaked.
            return .drop;
        }

        if (route_domain) |domain| {
            const iface = &self.table.interfaces.items[route_iface_index];
            const real_ip = self.resolver.resolveA(domain) catch |err| {
                std.debug.print("resolve failed for {s}: {s}\n", .{ domain, @errorName(err) });
                return .drop;
            };

            const key = FlowKey{
                .proto = @intFromEnum(info.protocol),
                .local_ip = info.src_ip,
                .local_port = info.src_port,
                .remote_ip = real_ip,
                .remote_port = info.dst_port,
            };
            try self.flows.put(key, .{
                .fake_ip = info.dst_ip,
                .mark = iface.mark,
                .expires_at = timeutil.nowSeconds() + ttlFor(info),
            });

            try packet.rewriteAddresses(pkt, null, real_ip);
            return .{ .accept = .{ .modified = true, .mark = iface.mark } };
        }

        const reply_key = FlowKey{
            .proto = @intFromEnum(info.protocol),
            .local_ip = info.dst_ip,
            .local_port = info.dst_port,
            .remote_ip = info.src_ip,
            .remote_port = info.src_port,
        };
        if (self.flows.get(reply_key)) |entry| {
            try packet.rewriteAddresses(pkt, entry.fake_ip, null);
            if (packet.tcpIsClosing(info)) _ = self.flows.remove(reply_key);
            return .{ .accept = .{ .modified = true, .mark = 0 } };
        }

        return .{ .accept = .{} };
    }

    fn cleanupExpired(self: *Router) !void {
        const now = timeutil.nowSeconds();
        var doomed: std.ArrayList(FlowKey) = .empty;
        defer doomed.deinit(self.allocator);

        var it = self.flows.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.expires_at <= now) try doomed.append(self.allocator, entry.key_ptr.*);
        }
        for (doomed.items) |key| _ = self.flows.remove(key);
    }
};

fn ttlFor(info: packet.Info) u64 {
    return switch (info.protocol) {
        .tcp => 10 * 60,
        .udp => 2 * 60,
    };
}
