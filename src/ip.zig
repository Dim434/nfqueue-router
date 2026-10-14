const std = @import("std");

pub const Ipv4 = u32; // host byte order, e.g. 0x7f000001 == 127.0.0.1

pub const IpPort = struct {
    ip: Ipv4,
    port: u16,
};

pub const Cidr = struct {
    base: Ipv4,
    prefix: u8,

    pub fn defaultFake() Cidr {
        return .{ .base = 0x7f800000, .prefix = 9 }; // 127.128.0.0/9
    }

    pub fn mask(self: Cidr) Ipv4 {
        if (self.prefix == 0) return 0;
        return @as(Ipv4, 0xffffffff) << @intCast(32 - self.prefix);
    }

    pub fn size(self: Cidr) u64 {
        return @as(u64, 1) << @intCast(32 - self.prefix);
    }

    pub fn contains(self: Cidr, addr: Ipv4) bool {
        return (addr & self.mask()) == (self.base & self.mask());
    }

    pub fn nth(self: Cidr, n: u64) !Ipv4 {
        if (n >= self.size()) return error.AddressOutOfRange;
        return (self.base & self.mask()) | @as(Ipv4, @intCast(n));
    }
};

pub fn parseCidr(text: []const u8) !Cidr {
    const slash = std.mem.findScalar(u8, text, '/') orelse return error.InvalidCidr;
    const ip_part = std.mem.trim(u8, text[0..slash], " \t\r\n");
    const prefix_part = std.mem.trim(u8, text[slash + 1 ..], " \t\r\n");
    const prefix = std.fmt.parseInt(u8, prefix_part, 10) catch return error.InvalidCidr;
    if (prefix > 32) return error.InvalidCidr;
    const base = try parseIpv4(ip_part);
    const cidr = Cidr{ .base = base, .prefix = prefix };
    return .{ .base = base & cidr.mask(), .prefix = prefix };
}

pub fn parseIpPort(text: []const u8, default_port: u16) !IpPort {
    const trimmed = std.mem.trim(u8, text, " \t\r\n");
    if (std.mem.lastIndexOfScalar(u8, trimmed, ':')) |colon| {
        const host = trimmed[0..colon];
        const port_text = trimmed[colon + 1 ..];
        if (host.len == 0 or port_text.len == 0) return error.InvalidIpPort;
        return .{
            .ip = try parseIpv4(host),
            .port = std.fmt.parseInt(u16, port_text, 10) catch return error.InvalidIpPort,
        };
    }
    return .{ .ip = try parseIpv4(trimmed), .port = default_port };
}

pub fn parseIpv4(text: []const u8) !Ipv4 {
    var parts = std.mem.splitScalar(u8, text, '.');
    var out: Ipv4 = 0;
    var count: usize = 0;
    while (parts.next()) |part| {
        if (part.len == 0) return error.InvalidIpv4;
        if (count == 4) return error.InvalidIpv4;
        const octet = std.fmt.parseInt(u8, part, 10) catch return error.InvalidIpv4;
        out = (out << 8) | octet;
        count += 1;
    }
    if (count != 4) return error.InvalidIpv4;
    return out;
}

pub fn formatIpv4(buf: []u8, addr: Ipv4) []const u8 {
    return std.fmt.bufPrint(buf, "{}.{}.{}.{}", .{
        (addr >> 24) & 0xff,
        (addr >> 16) & 0xff,
        (addr >> 8) & 0xff,
        addr & 0xff,
    }) catch unreachable;
}

pub fn writeIpv4(w: *std.Io.Writer, addr: Ipv4) !void {
    var buf: [16]u8 = undefined;
    try w.writeAll(formatIpv4(&buf, addr));
}

pub fn toNetworkBytes(addr: Ipv4) [4]u8 {
    return .{
        @intCast((addr >> 24) & 0xff),
        @intCast((addr >> 16) & 0xff),
        @intCast((addr >> 8) & 0xff),
        @intCast(addr & 0xff),
    };
}

pub fn fromNetworkBytes(bytes: []const u8) Ipv4 {
    std.debug.assert(bytes.len >= 4);
    return (@as(Ipv4, bytes[0]) << 24) |
        (@as(Ipv4, bytes[1]) << 16) |
        (@as(Ipv4, bytes[2]) << 8) |
        @as(Ipv4, bytes[3]);
}

test "IPv4 and CIDR parsing" {
    try std.testing.expectEqual(@as(Ipv4, 0x7f000001), try parseIpv4("127.0.0.1"));
    const c = try parseCidr("127.128.0.0/9");
    try std.testing.expect(c.contains(try parseIpv4("127.200.1.2")));
    try std.testing.expect(!c.contains(try parseIpv4("127.1.1.1")));
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("1.2.3.4", formatIpv4(&buf, 0x01020304));
}
