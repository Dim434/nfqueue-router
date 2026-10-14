const std = @import("std");
const ip = @import("ip.zig");

pub const Protocol = enum(u8) {
    tcp = 6,
    udp = 17,
};

pub const Info = struct {
    protocol: Protocol,
    src_ip: ip.Ipv4,
    dst_ip: ip.Ipv4,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8 = 0,
    ip_header_len: usize,
    total_len: usize,
};

pub fn parseIpv4Transport(pkt: []const u8) !Info {
    if (pkt.len < 20) return error.ShortIpv4Packet;
    if ((pkt[0] >> 4) != 4) return error.NotIpv4;
    const ihl = @as(usize, pkt[0] & 0x0f) * 4;
    if (ihl < 20 or pkt.len < ihl) return error.InvalidIpv4Header;
    const total_len = read16(pkt, 2);
    if (total_len < ihl or total_len > pkt.len) return error.InvalidIpv4Length;

    const frag = read16(pkt, 6);
    if ((frag & 0x3fff) != 0) return error.FragmentedPacketUnsupported;

    const proto_num = pkt[9];
    const proto: Protocol = switch (proto_num) {
        6 => .tcp,
        17 => .udp,
        else => return error.NotTcpUdp,
    };
    if (total_len < ihl + 8) return error.ShortTransportHeader;

    const src_port = read16(pkt, ihl);
    const dst_port = read16(pkt, ihl + 2);
    var flags: u8 = 0;
    if (proto == .tcp) {
        if (total_len < ihl + 20) return error.ShortTransportHeader;
        flags = pkt[ihl + 13];
    }

    return .{
        .protocol = proto,
        .src_ip = read32(pkt, 12),
        .dst_ip = read32(pkt, 16),
        .src_port = src_port,
        .dst_port = dst_port,
        .tcp_flags = flags,
        .ip_header_len = ihl,
        .total_len = total_len,
    };
}

pub fn rewriteAddresses(pkt: []u8, new_src: ?ip.Ipv4, new_dst: ?ip.Ipv4) !void {
    const info = try parseIpv4Transport(pkt);
    if (new_src) |addr| write32(pkt, 12, addr);
    if (new_dst) |addr| write32(pkt, 16, addr);
    recomputeIpv4Checksum(pkt[0..info.ip_header_len]);
    try recomputeTransportChecksum(pkt[0..info.total_len], info.ip_header_len, info.protocol);
}

pub fn tcpIsClosing(info: Info) bool {
    return info.protocol == .tcp and (info.tcp_flags & 0x05) != 0; // FIN or RST
}

fn recomputeIpv4Checksum(header: []u8) void {
    write16(header, 10, 0);
    write16(header, 10, checksum(header));
}

fn recomputeTransportChecksum(pkt: []u8, l4_off: usize, proto: Protocol) !void {
    const segment = pkt[l4_off..];
    const checksum_off = switch (proto) {
        .tcp => l4_off + 16,
        .udp => l4_off + 6,
    };
    if (checksum_off + 2 > pkt.len) return error.ShortTransportHeader;

    const old = read16(pkt, checksum_off);
    if (proto == .udp and old == 0) return; // IPv4 UDP checksum is optional.

    write16(pkt, checksum_off, 0);

    var sum: u32 = 0;
    const src = read32(pkt, 12);
    const dst = read32(pkt, 16);
    sum += (src >> 16) + (src & 0xffff);
    sum += (dst >> 16) + (dst & 0xffff);
    sum += @intFromEnum(proto);
    sum += @intCast(segment.len);
    sum += onesComplementSum(segment);

    var csum = finishChecksum(sum);
    if (proto == .udp and csum == 0) csum = 0xffff;
    write16(pkt, checksum_off, csum);
}

fn checksum(bytes: []const u8) u16 {
    return finishChecksum(onesComplementSum(bytes));
}

fn onesComplementSum(bytes: []const u8) u32 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i + 1 < bytes.len) : (i += 2) {
        sum += (@as(u32, bytes[i]) << 8) | bytes[i + 1];
    }
    if (i < bytes.len) sum += @as(u32, bytes[i]) << 8;
    return sum;
}

fn finishChecksum(sum_in: u32) u16 {
    var sum = sum_in;
    while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
    return @as(u16, @truncate(~sum));
}

fn read16(buf: []const u8, off: usize) u16 {
    return (@as(u16, buf[off]) << 8) | buf[off + 1];
}

fn write16(buf: []u8, off: usize, value: u16) void {
    buf[off] = @intCast((value >> 8) & 0xff);
    buf[off + 1] = @intCast(value & 0xff);
}

fn read32(buf: []const u8, off: usize) u32 {
    return (@as(u32, buf[off]) << 24) |
        (@as(u32, buf[off + 1]) << 16) |
        (@as(u32, buf[off + 2]) << 8) |
        buf[off + 3];
}

fn write32(buf: []u8, off: usize, value: u32) void {
    buf[off] = @intCast((value >> 24) & 0xff);
    buf[off + 1] = @intCast((value >> 16) & 0xff);
    buf[off + 2] = @intCast((value >> 8) & 0xff);
    buf[off + 3] = @intCast(value & 0xff);
}

test "parse and rewrite UDP IPv4" {
    var pkt = [_]u8{
        0x45, 0,    0, 28, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 127, 128, 0, 1,
        0x12, 0x34, 0, 53, 0, 8, 0, 0,
    };
    recomputeIpv4Checksum(pkt[0..20]);
    const info = try parseIpv4Transport(&pkt);
    try std.testing.expectEqual(@as(ip.Ipv4, 0x7f800001), info.dst_ip);
    try rewriteAddresses(&pkt, null, 0x01020304);
    const info2 = try parseIpv4Transport(&pkt);
    try std.testing.expectEqual(@as(ip.Ipv4, 0x01020304), info2.dst_ip);
}
