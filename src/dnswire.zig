const std = @import("std");
const ip = @import("ip.zig");
pub const Question = struct { name: []u8, qtype: u16, qclass: u16, question_end: usize };
pub const AAnswer = struct { addr: ip.Ipv4, ttl: u32 };
pub fn u16at(b: []const u8, o: usize) u16 {
    return std.mem.readInt(u16, b[o..][0..2], .big);
}
pub fn u32at(b: []const u8, o: usize) u32 {
    return std.mem.readInt(u32, b[o..][0..4], .big);
}
pub fn put16(b: []u8, o: usize, n: u16) void {
    std.mem.writeInt(u16, b[o..][0..2], n, .big);
}
fn append16(b: *std.ArrayList(u8), a: std.mem.Allocator, n: u16) !void {
    var v: [2]u8 = undefined;
    put16(&v, 0, n);
    try b.appendSlice(a, &v);
}

pub fn name(a: std.mem.Allocator, msg: []const u8, offset: *usize) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    errdefer b.deinit(a);
    var pos = offset.*;
    var jumped = false;
    var wire_len: usize = 1;
    var hops: usize = 0;
    while (true) {
        if (pos >= msg.len or hops > 128) return error.InvalidDnsName;
        const len = msg[pos];
        if ((len & 0xc0) == 0xc0) {
            if (pos + 2 > msg.len) return error.InvalidDnsName;
            const target = u16at(msg, pos) & 0x3fff;
            if (target >= pos) return error.InvalidDnsName;
            if (!jumped) offset.* = pos + 2;
            jumped = true;
            pos = target;
            hops += 1;
            continue;
        }
        if (len > 63 or pos + 1 + len > msg.len) return error.InvalidDnsName;
        pos += 1;
        if (len == 0) {
            if (!jumped) offset.* = pos;
            return b.toOwnedSlice(a);
        }
        wire_len += 1 + @as(usize, len);
        if (wire_len > 255) return error.InvalidDnsName;
        if (b.items.len != 0) try b.append(a, '.');
        for (msg[pos..][0..len]) |c| {
            // Preserve label boundaries even for binary DNS names.
            if ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or c == '-' or c == '_') {
                try b.append(a, std.ascii.toLower(c));
            } else try b.print(a, "\\{d:0>3}", .{c});
        }
        pos += len;
    }
}
pub fn appendName(b: *std.ArrayList(u8), a: std.mem.Allocator, domain: []const u8) !void {
    if (domain.len != 0) {
        var labels = std.mem.splitScalar(u8, domain, '.');
        while (labels.next()) |label| {
            const start = b.items.len;
            try b.append(a, 0);
            var i: usize = 0;
            while (i < label.len) {
                if (label[i] == '\\') {
                    if (i + 4 > label.len) return error.InvalidDnsName;
                    try b.append(a, try std.fmt.parseInt(u8, label[i + 1 .. i + 4], 10));
                    i += 4;
                } else {
                    try b.append(a, label[i]);
                    i += 1;
                }
            }
            const len = b.items.len - start - 1;
            if (len == 0 or len > 63) return error.InvalidDnsName;
            b.items[start] = @intCast(len);
        }
    }
    try b.append(a, 0);
}
pub fn parseQuestion(a: std.mem.Allocator, msg: []const u8) !Question {
    if (msg.len < 12) return error.ShortDnsPacket;
    if (u16at(msg, 4) != 1) return error.UnsupportedQuestionCount;
    var off: usize = 12;
    const n = try name(a, msg, &off);
    errdefer a.free(n);
    if (off + 4 > msg.len) return error.ShortDnsPacket;
    return .{ .name = n, .qtype = u16at(msg, off), .qclass = u16at(msg, off + 2), .question_end = off + 4 };
}
pub fn query(a: std.mem.Allocator, domain: []const u8, id: u16) ![]u8 {
    var b: std.ArrayList(u8) = .empty;
    errdefer b.deinit(a);
    try b.appendSlice(a, &.{ 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0 });
    put16(b.items, 0, id);
    try appendName(&b, a, domain);
    try append16(&b, a, 1);
    try append16(&b, a, 1);
    return b.toOwnedSlice(a);
}
pub fn validateResponse(a: std.mem.Allocator, request: []const u8, reply: []const u8) !void {
    if (request.len < 12 or reply.len < 12) return error.ShortDnsPacket;
    if (u16at(request, 0) != u16at(reply, 0)) return error.DnsIdMismatch;
    if ((u16at(reply, 2) & 0x8000) == 0 or (u16at(reply, 2) & 0x7800) != (u16at(request, 2) & 0x7800)) return error.NotDnsResponse;
    const q = try parseQuestion(a, request);
    defer a.free(q.name);
    const r = try parseQuestion(a, reply);
    defer a.free(r.name);
    if (q.qtype != r.qtype or q.qclass != r.qclass or !std.mem.eql(u8, q.name, r.name)) return error.DnsQuestionMismatch;
}

pub fn response(a: std.mem.Allocator, request: []const u8, rcode: u4, fake: ?ip.Ipv4, ttl: u32, truncated: bool) ![]u8 {
    if (request.len < 12) return error.ShortDnsPacket;
    var b: std.ArrayList(u8) = .empty;
    errdefer b.deinit(a);
    try b.appendSlice(a, &([_]u8{0} ** 12));
    put16(b.items, 0, u16at(request, 0));
    // Never claim AD/authentication for synthetic data; retain RD, CD, opcode.
    put16(b.items, 2, 0x8080 | (u16at(request, 2) & 0x7910) | @as(u16, rcode) | (if (truncated) @as(u16, 0x0200) else 0));
    const q = parseQuestion(a, request) catch return b.toOwnedSlice(a);
    defer a.free(q.name);
    put16(b.items, 4, 1);
    try appendName(&b, a, q.name);
    try append16(&b, a, q.qtype);
    try append16(&b, a, q.qclass);
    if (fake) |addr| {
        put16(b.items, 6, 1);
        try b.appendSlice(a, &.{ 0xc0, 0x0c, 0, 1, 0, 1 });
        var v: [4]u8 = undefined;
        std.mem.writeInt(u32, &v, ttl, .big);
        try b.appendSlice(a, &v);
        try append16(&b, a, 4);
        try b.appendSlice(a, &ip.toNetworkBytes(addr));
    }
    if (ednsInfo(a, request) catch null) |opt| {
        put16(b.items, 10, 1);
        // EDNS version negotiation: BADVERS is extended RCODE 16.
        if (opt.version != 0) put16(b.items, 2, u16at(b.items, 2) & 0xfff0);
        try b.append(a, 0);
        try append16(&b, a, 41);
        try append16(&b, a, 1232);
        var flags: [4]u8 = undefined;
        const value: u32 = (if (opt.version != 0) @as(u32, 1 << 24) else 0) | (if (opt.dnssec_ok) @as(u32, 0x8000) else 0);
        std.mem.writeInt(u32, &flags, value, .big);
        try b.appendSlice(a, &flags);
        try append16(&b, a, 0);
    }
    return b.toOwnedSlice(a);
}

pub const Record = struct { owner: []u8, kind: u16, class: u16, ttl: u32, start: usize, end: usize };
pub fn record(a: std.mem.Allocator, msg: []const u8, off: *usize) !Record {
    const owner = try name(a, msg, off);
    errdefer a.free(owner);
    if (off.* + 10 > msg.len) return error.ShortDnsPacket;
    const start = off.* + 10;
    const end = start + u16at(msg, off.* + 8);
    if (end > msg.len) return error.ShortDnsPacket;
    const r = Record{ .owner = owner, .kind = u16at(msg, off.*), .class = u16at(msg, off.* + 2), .ttl = u32at(msg, off.* + 4), .start = start, .end = end };
    off.* = end;
    return r;
}
pub const AResult = union(enum) { answer: AAnswer, alias: struct { domain: []u8, ttl: u32 } };
pub fn extractA(a: std.mem.Allocator, msg: []const u8) !AResult {
    if (msg.len < 12) return error.ShortDnsPacket;
    if ((u16at(msg, 2) & 0x0200) != 0) return error.TruncatedDnsResponse;
    switch (u16at(msg, 2) & 15) {
        0 => {},
        3 => return error.DnsNxDomain,
        else => return error.DnsErrorResponse,
    }
    const q = try parseQuestion(a, msg);
    defer a.free(q.name);
    var records: std.ArrayList(Record) = .empty;
    defer {
        for (records.items) |r| a.free(r.owner);
        records.deinit(a);
    }
    var off = q.question_end;
    for (0..u16at(msg, 6)) |_| {
        const r = try record(a, msg, &off);
        records.append(a, r) catch |err| {
            a.free(r.owner);
            return err;
        };
    }
    var current = try a.dupe(u8, q.name);
    defer a.free(current);
    var ttl: u32 = std.math.maxInt(u32);
    for (0..16) |hop| {
        for (records.items) |r| {
            if (r.class == 1 and r.kind == 1 and std.mem.eql(u8, r.owner, current)) {
                if (r.end - r.start != 4) return error.InvalidARecord;
                return .{ .answer = .{ .addr = ip.fromNetworkBytes(msg[r.start..r.end]), .ttl = @min(ttl, r.ttl) } };
            }
        }
        var found = false;
        for (records.items) |r| {
            if (r.class == 1 and r.kind == 5 and std.mem.eql(u8, r.owner, current)) {
                var pos = r.start;
                const alias = try name(a, msg, &pos);
                if (pos != r.end) {
                    a.free(alias);
                    return error.InvalidCname;
                }
                a.free(current);
                current = alias;
                ttl = @min(ttl, r.ttl);
                found = true;
                break;
            }
        }
        if (!found) {
            if (hop == 0) return error.NoARecord;
            return .{ .alias = .{ .domain = try a.dupe(u8, current), .ttl = ttl } };
        }
    }
    return error.CnameLoop;
}
pub const Edns = struct { size: u16, version: u8, dnssec_ok: bool };
pub fn ednsInfo(a: std.mem.Allocator, msg: []const u8) !?Edns {
    const q = try parseQuestion(a, msg);
    defer a.free(q.name);
    var off = q.question_end;
    const count = @as(usize, u16at(msg, 6)) + u16at(msg, 8) + u16at(msg, 10);
    var opt: ?Edns = null;
    for (0..count) |i| {
        const r = try record(a, msg, &off);
        defer a.free(r.owner);
        if (r.kind == 41) {
            if (opt != null or r.owner.len != 0 or i < @as(usize, u16at(msg, 6)) + u16at(msg, 8)) return error.InvalidEdns;
            opt = .{ .size = r.class, .version = @truncate(r.ttl >> 16), .dnssec_ok = (r.ttl & 0x8000) != 0 };
        }
    }
    if (off != msg.len) return error.InvalidDnsLength;
    return opt;
}
pub fn udpLimit(a: std.mem.Allocator, msg: []const u8) !usize {
    const opt = (try ednsInfo(a, msg)) orelse return 512;
    return @max(512, @min(opt.size, 1232));
}

test "root names and binary label boundaries" {
    const a = std.testing.allocator;
    const root = try query(a, "", 1);
    defer a.free(root);
    const q = try parseQuestion(a, root);
    defer a.free(q.name);
    try std.testing.expectEqualStrings("", q.name);
    var off: usize = 0;
    const n = try name(a, &.{ 3, 'a', '.', 'b', 0 }, &off);
    defer a.free(n);
    try std.testing.expectEqualStrings("a\\046b", n);
}
test "reject mismatched question and unrelated A owner" {
    const a = std.testing.allocator;
    const q = try query(a, "example.com", 123);
    defer a.free(q);
    const other = try query(a, "attacker.com", 123);
    defer a.free(other);
    const r = try response(a, other, 0, 0x01010101, 60, false);
    defer a.free(r);
    try std.testing.expectError(error.DnsQuestionMismatch, validateResponse(a, q, r));
    // Change the answer owner to the root, leaving the legitimate question.
    const valid = try response(a, q, 0, 0x01010101, 60, false);
    defer a.free(valid);
    valid[q.len] = 0xc0;
    valid[q.len + 1] = @intCast(q.len - 5); // terminating root label
    try std.testing.expectError(error.NoARecord, extractA(a, valid));
}
test "CNAME owner chain, TTL, compression loops and error responses" {
    const a = std.testing.allocator;
    const q = try query(a, "example.com", 7);
    defer a.free(q);
    const nx = try response(a, q, 3, null, 0, false);
    defer a.free(nx);
    try std.testing.expectError(error.DnsNxDomain, extractA(a, nx));
    const tc = try response(a, q, 0, null, 0, true);
    defer a.free(tc);
    try std.testing.expectError(error.TruncatedDnsResponse, extractA(a, tc));
    var pos: usize = 0;
    try std.testing.expectError(error.InvalidDnsName, name(a, &.{ 0xc0, 0 }, &pos));
}
