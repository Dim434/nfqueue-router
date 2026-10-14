const std = @import("std");
const linux = std.os.linux;
const nat = @import("nat.zig");

pub const Options = struct {
    queue_num: u16 = 100,
    copy_range: u32 = 0xffff,
};

const NFNL_SUBSYS_QUEUE = 3;
const NFQNL_MSG_PACKET = 0;
const NFQNL_MSG_VERDICT = 1;
const NFQNL_MSG_CONFIG = 2;

const NFQA_PACKET_HDR = 1;
const NFQA_VERDICT_HDR = 2;
const NFQA_MARK = 3;
const NFQA_PAYLOAD = 10;

const NFQA_CFG_CMD = 1;
const NFQA_CFG_PARAMS = 2;

const NFQNL_CFG_CMD_BIND = 1;
const NFQNL_CFG_CMD_PF_BIND = 3;
const NFQNL_CFG_CMD_PF_UNBIND = 4;

const NFQNL_COPY_PACKET = 2;

const NF_DROP = 0;
const NF_ACCEPT = 1;

pub fn run(router: *nat.Router, opts: Options) !void {
    const fd = try openNetfilterSocket();
    defer _ = linux.close(fd);

    var seq: u32 = 1;
    try configureQueue(fd, opts.queue_num, opts.copy_range, &seq);

    std.debug.print("nfqueue-router: listening on NFQUEUE {}\n", .{opts.queue_num});

    var recv_buf: [128 * 1024]u8 align(4) = undefined;
    while (true) {
        const rc = linux.recvfrom(fd, recv_buf[0..].ptr, recv_buf.len, 0, null, null);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            .NOBUFS => {
                // Kernel dropped one or more queued packets because userspace was
                // temporarily behind. Keep the worker alive; TCP/QUIC can retry.
                std.debug.print("nfqueue warning: kernel reported ENOBUFS, continuing\n", .{});
                continue;
            },
            else => |e| return nfqueueError(e),
        }
        const n: usize = @intCast(rc);
        var off: usize = 0;
        while (off + 16 <= n) {
            const nl_len = readNative(u32, recv_buf[off..], 0);
            if (nl_len < 16 or off + nl_len > n) break;
            try handleMessage(fd, opts.queue_num, router, recv_buf[off .. off + nl_len], &seq);
            off += align4(nl_len);
        }
    }
}

fn openNetfilterSocket() !i32 {
    const rc = linux.socket(linux.AF.NETLINK, linux.SOCK.RAW | linux.SOCK.CLOEXEC, linux.NETLINK.NETFILTER);
    switch (std.posix.errno(rc)) {
        .SUCCESS => {},
        else => |e| return nfqueueError(e),
    }
    const fd: i32 = @intCast(rc);
    setReceiveBuffer(fd);
    var addr = linux.sockaddr.nl{ .pid = 0, .groups = 0 };
    const bind_rc = linux.bind(fd, @ptrCast(&addr), @sizeOf(@TypeOf(addr)));
    switch (std.posix.errno(bind_rc)) {
        .SUCCESS => {},
        else => |e| return nfqueueError(e),
    }
    return fd;
}

fn setReceiveBuffer(fd: i32) void {
    var size: i32 = 16 * 1024 * 1024;
    const bytes = std.mem.asBytes(&size);
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVBUF, bytes.ptr, @intCast(bytes.len));
}

fn configureQueue(fd: i32, queue_num: u16, copy_range: u32, seq: *u32) !void {
    // Bind IPv4 packets to nfnetlink_queue. The queue-specific bind is kept for
    // kernels/libnetfilter_queue compatibility.
    try sendConfigCmd(fd, seq.*, 0, linux.AF.INET, NFQNL_CFG_CMD_PF_UNBIND);
    seq.* += 1;
    try sendConfigCmd(fd, seq.*, 0, linux.AF.INET, NFQNL_CFG_CMD_PF_BIND);
    seq.* += 1;
    try sendConfigCmd(fd, seq.*, queue_num, linux.AF.UNSPEC, NFQNL_CFG_CMD_BIND);
    seq.* += 1;
    try sendCopyMode(fd, seq.*, queue_num, copy_range);
    seq.* += 1;
}

fn handleMessage(fd: i32, queue_num: u16, router: *nat.Router, msg: []u8, seq: *u32) !void {
    const typ = readNative(u16, msg, 4);
    if (typ == @intFromEnum(linux.NetlinkMessageType.ERROR)) {
        if (msg.len >= 20) {
            const errno_i = @as(i32, @bitCast(readNative(u32, msg, 16)));
            if (errno_i != 0) std.debug.print("netlink error {}\n", .{errno_i});
        }
        return;
    }
    if (typ != nfqMsgType(NFQNL_MSG_PACKET)) return;
    if (msg.len < 20) return;

    var attrs_off: usize = 20; // nlmsghdr (16) + nfgenmsg (4)
    var packet_id: ?u32 = null;
    var payload: ?[]u8 = null;

    while (attrs_off + 4 <= msg.len) {
        const attr_len = readNative(u16, msg, attrs_off);
        const attr_type = readNative(u16, msg, attrs_off + 2) & 0x3fff;
        if (attr_len < 4 or attrs_off + attr_len > msg.len) break;
        const attr_payload = msg[attrs_off + 4 .. attrs_off + attr_len];
        switch (attr_type) {
            NFQA_PACKET_HDR => {
                if (attr_payload.len >= 4) packet_id = readBig(u32, attr_payload, 0);
            },
            NFQA_PAYLOAD => payload = attr_payload,
            else => {},
        }
        attrs_off += align4(attr_len);
    }

    const id = packet_id orelse return;
    const pkt = payload orelse {
        try sendVerdict(fd, queue_num, id, .{ .accept = .{} }, null, seq);
        return;
    };

    const decision = router.process(pkt) catch |err| blk: {
        std.debug.print("packet processing failed: {s}\n", .{@errorName(err)});
        break :blk nat.Decision.drop;
    };
    try sendVerdict(fd, queue_num, id, decision, pkt, seq);
}

fn sendConfigCmd(fd: i32, seq: u32, queue_num: u16, pf: u32, command: u8) !void {
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(std.heap.smp_allocator);
    const a = std.heap.smp_allocator;
    const start = try beginNfqMessage(&msg, a, NFQNL_MSG_CONFIG, linux.NLM_F_REQUEST, seq, queue_num, @intCast(pf));
    var payload = [_]u8{ command, 0, 0, 0 };
    std.mem.writeInt(u16, payload[2..][0..2], @intCast(pf), .big);
    try addAttr(&msg, a, NFQA_CFG_CMD, &payload);
    finishNfqMessage(&msg, start);
    try sendNetlink(fd, msg.items);
}

fn sendCopyMode(fd: i32, seq: u32, queue_num: u16, copy_range: u32) !void {
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(std.heap.smp_allocator);
    const a = std.heap.smp_allocator;
    const start = try beginNfqMessage(&msg, a, NFQNL_MSG_CONFIG, linux.NLM_F_REQUEST, seq, queue_num, linux.AF.UNSPEC);
    var payload: [5]u8 = undefined;
    std.mem.writeInt(u32, payload[0..][0..4], copy_range, .big);
    payload[4] = NFQNL_COPY_PACKET;
    try addAttr(&msg, a, NFQA_CFG_PARAMS, &payload);
    finishNfqMessage(&msg, start);
    try sendNetlink(fd, msg.items);
}

fn sendVerdict(fd: i32, queue_num: u16, id: u32, decision: nat.Decision, modified_payload: ?[]const u8, seq: *u32) !void {
    var msg: std.ArrayList(u8) = .empty;
    defer msg.deinit(std.heap.smp_allocator);
    const a = std.heap.smp_allocator;
    const start = try beginNfqMessage(&msg, a, NFQNL_MSG_VERDICT, linux.NLM_F_REQUEST, seq.*, queue_num, linux.AF.UNSPEC);
    seq.* += 1;

    var verdict_payload: [8]u8 = undefined;
    const verdict: u32 = switch (decision) {
        .drop => NF_DROP,
        .accept => NF_ACCEPT,
    };
    std.mem.writeInt(u32, verdict_payload[0..][0..4], verdict, .big);
    std.mem.writeInt(u32, verdict_payload[4..][0..4], id, .big);
    try addAttr(&msg, a, NFQA_VERDICT_HDR, &verdict_payload);

    switch (decision) {
        .drop => {},
        .accept => |accept| {
            if (accept.mark != 0) {
                var mark_payload: [4]u8 = undefined;
                std.mem.writeInt(u32, &mark_payload, accept.mark, .big);
                try addAttr(&msg, a, NFQA_MARK, &mark_payload);
            }
            if (accept.modified) {
                if (modified_payload) |payload| try addAttr(&msg, a, NFQA_PAYLOAD, payload);
            }
        },
    }

    finishNfqMessage(&msg, start);
    try sendNetlink(fd, msg.items);
}

fn beginNfqMessage(
    msg: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    kind: u8,
    flags: u16,
    seq: u32,
    queue_num: u16,
    family: u8,
) !usize {
    const start = msg.items.len;
    try appendNative(u32, msg, allocator, 0); // nlmsg_len filled later
    try appendNative(u16, msg, allocator, nfqMsgType(kind));
    try appendNative(u16, msg, allocator, flags);
    try appendNative(u32, msg, allocator, seq);
    try appendNative(u32, msg, allocator, 0); // pid
    try msg.append(allocator, family);
    try msg.append(allocator, 0); // nfnetlink v0
    try appendBig(u16, msg, allocator, queue_num);
    return start;
}

fn finishNfqMessage(msg: *std.ArrayList(u8), start: usize) void {
    std.mem.writeInt(u32, msg.items[start..][0..4], @intCast(msg.items.len - start), .native);
}

fn addAttr(msg: *std.ArrayList(u8), allocator: std.mem.Allocator, attr_type: u16, payload: []const u8) !void {
    const len: u16 = @intCast(4 + payload.len);
    try appendNative(u16, msg, allocator, len);
    try appendNative(u16, msg, allocator, attr_type);
    try msg.appendSlice(allocator, payload);
    while ((msg.items.len & 3) != 0) try msg.append(allocator, 0);
}

fn sendNetlink(fd: i32, bytes: []const u8) !void {
    var kernel = linux.sockaddr.nl{ .pid = 0, .groups = 0 };
    const rc = linux.sendto(fd, bytes.ptr, bytes.len, 0, @ptrCast(&kernel), @sizeOf(@TypeOf(kernel)));
    switch (std.posix.errno(rc)) {
        .SUCCESS => {},
        else => |e| return nfqueueError(e),
    }
}

fn appendNative(comptime T: type, msg: *std.ArrayList(u8), allocator: std.mem.Allocator, value: T) !void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .native);
    try msg.appendSlice(allocator, &bytes);
}

fn appendBig(comptime T: type, msg: *std.ArrayList(u8), allocator: std.mem.Allocator, value: T) !void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .big);
    try msg.appendSlice(allocator, &bytes);
}

fn nfqMsgType(kind: u8) u16 {
    return (@as(u16, NFNL_SUBSYS_QUEUE) << 8) | kind;
}

fn align4(v: anytype) usize {
    return (@as(usize, @intCast(v)) + 3) & ~@as(usize, 3);
}

fn readNative(comptime T: type, buf: []const u8, off: usize) T {
    return std.mem.readInt(T, buf[off..][0..@sizeOf(T)], .native);
}

fn readBig(comptime T: type, buf: []const u8, off: usize) T {
    return std.mem.readInt(T, buf[off..][0..@sizeOf(T)], .big);
}

fn nfqueueError(e: std.posix.E) anyerror {
    std.debug.print("nfqueue netlink error: {s}\n", .{@tagName(e)});
    return error.NfqueueNetlinkError;
}
