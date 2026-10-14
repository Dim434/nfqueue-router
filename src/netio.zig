const std = @import("std");
const builtin = @import("builtin");
const ip = @import("ip.zig");
const sys = std.posix.system;
pub const fd_t = std.posix.fd_t;

pub fn randomId() !u16 {
    var bytes: [2]u8 = undefined;
    if (comptime builtin.os.tag == .linux) {
        var off: usize = 0;
        while (off < bytes.len) {
            const rc = std.os.linux.getrandom(bytes[off..].ptr, bytes.len - off, 0);
            switch (std.posix.errno(rc)) {
                .SUCCESS => off += rc,
                .INTR => continue,
                else => return error.EntropyUnavailable,
            }
        }
    } else std.c.arc4random_buf(&bytes, bytes.len);
    return std.mem.readInt(u16, &bytes, .big);
}

pub fn address(value: ip.IpPort) std.posix.sockaddr.in {
    var sa: std.posix.sockaddr.in = std.mem.zeroes(std.posix.sockaddr.in);
    if (@hasField(std.posix.sockaddr.in, "len")) sa.len = @sizeOf(std.posix.sockaddr.in);
    sa.family = std.posix.AF.INET;
    sa.port = std.mem.nativeToBig(u16, value.port);
    sa.addr = std.mem.nativeToBig(u32, value.ip);
    return sa;
}
pub fn close(fd: fd_t) void {
    _ = sys.close(fd);
}
pub fn nonblocking(fd: fd_t) !void {
    const flags: u32 = @bitCast(std.posix.O{ .NONBLOCK = true });
    if (std.posix.errno(sys.fcntl(fd, std.posix.F.SETFL, @as(usize, flags))) != .SUCCESS) return error.SocketFlagsFailed;
    if (std.posix.errno(sys.fcntl(fd, std.posix.F.SETFD, @as(usize, 1))) != .SUCCESS) return error.SocketFlagsFailed;
}
pub fn socket(tcp: bool) !fd_t {
    const kind: u32 = if (tcp) std.posix.SOCK.STREAM else std.posix.SOCK.DGRAM;
    const rc = sys.socket(std.posix.AF.INET, kind, 0);
    if (std.posix.errno(rc) != .SUCCESS) return error.SocketOpenFailed;
    const fd: fd_t = @intCast(rc);
    errdefer close(fd);
    try nonblocking(fd);
    if (comptime builtin.os.tag != .linux) {
        const one: c_int = 1;
        _ = sys.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.NOSIGPIPE, @ptrCast(&one), @sizeOf(c_int));
    }
    return fd;
}
pub fn bind(fd: fd_t, value: ip.IpPort, tcp: bool) !void {
    var sa = address(value);
    if (tcp) {
        const one: c_int = 1;
        _ = sys.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.REUSEADDR, @ptrCast(&one), @sizeOf(c_int));
    }
    if (std.posix.errno(sys.bind(fd, @ptrCast(&sa), @sizeOf(@TypeOf(sa)))) != .SUCCESS) return error.SocketBindFailed;
}
// Absolute monotonic deadlines prevent a stream of junk/partial responses from
// keeping a request or TCP client alive forever.
pub fn nowMs() i64 {
    if (comptime builtin.os.tag == .linux) {
        var ts: std.os.linux.timespec = undefined;
        _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
        return ts.sec * 1000 + @divTrunc(ts.nsec, 1_000_000);
    } else {
        var ts: std.c.timespec = undefined;
        _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
        return ts.sec * 1000 + @divTrunc(ts.nsec, 1_000_000);
    }
}
pub fn wait(fd: fd_t, write: bool, deadline: i64) !void {
    while (true) {
        const left = deadline - nowMs();
        if (left <= 0) return error.DnsTimeout;
        var pfd = [_]std.posix.pollfd{.{ .fd = fd, .events = if (write) std.posix.POLL.OUT else std.posix.POLL.IN, .revents = 0 }};
        const rc = sys.poll(&pfd, 1, @intCast(@min(left, std.math.maxInt(i32))));
        switch (std.posix.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.SocketPollFailed,
        }
        if (rc == 0) return error.DnsTimeout;
        return;
    }
}
pub fn connect(fd: fd_t, remote: ip.IpPort, deadline: i64) !void {
    var sa = address(remote);
    const rc = sys.connect(fd, @ptrCast(&sa), @sizeOf(@TypeOf(sa)));
    switch (std.posix.errno(rc)) {
        .SUCCESS => return,
        .INPROGRESS, .AGAIN => {},
        else => return error.SocketConnectFailed,
    }
    try wait(fd, true, deadline);
    var result: c_int = 0;
    var len: std.posix.socklen_t = @sizeOf(c_int);
    const check = sys.getsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.ERROR, @ptrCast(&result), &len);
    if (std.posix.errno(check) != .SUCCESS or result != 0) return error.SocketConnectFailed;
}
pub fn send(fd: fd_t, data: []const u8, deadline: i64) !void {
    var off: usize = 0;
    while (off < data.len) {
        try wait(fd, true, deadline);
        const flags = if (comptime builtin.os.tag == .linux) std.posix.MSG.NOSIGNAL else 0;
        const rc = sys.sendto(fd, data[off..].ptr, data.len - off, flags, null, 0);
        switch (std.posix.errno(rc)) {
            .SUCCESS => {},
            .INTR, .AGAIN => continue,
            else => return error.SocketSendFailed,
        }
        if (rc == 0) return error.SocketClosed;
        off += @intCast(rc);
    }
}
pub fn recv(fd: fd_t, buf: []u8, deadline: i64) !usize {
    while (true) {
        try wait(fd, false, deadline);
        const rc = sys.recvfrom(fd, buf.ptr, buf.len, 0, null, null);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR, .AGAIN => continue,
            else => return error.SocketRecvFailed,
        }
    }
}
pub fn readAll(fd: fd_t, data: []u8, deadline: i64) !void {
    var off: usize = 0;
    while (off < data.len) {
        const n = try recv(fd, data[off..], deadline);
        if (n == 0) return error.SocketClosed;
        off += n;
    }
}
pub fn readFrame(a: std.mem.Allocator, fd: fd_t, deadline: i64) ![]u8 {
    var len: [2]u8 = undefined;
    try readAll(fd, &len, deadline);
    const size = std.mem.readInt(u16, &len, .big);
    if (size < 12) return error.ShortDnsPacket;
    const buf = try a.alloc(u8, size);
    errdefer a.free(buf);
    try readAll(fd, buf, deadline);
    return buf;
}
pub fn writeFrame(fd: fd_t, data: []const u8, deadline: i64) !void {
    var len: [2]u8 = undefined;
    std.mem.writeInt(u16, &len, @intCast(data.len), .big);
    try send(fd, &len, deadline);
    try send(fd, data, deadline);
}
