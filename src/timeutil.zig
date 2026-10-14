const std = @import("std");
const builtin = @import("builtin");

pub fn nowSeconds() u64 {
    return switch (comptime builtin.os.tag) {
        .linux => linuxNowSeconds(),
        else => cNowSeconds(),
    };
}

fn linuxNowSeconds() u64 {
    const linux = std.os.linux;
    var ts: linux.timespec = undefined;
    const rc = linux.clock_gettime(.MONOTONIC, &ts);
    if (std.posix.errno(rc) == .SUCCESS) return @intCast(ts.sec);
    return 0;
}

fn cNowSeconds() u64 {
    var tv: std.c.timeval = undefined;
    if (std.c.gettimeofday(&tv, null) == 0) return @intCast(tv.sec);
    return 0;
}
