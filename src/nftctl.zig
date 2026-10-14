const std = @import("std");
const ip = @import("ip.zig");

pub const Mapping = struct { real: ip.Ipv4, mark: u32 };
pub const Record = struct { fake: ip.Ipv4, real: ip.Ipv4, mark: u32 };

pub const Controller = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    table_name: []const u8 = "nfqueue_router",
    batch_path: []const u8 = "/run/nfqueue-router/update.nft",
    executable: []const u8 = "/usr/sbin/nft",
    mutex: std.atomic.Mutex = .unlocked,
    mapped: std.AutoHashMap(ip.Ipv4, Mapping),

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Controller {
        return .{ .allocator = allocator, .io = io, .mapped = std.AutoHashMap(ip.Ipv4, Mapping).init(allocator) };
    }
    pub fn deinit(self: *Controller) void {
        self.mapped.deinit();
    }

    /// All delete/add operations are in one nft netlink transaction. Failure
    /// leaves BOTH kernel maps and the userspace cache unchanged.
    pub fn ensureMapping(self: *Controller, fake: ip.Ipv4, real: ip.Ipv4, mark: u32) !void {
        self.lock();
        defer self.mutex.unlock();
        const old = self.mapped.get(fake);
        if (old) |m| if (m.real == real and m.mark == mark) return;
        try self.mapped.ensureUnusedCapacity(1);
        var batch: std.ArrayList(u8) = .empty;
        defer batch.deinit(self.allocator);
        try appendUpdate(&batch, self.allocator, self.table_name, .{ .fake = fake, .real = real, .mark = mark }, old != null);
        try self.runBatch(batch.items);
        self.mapped.putAssumeCapacity(fake, .{ .real = real, .mark = mark });
    }

    /// Reconcile on every startup, even if the previous process died after a
    /// successful kernel transaction but before updating its in-memory cache.
    pub fn restore(self: *Controller, records: []const Record) !void {
        self.lock();
        defer self.mutex.unlock();
        var next = std.AutoHashMap(ip.Ipv4, Mapping).init(self.allocator);
        errdefer next.deinit();
        var batch: std.ArrayList(u8) = .empty;
        defer batch.deinit(self.allocator);
        try batch.print(self.allocator, "flush map inet {s} fake_to_real\nflush map inet {s} fake_to_mark\n", .{ self.table_name, self.table_name });
        for (records) |r| {
            try appendUpdate(&batch, self.allocator, self.table_name, r, false);
            try next.put(r.fake, .{ .real = r.real, .mark = r.mark });
        }
        try self.runBatch(batch.items);
        self.mapped.deinit();
        self.mapped = next;
    }

    fn runBatch(self: *Controller, batch: []const u8) !void {
        var file = try std.Io.Dir.cwd().createFileAtomic(self.io, self.batch_path, .{ .replace = true, .make_path = true });
        defer file.deinit(self.io);
        try file.file.writeStreamingAll(self.io, batch);
        try file.replace(self.io);
        defer std.Io.Dir.cwd().deleteFile(self.io, self.batch_path) catch {};
        const result = try std.process.run(self.allocator, self.io, .{
            .argv = &.{ self.executable, "-f", self.batch_path },
            .stdout_limit = .limited(16 * 1024),
            .stderr_limit = .limited(16 * 1024),
        });
        defer self.allocator.free(result.stdout);
        defer self.allocator.free(result.stderr);
        const ok = switch (result.term) {
            .exited => |code| code == 0,
            else => false,
        };
        if (!ok) {
            std.debug.print("nft transaction failed: {s}\n", .{result.stderr});
            return error.NftCommandFailed;
        }
    }
    fn lock(self: *Controller) void {
        while (!self.mutex.tryLock()) std.Thread.yield() catch {};
    }
};

fn appendUpdate(batch: *std.ArrayList(u8), a: std.mem.Allocator, table: []const u8, r: Record, exists: bool) !void {
    var f: [16]u8 = undefined;
    var v: [16]u8 = undefined;
    const fake = ip.formatIpv4(&f, r.fake);
    if (exists) try batch.print(a, "delete element inet {s} fake_to_real {{ {s} }}\ndelete element inet {s} fake_to_mark {{ {s} }}\n", .{ table, fake, table, fake });
    try batch.print(a, "add element inet {s} fake_to_real {{ {s} : {s} }}\nadd element inet {s} fake_to_mark {{ {s} : 0x{x} }}\n", .{ table, fake, ip.formatIpv4(&v, r.real), table, fake, r.mark });
}

test "nft update changes mark and destination together" {
    var b: std.ArrayList(u8) = .empty;
    defer b.deinit(std.testing.allocator);
    try appendUpdate(&b, std.testing.allocator, "nfqueue_router", .{ .fake = 0xc6120001, .real = 0x01010101, .mark = 123 }, true);
    try std.testing.expect(std.mem.indexOf(u8, b.items, "delete element inet nfqueue_router fake_to_mark") != null);
    try std.testing.expect(std.mem.indexOf(u8, b.items, "198.18.0.1 : 0x7b") != null);
}
