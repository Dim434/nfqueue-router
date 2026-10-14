const nat = @import("nat.zig");

pub const Options = struct {
    queue_num: u16 = 100,
    copy_range: u32 = 0xffff,
};

pub fn run(_: *nat.Router, _: Options) !void {
    return error.UnsupportedPlatform;
}
