const std = @import("std");
const builtin = @import("builtin");

const ip = @import("ip.zig");
const config = @import("config.zig");
const dns = @import("dns.zig");
const nat = @import("nat.zig");
const nfqueue = if (builtin.os.tag == .linux) @import("nfqueue_linux.zig") else @import("nfqueue_stub.zig");
const nftctl = @import("nftctl.zig");
const registry = @import("registry.zig");

const Options = struct {
    domains_dir: []const u8,
    fake_cidr: ip.Cidr,
    queue_num: u16,
    mark_base: u32,
    upstream: ip.IpPort,
    dns_listen: ip.IpPort,
    dns_enabled: bool,
    fake_ttl: u32,
    dns_timeout_ms: i32,
    wildcard_idle_timeout: u64,
    nft_map: bool,
    state_file: []const u8,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var stdout_buf: [8192]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(init.io, &stdout_buf);
    const out = &stdout_writer.interface;
    defer out.flush() catch {};

    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next(); // argv[0]

    const cmd = args.next() orelse "help";
    var opts = Options{
        .domains_dir = "/etc/nfqueue-router/domains",
        .fake_cidr = ip.Cidr.defaultFake(),
        .queue_num = 100,
        .mark_base = 0x52000000,
        .upstream = try ip.parseIpPort("1.1.1.1:53", 53),
        .dns_listen = try ip.parseIpPort("127.0.0.1:53053", 53),
        .dns_enabled = true,
        .fake_ttl = 60,
        .dns_timeout_ms = 1500,
        .wildcard_idle_timeout = config.DynamicMap.default_idle_ttl_seconds,
        .nft_map = false,
        .state_file = "/var/lib/nfqueue-router/leases.txt",
    };
    try parseOptions(&args, &opts);

    if (std.mem.eql(u8, cmd, "help") or std.mem.eql(u8, cmd, "--help") or std.mem.eql(u8, cmd, "-h")) {
        try printHelp(out);
    } else if (std.mem.eql(u8, cmd, "list")) {
        var table = try config.Table.load(allocator, init.io, opts.domains_dir, opts.fake_cidr, opts.mark_base);
        defer table.deinit();
        try printTable(out, &table);
    } else if (std.mem.eql(u8, cmd, "gen-hosts")) {
        var table = try config.Table.load(allocator, init.io, opts.domains_dir, opts.fake_cidr, opts.mark_base);
        defer table.deinit();
        try printHosts(out, &table);
    } else if (std.mem.eql(u8, cmd, "gen-kresd")) {
        try printKresdSnippet(out, opts);
    } else if (std.mem.eql(u8, cmd, "gen-nft")) {
        var table = try config.Table.load(allocator, init.io, opts.domains_dir, opts.fake_cidr, opts.mark_base);
        defer table.deinit();
        try printNft(out, opts, &table);
    } else if (std.mem.eql(u8, cmd, "gen-ip-rules")) {
        var table = try config.Table.load(allocator, init.io, opts.domains_dir, opts.fake_cidr, opts.mark_base);
        defer table.deinit();
        try printIpRules(out, &table);
    } else if (std.mem.eql(u8, cmd, "dns")) {
        var table = try config.Table.load(allocator, init.io, opts.domains_dir, opts.fake_cidr, opts.mark_base);
        defer table.deinit();
        var dynamic = config.DynamicMap.initWithIdleTtl(allocator, &table, opts.wildcard_idle_timeout);
        defer dynamic.deinit();
        var nft_controller = nftctl.Controller.init(allocator, init.io);
        defer nft_controller.deinit();
        const batch_path = try std.fmt.allocPrint(allocator, "{s}.nft", .{opts.state_file});
        defer allocator.free(batch_path);
        nft_controller.batch_path = batch_path;
        var leases = registry.Registry.init(allocator, init.io, opts.state_file, &table);
        defer leases.deinit();
        if (opts.nft_map) {
            try leases.load();
            try leases.restore(&nft_controller);
        }
        try dns.serveUdp(allocator, &table, &dynamic, if (opts.nft_map) &nft_controller else null, .{
            .leases = if (opts.nft_map) &leases else null,
            .listen = opts.dns_listen,
            .upstream = opts.upstream,
            .fake_ttl = opts.fake_ttl,
            .timeout_ms = opts.dns_timeout_ms,
        });
    } else if (std.mem.eql(u8, cmd, "run")) {
        if (builtin.os.tag != .linux) return error.UnsupportedPlatform;
        var table = try config.Table.load(allocator, init.io, opts.domains_dir, opts.fake_cidr, opts.mark_base);
        defer table.deinit();

        var dynamic = config.DynamicMap.initWithIdleTtl(allocator, &table, opts.wildcard_idle_timeout);
        defer dynamic.deinit();

        if (opts.dns_enabled) {
            const dns_args = DnsThreadArgs{
                .allocator = allocator,
                .table = &table,
                .dynamic = &dynamic,
                .nft = null,
                .opts = .{
                    .listen = opts.dns_listen,
                    .upstream = opts.upstream,
                    .fake_ttl = opts.fake_ttl,
                    .timeout_ms = opts.dns_timeout_ms,
                },
            };
            var thread = try std.Thread.spawn(.{}, dnsThreadMain, .{dns_args});
            thread.detach();
        }

        var resolver = dns.Resolver.init(allocator, opts.upstream, opts.dns_timeout_ms);
        defer resolver.deinit();
        var router = nat.Router.init(allocator, &table, &dynamic, &resolver);
        defer router.deinit();
        try nfqueue.run(&router, .{ .queue_num = opts.queue_num });
    } else {
        try out.print("unknown command: {s}\n\n", .{cmd});
        try printHelp(out);
        return error.InvalidCommand;
    }
}

const DnsThreadArgs = struct {
    allocator: std.mem.Allocator,
    table: *const config.Table,
    dynamic: *config.DynamicMap,
    nft: ?*nftctl.Controller,
    opts: dns.ServerOptions,
};

fn dnsThreadMain(args: DnsThreadArgs) void {
    dns.serveUdp(args.allocator, args.table, args.dynamic, args.nft, args.opts) catch |err| {
        std.debug.print("DNS worker stopped: {s}\n", .{@errorName(err)});
    };
}

fn parseOptions(args: *std.process.Args.Iterator, opts: *Options) !void {
    while (args.next()) |arg_z| {
        const arg: []const u8 = arg_z;
        if (try optionValue(arg, "--domains-dir", args)) |v| {
            opts.domains_dir = v;
        } else if (try optionValue(arg, "--fake-cidr", args)) |v| {
            opts.fake_cidr = try ip.parseCidr(v);
        } else if (try optionValue(arg, "--queue-num", args)) |v| {
            opts.queue_num = std.fmt.parseInt(u16, v, 0) catch return error.InvalidQueueNum;
        } else if (try optionValue(arg, "--mark-base", args)) |v| {
            opts.mark_base = std.fmt.parseInt(u32, v, 0) catch return error.InvalidMarkBase;
        } else if (try optionValue(arg, "--upstream-dns", args)) |v| {
            opts.upstream = try ip.parseIpPort(v, 53);
        } else if (try optionValue(arg, "--dns-listen", args)) |v| {
            opts.dns_listen = try ip.parseIpPort(v, 53);
        } else if (try optionValue(arg, "--fake-ttl", args)) |v| {
            opts.fake_ttl = std.fmt.parseInt(u32, v, 0) catch return error.InvalidTtl;
        } else if (try optionValue(arg, "--dns-timeout-ms", args)) |v| {
            opts.dns_timeout_ms = std.fmt.parseInt(i32, v, 0) catch return error.InvalidTimeout;
        } else if (try optionValue(arg, "--state-file", args)) |v| {
            opts.state_file = v;
        } else if (try optionValue(arg, "--wildcard-idle-timeout", args)) |v| {
            opts.wildcard_idle_timeout = std.fmt.parseInt(u64, v, 0) catch return error.InvalidWildcardIdleTimeout;
        } else if (std.mem.eql(u8, arg, "--no-dns")) {
            opts.dns_enabled = false;
        } else if (std.mem.eql(u8, arg, "--nft-map")) {
            opts.nft_map = true;
        } else {
            std.debug.print("unknown option: {s}\n", .{arg});
            return error.InvalidOption;
        }
    }
}

fn optionValue(arg: []const u8, name: []const u8, args: *std.process.Args.Iterator) !?[]const u8 {
    if (std.mem.eql(u8, arg, name)) return args.next() orelse error.MissingOptionValue;
    if (std.mem.startsWith(u8, arg, name) and arg.len > name.len and arg[name.len] == '=') return arg[name.len + 1 ..];
    return null;
}

fn printHelp(out: *std.Io.Writer) !void {
    try out.writeAll(
        \\nfqueue-router - fake-IP domain router for Knot Resolver + Linux NFQUEUE
        \\
        \\Commands:
        \\  run            run UDP DNS worker and Linux NFQUEUE packet worker
        \\  dns            run only the UDP DNS worker for Knot Resolver
        \\  list           print domain -> fake IP -> interface mapping
        \\  gen-kresd      print Knot Resolver forwarding snippet
        \\  gen-nft        print nftables NFQUEUE rules
        \\  gen-ip-rules   print Linux policy-routing rules for interface marks
        \\  gen-hosts      print static hosts-style fake records
        \\
        \\Options:
        \\  --domains-dir DIR       directory with <interface>.txt domain files
        \\  --fake-cidr CIDR        fake IPv4 pool (default 127.128.0.0/9)
        \\  --queue-num N           NFQUEUE number (default 100)
        \\  --mark-base N           fwmark base (default 0x52000000)
        \\  --dns-listen IP:PORT    DNS worker listen address (default 127.0.0.1:53053)
        \\  --upstream-dns IP:PORT  upstream DNS for real answers (default 1.1.1.1:53)
        \\  --fake-ttl SECONDS      TTL for fake A answers (default 60)
        \\  --wildcard-idle-timeout SECONDS
        \\                           legacy NFQUEUE only: expire idle mappings (default 3600)
        \\  --state-file PATH       kernel-mode durable leases (default /var/lib/nfqueue-router/leases.txt)
        \\  --no-dns                in run mode, do not start embedded DNS worker
        \\  --nft-map               DNS mode: maintain kernel nft DNAT maps for QUIC/HTTP3
        \\
    );
}

fn printTable(out: *std.Io.Writer, table: *const config.Table) !void {
    try out.writeAll("FAKE_IP\tINTERFACE\tMARK\tDOMAIN\n");
    for (table.routes.items) |route| {
        const iface = table.ifaceFor(&route);
        try ip.writeIpv4(out, route.fake_ip);
        try out.print("\t{s}\t0x{x}\t", .{ iface.name, iface.mark });
        try writeRouteDomain(out, route);
        try out.writeAll("\n");
    }
}

fn printHosts(out: *std.Io.Writer, table: *const config.Table) !void {
    for (table.routes.items) |route| {
        try ip.writeIpv4(out, route.fake_ip);
        try out.writeAll("\t");
        try writeRouteDomain(out, route);
        try out.writeAll("\n");
    }
}

fn printKresdSnippet(out: *std.Io.Writer, opts: Options) !void {
    try out.writeAll("-- nfqueue-router Knot Resolver integration\n");
    try out.writeAll("-- Run nfqueue-router as a local DNS upstream and NFQUEUE worker.\n");
    try out.writeAll("-- Make sure nfqueue-router --upstream-dns does NOT point back to this kresd instance.\n");
    try out.writeAll("modules = { 'policy' }\n");
    try out.writeAll("policy.add(policy.all(policy.FORWARD({ '");
    try writeIpPort(out, opts.dns_listen);
    try out.writeAll("' })))\n");
}

fn printNft(out: *std.Io.Writer, opts: Options, table: *const config.Table) !void {
    try out.writeAll("#!/usr/sbin/nft -f\n");
    try out.writeAll("# Generated by nfqueue-router. This ruleset is for local-host routing.\n");
    try out.writeAll("# Reply packets are queued in prerouting/raw so source rewrite happens before conntrack/TCP demux.\n");
    try out.writeAll("table inet nfqueue_router {\n");
    try out.writeAll("  chain output_fakeip {\n");
    try out.writeAll("    type route hook output priority mangle; policy accept;\n");
    for (table.routes.items) |route| {
        const iface = table.ifaceFor(&route);
        try out.writeAll("    meta l4proto { tcp, udp } ip daddr ");
        try ip.writeIpv4(out, route.fake_ip);
        try out.print(" counter meta mark set 0x{x} # ", .{iface.mark});
        try writeRouteDomain(out, route);
        try out.print(" via {s}\n", .{iface.name});
    }
    try out.writeAll("    meta l4proto { tcp, udp } ip daddr ");
    try writeCidr(out, opts.fake_cidr);
    try out.print(" counter queue num {} bypass\n", .{opts.queue_num});
    try out.writeAll("  }\n\n");
    try out.writeAll("  chain preroute_replies {\n");
    try out.writeAll("    type filter hook prerouting priority raw; policy accept;\n");
    try out.writeAll("    ip saddr ");
    try ip.writeIpv4(out, opts.upstream.ip);
    try out.print(" udp sport {} counter accept # nfqueue-router resolver replies\n", .{opts.upstream.port});
    try out.writeAll("    ip saddr ");
    try ip.writeIpv4(out, opts.upstream.ip);
    try out.print(" tcp sport {} counter accept # nfqueue-router resolver replies\n", .{opts.upstream.port});
    try out.print("    meta l4proto {{ tcp, udp }} counter queue num {} bypass\n", .{opts.queue_num});
    try out.writeAll("  }\n");
    try out.writeAll("}\n");
}

fn printIpRules(out: *std.Io.Writer, table: *const config.Table) !void {
    try out.writeAll("#!/bin/sh\nset -eu\n");
    for (table.interfaces.items, 0..) |iface, idx| {
        const table_id = 1000 + idx + 1;
        try out.print("# {s}\n", .{iface.name});
        try out.print("ip rule add fwmark 0x{x}/0xffffffff table {} 2>/dev/null || true\n", .{ iface.mark, table_id });
        try out.print("ip route replace default dev {s} table {}\n\n", .{ iface.name, table_id });
    }
}

fn writeRouteDomain(out: *std.Io.Writer, route: config.Route) !void {
    if (route.wildcard) try out.writeAll("*.");
    try out.writeAll(route.domain);
}

fn writeIpPort(out: *std.Io.Writer, value: ip.IpPort) !void {
    try ip.writeIpv4(out, value.ip);
    try out.print("@{}", .{value.port});
}

fn writeCidr(out: *std.Io.Writer, cidr: ip.Cidr) !void {
    try ip.writeIpv4(out, cidr.base);
    try out.print("/{}", .{cidr.prefix});
}

test {
    _ = ip;
    _ = config;
    _ = dns;
    _ = nat;
    _ = nftctl;
    _ = registry;
    _ = @import("packet.zig");
}
