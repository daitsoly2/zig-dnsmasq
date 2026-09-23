// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! dot_proto.zig — DoT (RFC 7858) 客户端原型
//!
//! 目的：先把「Zig 0.16 上如何用裸 socket 做 TLS」这条路走通，
//! 再把它搬进 dnsmasq 的上游转发层。跑通了才动主代码。
//!
//! 用法：zig run bench/dot_proto.zig -- <ip> <port> <sni-host> <qname>

const std = @import("std");
const tls = std.crypto.tls;

fn encodeQname(buf: []u8, name: []const u8) usize {
    var o: usize = 0;
    var it = std.mem.splitScalar(u8, name, '.');
    while (it.next()) |label| {
        if (label.len == 0) continue;
        buf[o] = @intCast(label.len);
        o += 1;
        @memcpy(buf[o..][0..label.len], label);
        o += label.len;
    }
    buf[o] = 0;
    o += 1;
    return o;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    var args: std.ArrayListUnmanaged([]const u8) = .empty;
    defer args.deinit(gpa);
    var it = init.minimal.args.iterate();
    _ = it.next();
    while (it.next()) |a| try args.append(gpa, a);

    const ip_s = if (args.items.len > 0) args.items[0] else "1.1.1.1";
    const port: u16 = if (args.items.len > 1)
        try std.fmt.parseInt(u16, args.items[1], 10)
    else
        853;
    const sni = if (args.items.len > 2) args.items[2] else "cloudflare-dns.com";
    const qname = if (args.items.len > 3) args.items[3] else "example.com";

    var bench = std.heap.DebugAllocator(.{}).init;
    defer _ = bench.deinit();

    std.debug.print("[1] 连接 {s}:{d} (SNI={s})\n", .{ ip_s, port, sni });

    var addr = std.Io.net.IpAddress.parse(ip_s, port) catch |e| {
        std.debug.print("地址解析失败: {s}\n", .{@errorName(e)});
        return;
    };
    var stream = addr.connect(io, .{ .mode = .stream }) catch |e| {
        std.debug.print("TCP 连接失败: {s}\n", .{@errorName(e)});
        return;
    };
    defer stream.close(io);

    std.debug.print("[2] 加载系统根证书\n", .{});
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(gpa);
    var bundle_lock: std.Io.RwLock = .init;
    const now = std.Io.Timestamp.now(io, .real);
    bundle.rescan(gpa, io, now) catch |e| {
        std.debug.print("  证书加载失败: {s}\n", .{@errorName(e)});
        return;
    };
    std.debug.print("  已加载 {d} 个根证书\n", .{bundle.map.count()});

    var net_rbuf: [tls.Client.min_buffer_len]u8 = undefined;
    var net_wbuf: [tls.Client.min_buffer_len]u8 = undefined;
    var sr = stream.reader(io, &net_rbuf);
    var sw = stream.writer(io, &net_wbuf);

    var plain_wbuf: [4096]u8 = undefined;
    var plain_rbuf: [4096]u8 = undefined;
    var entropy: [tls.Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);

    std.debug.print("[3] TLS 握手\n", .{});
    var client = tls.Client.init(&sr.interface, &sw.interface, .{
        .host = .{ .explicit = sni },
        .ca = .{ .bundle = .{
            .gpa = gpa,
            .io = io,
            .lock = &bundle_lock,
            .bundle = &bundle,
        } },
        .write_buffer = &plain_wbuf,
        .read_buffer = &plain_rbuf,
        .entropy = &entropy,
        .realtime_now = now,
    }) catch |e| {
        std.debug.print("握手失败: {s}\n", .{@errorName(e)});
        if (sr.err) |se| std.debug.print("  底层读错误: {s}\n", .{@errorName(se)});
        if (sw.err) |se| std.debug.print("  底层写错误: {s}\n", .{@errorName(se)});
        return;
    };
    std.debug.print("  握手成功（证书已通过校验）\n", .{});

    // ---- 构造 DNS 查询 ----
    var q: [512]u8 = undefined;
    q[0] = 0xAB; q[1] = 0xCD;
    q[2] = 0x01; q[3] = 0x00; // RD
    q[4] = 0; q[5] = 1;       // qdcount
    q[6] = 0; q[7] = 0;
    q[8] = 0; q[9] = 0;
    q[10] = 0; q[11] = 0;
    var o: usize = 12;
    o += encodeQname(q[o..], qname);
    q[o] = 0; q[o + 1] = 1; // A
    q[o + 2] = 0; q[o + 3] = 1; // IN
    o += 4;

    // DoT 帧：2 字节长度前缀
    var frame: [600]u8 = undefined;
    std.mem.writeInt(u16, frame[0..2], @intCast(o), .big);
    @memcpy(frame[2..][0..o], q[0..o]);
    const flen = o + 2;

    std.debug.print("[4] 发送 {d} 字节 DoT 查询: {s}\n", .{ flen, qname });
    try client.writer.writeAll(frame[0..flen]);
    try client.writer.flush();

    var lenbuf: [2]u8 = undefined;
    try client.reader.readSliceAll(&lenbuf);
    const rlen = std.mem.readInt(u16, &lenbuf, .big);
    var rbuf: [4096]u8 = undefined;
    if (rlen > rbuf.len) {
        std.debug.print("应答过长: {d}\n", .{rlen});
        return;
    }
    try client.reader.readSliceAll(rbuf[0..rlen]);

    const flags = std.mem.readInt(u16, rbuf[2..4], .big);
    const ancount = std.mem.readInt(u16, rbuf[6..8], .big);
    std.debug.print("[5] 收到 {d} 字节应答: id=0x{x} rcode={d} ancount={d}\n", .{
        rlen,
        std.mem.readInt(u16, rbuf[0..2], .big),
        flags & 0xF,
        ancount,
    });

    if (ancount > 0 and rlen >= 4) {
        std.debug.print("    末尾 4 字节（应为 A 记录地址）: {d}.{d}.{d}.{d}\n", .{
            rbuf[rlen - 4], rbuf[rlen - 3], rbuf[rlen - 2], rbuf[rlen - 1],
        });
    }

    client.end() catch {};
    std.debug.print("[6] 完成\n", .{});
}
