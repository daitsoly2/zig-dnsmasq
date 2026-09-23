// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! resolv.zig — 复刻 dnsmasq 读取 resolv.conf 的功能（对应 C 源码
//! src/network.c 的 reload_servers()，以及 src/option.c 中读取 domain/search 的逻辑）。
//!
//! 行为要点：
//!   * nameserver <ip> 只接受 IP 字面量（不做 DNS 解析），创建 daemon.Server，
//!     flags = SERV_USE_RESOLV | SERV_FROM_RESOLV，端口 53。
//!   * domain <name> 与 search <name> ... 在 d.domain == null 时设置 d.domain
//!     （用 canonicalise，dup 到 d.allocator）。
//!   * options ... / sortlist ... 忽略；文件不存在不报错（返回 0 并 log 提示）。

const std = @import("std");
const protocol = @import("protocol.zig");
const addr = @import("addr.zig");
const name = @import("name.zig");
const daemon = @import("daemon.zig");
const log = @import("log.zig");

/// 用同步 posix 调用把整个文件读入内存；文件不存在或读取失败时返回 null。
fn readTextFile(allocator: std.mem.Allocator, path: []const u8) ?[]u8 {
    const fd = std.posix.openat(std.posix.AT.FDCWD, path, std.posix.O{ .ACCMODE = .RDONLY }, 0) catch {
        log.info("无法读取 resolv 文件 {s}", .{path});
        return null;
    };
    defer _ = std.posix.system.close(fd);

    var buf: std.ArrayList(u8) = .empty;
    var tmp: [8192]u8 = undefined;
    while (true) {
        const n = std.posix.read(fd, &tmp) catch {
            buf.deinit(allocator);
            return null;
        };
        if (n == 0) break;
        buf.appendSlice(allocator, tmp[0..n]) catch {
            buf.deinit(allocator);
            return null;
        };
    }

    return buf.toOwnedSlice(allocator) catch null;
}

/// 同一份 resolv.conf 里已经读过、且地址端口完全一致的 resolv 来源上游是否已存在。
///
/// 这是一道防御线：本模块的读取函数是**追加**语义，调用方若未先清理
/// SERV_FROM_RESOLV 就重复调用（历史上 pollResolv 正是这么错的），会把同一
/// 组 nameserver 一遍遍堆上去。有了去重，即便重复调用也只是 no-op。
fn hasResolvServer(d: *const daemon.Daemon, sa: addr.SockAddr) bool {
    for (d.servers.items) |s| {
        if ((s.flags & protocol.SERV_FROM_RESOLV) == 0) continue;
        if (s.addr.family() != sa.family()) continue;
        if (s.addr.port() != sa.port()) continue;
        if (s.addr.isIp4() and sa.isIp4()) {
            if (s.addr.asIn().addr == sa.asIn().addr) return true;
        } else if (s.addr.isIp6() and sa.isIp6()) {
            if (std.mem.eql(u8, &s.addr.asIn6().addr, &sa.asIn6().addr)) return true;
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// 解析 resolv.conf 文本（对应 C: network.c reload_servers 的核心循环）
// ---------------------------------------------------------------------------
/// 解析一段 resolv.conf 文本，返回新增的 nameserver 条数；
/// domain/search 会用于设置 d.domain（若尚未设置）。
pub fn parseResolvText(d: *daemon.Daemon, text: []const u8) !usize {
    var added: usize = 0;

    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        // '#' 起为注释，截断到行尾
        const hidx = std.mem.indexOfScalar(u8, line, '#');
        const l = if (hidx) |i| line[0..i] else line;

        var it = std.mem.tokenizeAny(u8, l, " \t");
        const cmd = it.next() orelse continue;

        if (std.mem.eql(u8, cmd, "nameserver")) {
            const tok = it.next() orelse continue;

            // 只接受 IP 字面量，不做 DNS 解析
            var ip4: u32 = 0;
            var ip6: [16]u8 = undefined;
            var a: addr.AllAddr = undefined;

            if (addr.parseIp4(tok, &ip4)) {
                a = .{ .ip4 = ip4 };
            } else if (addr.parseIp6(tok, &ip6)) {
                a = .{ .ip6 = ip6 };
            } else {
                continue;
            }

            const sa = switch (a) {
                .ip4 => addr.SockAddr.fromIp4(a.ip4, protocol.NAMESERVER_PORT),
                .ip6 => addr.SockAddr.fromIp6(a.ip6, protocol.NAMESERVER_PORT, 0),
                else => continue,
            };

            // 已存在同地址的上游就跳过：重复加载同一份文件不应产生重复条目
            if (hasResolvServer(d, sa)) continue;

            const s = try d.newServer();
            s.flags = protocol.SERV_USE_RESOLV | protocol.SERV_FROM_RESOLV;
            s.addr = sa;
            try d.addServer(s);
            added += 1;
        } else if (std.mem.eql(u8, cmd, "domain")) {
            // domain <name>：d.domain == null 时设置
            if (d.domain == null) {
                const tok = it.next() orelse continue;
                if (name.canonicalise(d.allocator, tok)) |canon| {
                    d.domain = canon;
                }
            }
        } else if (std.mem.eql(u8, cmd, "search")) {
            // search <name> ...：取第一个名字作为默认域（d.domain == null 时）
            if (d.domain == null) {
                const tok = it.next() orelse continue;
                if (name.canonicalise(d.allocator, tok)) |canon| {
                    d.domain = canon;
                }
            }
        } else {
            // options / sortlist / 其它：忽略
            continue;
        }
    }

    return added;
}

// ---------------------------------------------------------------------------
// 读取一个 resolv.conf 文件
// ---------------------------------------------------------------------------
/// 读取一个 resolv.conf 文件；文件不存在返回 0（并 log 提示），否则返回新增
/// 的 nameserver 条数。
pub fn readResolvFile(d: *daemon.Daemon, path: []const u8) !usize {
    const content = readTextFile(d.allocator, path) orelse return 0;
    defer d.allocator.free(content);
    return try parseResolvText(d, content);
}

// ---------------------------------------------------------------------------
// 按 d.resolv_files 读取（对应 C: option.c 中 resolv 文件列表 + OPT_NO_RESOLV）
// ---------------------------------------------------------------------------
/// 按 d.resolv_files（默认 /etc/resolv.conf）读取；若设置了 OPT_NO_RESOLV 则直接返回。
pub fn readResolvFiles(d: *daemon.Daemon) !void {
    if (d.option(protocol.OPT_NO_RESOLV)) return;

    // 默认路径：/etc/resolv.conf（对应 C 的 RESOLVFILE）
    if (d.resolv_files.items.len == 0) {
        _ = readResolvFile(d, "/etc/resolv.conf") catch 0;
        return;
    }

    for (d.resolv_files.items) |p| {
        _ = readResolvFile(d, p) catch 0;
    }
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------
const testing = std.testing;

test "parseResolvText nameserver/domain/search" {
    const allocator = testing.allocator;
    var d: daemon.Daemon = .{ .allocator = allocator };
    // domain 由 Daemon 持有，deinit() 会释放
    defer d.deinit();

    const text =
        "nameserver 8.8.8.8\n" ++
        "nameserver 2001:4860:4860::8888\n" ++
        "domain example.com\n" ++
        "search sub1.example sub2.example\n";
    const added = try parseResolvText(&d, text);
    try testing.expectEqual(@as(usize, 2), added);
    try testing.expectEqual(@as(usize, 2), d.servers.items.len);

    const s0 = d.servers.items[0];
    try testing.expect((s0.flags & protocol.SERV_USE_RESOLV) != 0);
    try testing.expect((s0.flags & protocol.SERV_FROM_RESOLV) != 0);
    try testing.expectEqual(@as(u16, 53), s0.addr.port());

    // domain 取自 domain 行（canonicalise 后不变）
    try testing.expect(d.domain != null);
    try testing.expectEqualStrings("example.com", d.domain.?);

    // search 行不被采用（domain 已设置）
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("8.8.8.8#53", s0.addr.writeTo(&buf));
}

test "parseResolvText 忽略非法行与 options/sortlist" {
    const allocator = testing.allocator;
    var d: daemon.Daemon = .{ .allocator = allocator };
    // domain 由 Daemon 持有，deinit() 会释放
    defer d.deinit();

    const text =
        "options ndots:5 timeout:2\n" ++
        "sortlist 10.0.0.0/8\n" ++
        "nameserver not-an-ip\n" ++
        "garbage line here\n" ++
        "nameserver 1.1.1.1\n";
    const added = try parseResolvText(&d, text);
    try testing.expectEqual(@as(usize, 1), added);
    try testing.expectEqual(@as(usize, 1), d.servers.items.len);
    try testing.expect(d.domain == null);
}

test "parseResolvText search 取首个名字作为默认域" {
    const allocator = testing.allocator;
    var d: daemon.Daemon = .{ .allocator = allocator };
    // domain 由 Daemon 持有，deinit() 会释放
    defer d.deinit();

    const text = "search alpha.example beta.example\n";
    _ = try parseResolvText(&d, text);
    try testing.expect(d.domain != null);
    try testing.expectEqualStrings("alpha.example", d.domain.?);
}

test "readResolvFile 缺失文件返回 0" {
    const allocator = testing.allocator;
    var d: daemon.Daemon = .{ .allocator = allocator };
    // domain 由 Daemon 持有，deinit() 会释放
    defer d.deinit();

    const added = try readResolvFile(&d, "/tmp/zz_nonexistent_resolv_xyz.conf");
    try testing.expectEqual(@as(usize, 0), added);
}

test "readResolvFile 正常读取文件" {
    const allocator = testing.allocator;
    var d: daemon.Daemon = .{ .allocator = allocator };
    // domain 由 Daemon 持有，deinit() 会释放
    defer d.deinit();

    const path = "/tmp/zz_resolv_test.conf";
    const fd = std.posix.openat(std.posix.AT.FDCWD, path, std.posix.O{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
    }, 0o644) catch unreachable;
    defer _ = std.posix.system.close(fd);
    _ = std.posix.system.write(fd, "nameserver 9.9.9.9\n".ptr, "nameserver 9.9.9.9\n".len);

    const added = try readResolvFile(&d, path);
    try testing.expectEqual(@as(usize, 1), added);
    try testing.expectEqual(@as(usize, 1), d.servers.items.len);
}
