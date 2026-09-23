// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! ifaddr.zig —— 「网卡名 -> 当前 IPv4 地址 + 掩码」。
//!
//! 为什么需要它：odhcpd 的 UCI DHCPv4 池不是写死地址的，而是
//! 「网段的第 start 个地址起、共 limit 个」——见 `ref/odhcpd/src/config.c:1233`
//! （`dhcpv4_pool_start = start`、`dhcpv4_pool_end = start + limit - 1`，都是
//! **相对网络号的偏移**），再由 `dhcpv4.c:1362` 的 `dhcpv4_setup_addresses()`
//! 加上接口地址所在网段的基址。所以要在没有 ubus 的情况下复刻它，就必须
//! 自己拿到接口的 IPv4 地址与掩码位数。
//!
//! 数据来源刻意只走 **netlink**（复用 `net.zig` 的两个 dump）：
//! ujail 沙箱默认只挂白名单挂载，`/sys` 常常不可见，而 ioctl(SIOCGIFADDR)
//! 在沙箱里也要多一个 socket。netlink 路线在 DNS 侧已经被实机验证过
//! （见 net.zig 顶部的长注释），这里沿用同一套。

const std = @import("std");
const net = @import("net.zig");
const dhcpv4 = @import("dhcpv4.zig");

const Allocator = std.mem.Allocator;
const log = @import("log.zig");

/// 一个网卡上的一条 IPv4 配置。
pub const Ipv4Iface = struct {
    /// 本端地址
    addr: [4]u8,
    /// 由 prefixlen 还原出的点分掩码
    netmask: [4]u8,
    /// 掩码位数（RTM_GETADDR 的 prefixlen）
    prefixlen: u8,
    /// 网络号 = addr & netmask
    network: [4]u8,
};

/// 掩码位数 -> 点分掩码。`prefixlen` 超过 32 时按 32 处理（防御性）。
pub fn prefixLenToMask(prefixlen: u8) [4]u8 {
    var m: u32 = 0;
    var i: u8 = 0;
    while (i < prefixlen and i < 32) : (i += 1) m |= @as(u32, 1) << @intCast(31 - i);
    return dhcpv4.u32ToIp(m);
}

/// `net.SockAddr` 里的 IPv4 存的是**网络序的 u32**（见 addr.zig 的 fromIp4），
/// 这里把它还原成 4 个字节。用 writeInt(.little) 而不是 @bitCast，是为了在
/// 大小端机器上结果都一致。
fn naU32ToIp(v: u32) [4]u8 {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .little);
    return b;
}

/// 查一个网卡名当前的一条 IPv4 配置；没有 IPv4 地址（或网卡不存在）返回 null。
///
/// 多地址时取**第一个**（netlink dump 的顺序 = 内核地址链表顺序，主地址在前），
/// 与 odhcpd 在 `dhcpv4_setup_addresses()` 里遍历 `oaddrs4[]` 取首个可用项一致。
pub fn lookup(allocator: Allocator, ifname: []const u8) ?Ipv4Iface {
    var links: std.ArrayListUnmanaged(net.IfaceLink) = .empty;
    defer {
        for (links.items) |l| allocator.free(l.name);
        links.deinit(allocator);
    }
    net.listIfaceLinks(allocator, &links) catch return null;

    var idx: ?u32 = null;
    for (links.items) |l| {
        if (std.mem.eql(u8, l.name, ifname)) {
            idx = l.index;
            break;
        }
    }
    const want = idx orelse {
        log.warning("网卡 '{s}' 不存在", .{ifname});
        return null;
    };

    var addrs: std.ArrayListUnmanaged(net.IfaceAddr) = .empty;
    defer addrs.deinit(allocator);
    net.listIfaceAddrs(allocator, &addrs) catch return null;

    for (addrs.items) |a| {
        if (a.ifindex != want) continue;
        if (!a.sa.isIp4()) continue;
        const addr = naU32ToIp(a.sa.asIn().addr);
        const mask = prefixLenToMask(a.prefixlen);
        return .{
            .addr = addr,
            .netmask = mask,
            .prefixlen = a.prefixlen,
            .network = dhcpv4.networkOf(addr, mask),
        };
    }
    return null;
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

const testing = std.testing;

test "ifaddr：prefixLenToMask 覆盖常见与边界位数" {
    try testing.expectEqual([4]u8{ 0, 0, 0, 0 }, prefixLenToMask(0));
    try testing.expectEqual([4]u8{ 128, 0, 0, 0 }, prefixLenToMask(1));
    try testing.expectEqual([4]u8{ 255, 0, 0, 0 }, prefixLenToMask(8));
    try testing.expectEqual([4]u8{ 255, 255, 0, 0 }, prefixLenToMask(16));
    try testing.expectEqual([4]u8{ 255, 255, 255, 0 }, prefixLenToMask(24));
    try testing.expectEqual([4]u8{ 255, 255, 255, 128 }, prefixLenToMask(25));
    try testing.expectEqual([4]u8{ 255, 255, 255, 240 }, prefixLenToMask(28));
    try testing.expectEqual([4]u8{ 255, 255, 255, 254 }, prefixLenToMask(31));
    try testing.expectEqual([4]u8{ 255, 255, 255, 255 }, prefixLenToMask(32));
    // 越界按 /32 处理，不能崩
    try testing.expectEqual([4]u8{ 255, 255, 255, 255 }, prefixLenToMask(33));
    try testing.expectEqual([4]u8{ 255, 255, 255, 255 }, prefixLenToMask(255));
}

test "ifaddr：还原出的掩码必须是连续掩码（反向自检）" {
    var pl: u8 = 0;
    while (pl <= 32) : (pl += 1) {
        const m = prefixLenToMask(pl);
        try testing.expectEqual(pl, dhcpv4.maskPrefixLen(m).?);
    }
}

test "ifaddr：naU32ToIp 按网络序还原字节" {
    // netlink 收到 192.168.0.1 的字节 C0 A8 00 01，按 little 读成 u32
    try testing.expectEqual([4]u8{ 192, 168, 0, 1 }, naU32ToIp(0x0100A8C0));
    try testing.expectEqual([4]u8{ 127, 0, 0, 1 }, naU32ToIp(0x0100007F));
    try testing.expectEqual([4]u8{ 0, 0, 0, 0 }, naU32ToIp(0));
}

test "ifaddr：本机回环必须查得到 127.0.0.1/8" {
    const r = lookup(testing.allocator, "lo") orelse return error.SkipZigTest;
    try testing.expectEqual([4]u8{ 255, 0, 0, 0 }, r.netmask);
    try testing.expectEqual(@as(u8, 8), r.prefixlen);
    try testing.expectEqual(dhcpv4.networkOf(r.addr, r.netmask), r.network);
}

test "ifaddr：不存在的网卡返回 null 而不是崩" {
    try testing.expectEqual(@as(?Ipv4Iface, null), lookup(testing.allocator, "zz-nope-0"));
}
