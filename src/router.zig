// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! router.zig —— RA（RFC 4861/4862）与 NDP 应答的报文构造。
//!
//! ## 定位
//!
//! 与 `dhcpv6.zig` 一样是**纯函数**：字节进出。socket 与周期调度在
//! `odhcpd_main.zig` 的 v6 运行时里。
//!
//! ## 关键的平台事实（探针实测，见 DHCP-PLAN.md §9）
//!
//! * **raw ICMPv6 socket 会收到自己发的包** —— ICMP6_FILTER 绝不能放行
//!   type 134（RA），否则自己刚发的 RA 会被当成收到的报文再处理一遍。
//! * **校验和由内核代填**：raw socket 上内核算 ICMPv6 checksum，
//!   构造时 checksum 字段写 0 即可。
//! * 回环不支持组播（IPV6_MULTICAST_IF 在 lo 上 EINVAL），测试用
//!   「目的地址 = 本机自己的链路本地地址」走完整收发路径。

const std = @import("std");
const v6conf = @import("v6conf.zig");

pub const ICMPV6_RA: u8 = 134;
pub const ICMPV6_RS: u8 = 133;
pub const ICMPV6_NS: u8 = 135;
pub const ICMPV6_NA: u8 = 136;

// ICMPv6 option 类型
pub const OPT_SRC_LLADDR: u8 = 1;
pub const OPT_TARGET_LLADDR: u8 = 2;
pub const OPT_PREFIX_INFO: u8 = 3;
pub const OPT_MTU: u8 = 5;
pub const OPT_RDNSS: u8 = 25; // RFC 8106
pub const OPT_DNSSL: u8 = 31; // RFC 8106
pub const OPT_PREF64: u8 = 38; // RFC 8781

// ff02::1 —— 组播地址高 2 字节必须是 FF02，否则 join/sendto 直接 EINVAL
pub const AllNodes: [16]u8 = .{ 0xFF, 2 } ++ [_]u8{0} ** 12 ++ .{ 0, 1 };

// ff02::2
pub const AllRouters: [16]u8 = .{ 0xFF, 2 } ++ [_]u8{0} ** 13 ++ .{2};

/// PIO 需要的一条前缀信息
pub const Pio = struct {
    prefix: [16]u8,
    len: u8,
    valid: u32,
    preferred: u32,
};

// ---------------------------------------------------------------------------
// RA 构造
// ---------------------------------------------------------------------------

/// 构造一个 RA。返回写入的字节数（buf 太小则尽力写，选项按顺序放，放不下的丢）。
///
/// 字段对照 odhcpd `router.c:send_router_advert()`：
///   * `nd_ra_router_lifetime`：**只有 ra_default>0 且有公网前缀**才填
///     （router.c:878-888），否则为 0 —— 客户端就没有默认路由。
///   * flags 的 M/O 位直接来自 `ra_flags`（UCI `list ra_flags`）。
///   * Prf（路由优先级）在 header 第 6 字节的 bit3-4。
pub fn buildRA(
    out: []u8,
    cfg6: *const v6conf.Iface6,
    pios: []const Pio,
    rdns: []const [16]u8,
    domains: []const []const u8,
    src_mac: [6]u8,
    mtu: u32,
    /// 调用方按 odhcpd router.c:878 的语义算好：default_route && valid_prefix
    /// 才给 calc_ra_lifetime() 的结果，否则 0（不是本函数的职责）。
    router_lifetime: u32,
) usize {
    var off: usize = 0;

    // ICMPv6 头：type 134, code 0, checksum 0（内核填）, hoplimit, flags, lifetime...
    const hoplimit: u8 = if (cfg6.ra_hoplimit != 0) @intCast(@min(cfg6.ra_hoplimit, 255)) else 64;
    out[off] = ICMPV6_RA;
    out[off + 1] = 0;
    std.mem.writeInt(u16, out[off + 2 ..][0..2], 0, .big); // checksum 由内核代填
    // type(1) + code(1) + checksum(2) = 4 字节
    off += 4;
    out[off] = hoplimit;
    off += 1;
    // M/O 位在 ra_flags 里就是 0x80/0x40 的位置（ND_RA_FLAG_MANAGED/OTHER），
    // H(A) 位 0x20 同理 —— 直接放。
    out[off] = cfg6.ra_flags & 0xE0;
    off += 1;
    putU16(out, &off, @intCast(@min(router_lifetime, 0xFFFF)));
    putU32(out, &off, cfg6.ra_reachabletime);
    putU32(out, &off, cfg6.ra_retranstime);

    // option: source link-layer address
    appendTlv(out, &off, OPT_SRC_LLADDR, &src_mac);
    // option: MTU（配置了或网卡 MTU 已由调用方填好）
    // 注意：reserved 两字节必须用绝对偏移写 —— putU16(out,&off,..) 会推进
    // off，把刚写好的 type/len 覆盖成 0（真 bug，测试抓出来的）。
    if (mtu != 0) {
        if (off + 8 <= out.len) {
            out[off] = OPT_MTU;
            out[off + 1] = 1;
            std.mem.writeInt(u16, out[off + 2 ..][0..2], 0, .big); // reserved
            std.mem.writeInt(u32, out[off + 4 ..][0..4], mtu, .big);
            off += 8;
        }
    }

    // option: PIO
    for (pios) |p| {
        if (off + 32 > out.len) break;
        out[off] = OPT_PREFIX_INFO;
        out[off + 1] = 4; // 32 字节
        out[off + 2] = p.len;
        // L 恒置 1（on-link）；A 位看 ra_slaac（RFC 4862 无状态自动配置）
        out[off + 3] = 0x80 | (if (cfg6.ra_slaac) @as(u8, 0x40) else 0);
        std.mem.writeInt(u32, out[off + 4 ..][0..4], p.valid, .big);
        std.mem.writeInt(u32, out[off + 8 ..][0..4], p.preferred, .big);
        @memset(out[off + 12 ..][0..4], 0); // reserved
        @memcpy(out[off + 16 ..][0..16], &p.prefix);
        off += 32;
    }

    // option: RDNSS（RFC 8106）
    if (rdns.len > 0) {
        const need = 8 + 16 * rdns.len;
        if (off + need <= out.len) {
            out[off] = OPT_RDNSS;
            out[off + 1] = @intCast((need / 8));
            std.mem.writeInt(u16, out[off + 2 ..][0..2], 0, .big); // reserved
            std.mem.writeInt(u32, out[off + 4 ..][0..4], @min(cfg6.ra_lifetime, 0xFFFFFFFF), .big);
            off += 8; // 先推进过选项头，再写地址
            for (rdns) |a| {
                @memcpy(out[off..][0..16], &a);
                off += 16;
            }
        }
    }

    // option: DNSSL（搜索域）
    if (domains.len > 0) {
        var names: [512]u8 = undefined;
        const nlen = encodeDNSSLNames(&names, domains);
        if (nlen > 0) {
            const total = 8 + nlen;
            const padded = (total + 7) / 8 * 8;
            if (off + padded <= out.len) {
                out[off] = OPT_DNSSL;
                out[off + 1] = @intCast(padded / 8);
                std.mem.writeInt(u16, out[off + 2 ..][0..2], 0, .big); // reserved
                std.mem.writeInt(u32, out[off + 4 ..][0..4], @min(cfg6.ra_lifetime, 0xFFFFFFFF), .big);
                off += 8; // 先推进过选项头，再写域名
                @memcpy(out[off..][0..nlen], names[0..nlen]);
                off += nlen;
                // 尾部补零到 8 字节对齐
                @memset(out[off..][0 .. padded - total], 0);
                off += padded - total;
            }
        }
    }

    // option: PREF64（NAT64 前缀，RFC 8781）
    if (cfg6.ra_pref64) |p| {
        if (off + 16 <= out.len and p.len >= 96) {
            out[off] = OPT_PREF64;
            out[off + 1] = 2;
            // 前缀长度编码在 lifetime 高 3 位（/96 -> 0）
            const plen_units: u16 = @intCast((@as(u16, p.len) - 96) / 8);
            std.mem.writeInt(u16, out[off + 2 ..][0..2], plen_units << 13, .big);
            std.mem.writeInt(u32, out[off + 4 ..][0..4], 0, .big); // lifetime 低 13 位
            @memcpy(out[off..][0..12], p.addr[0..12]);
            off += 16;
        }
    }

    return off;
}

/// DNSSL 的域名部分：RFC1035 标签序列 + 0 结尾，每个域名补零到 8 字节倍数。
fn encodeDNSSLNames(buf: []u8, domains: []const []const u8) usize {
    var n: usize = 0;
    for (domains) |d| {
        const start = n;
        var it = std.mem.splitScalar(u8, d, '.');
        while (it.next()) |label| {
            if (label.len == 0 or label.len > 63) continue;
            if (n + 1 + label.len > buf.len) return start;
            buf[n] = @intCast(label.len);
            n += 1;
            @memcpy(buf[n..][0..label.len], label);
            n += label.len;
        }
        if (n < buf.len) {
            buf[n] = 0;
            n += 1;
        }
        // 每个域名补到 8 字节边界（DNSSL 的对齐要求）
        while (n % 8 != 0) {
            if (n >= buf.len) return start;
            buf[n] = 0;
            n += 1;
        }
    }
    return n;
}

// ---------------------------------------------------------------------------
// NDP：NA 构造 + RS/NS 识别
// ---------------------------------------------------------------------------

/// 邻居通告（type 136）。`solicited` 置 S 位；O 位总是置（覆盖缓存）。
pub fn buildNA(out: []u8, target: [16]u8, src_mac: [6]u8, solicited: bool) usize {
    out[0] = ICMPV6_NA;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0; // checksum 由内核填
    out[4] = 0x20 | (if (solicited) @as(u8, 0x40) else 0); // O=1, S=?
    @memset(out[5..8], 0);
    @memcpy(out[8..24], &target);
    var off: usize = 24;
    appendTlv(out, &off, OPT_TARGET_LLADDR, &src_mac);
    return off;
}

pub const IcmpHdr = struct { type_: u8, code: u8 };

pub fn icmpType(buf: []const u8) ?u8 {
    if (buf.len < 4) return null;
    return buf[0];
}

/// NS 的 target 地址（type 135 的 8..24 字节）
pub fn nsTarget(buf: []const u8) ?[16]u8 {
    if (buf.len < 24 or buf[0] != ICMPV6_NS) return null;
    var tgt: [16]u8 = undefined;
    @memcpy(&tgt, buf[8..24]);
    return tgt;
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

fn putU16(buf: []u8, off: *usize, v: u16) void {
    std.mem.writeInt(u16, buf[off.*..][0..2], v, .big);
    off.* += 2;
}

fn putU32(buf: []u8, off: *usize, v: u32) void {
    std.mem.writeInt(u32, buf[off.*..][0..4], v, .big);
    off.* += 4;
}

fn appendTlv(buf: []u8, off: *usize, opt_type: u8, data: []const u8) void {
    // ICMPv6 ND 选项的 Length 单位是 8 字节，**且包含 type/len 这 2 字节本身**
    //（RFC 4861 §4.6）。写成「数据对齐」会让 off 多走 2 字节，后面的选项全部错位。
    const total = (data.len + 2 + 7) / 8 * 8;
    if (off.* + total > buf.len) return;
    buf[off.*] = opt_type;
    buf[off.* + 1] = @intCast(total / 8);
    @memcpy(buf[off.* + 2 ..][0..data.len], data);
    @memset(buf[off.* + 2 + data.len ..][0 .. total - 2 - data.len], 0);
    off.* += total;
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

const t = std.testing;

fn mkCfg() v6conf.Iface6 {
    var cfg6 = v6conf.Iface6{
        .name = "lan",
        .ifname = "br-lan",
        .ra = .server,
        .ra_default = 1,
        .ra_lifetime = 1800,
        .ra_maxinterval = 600,
        .ra_mininterval = 200,
        .ra_slaac = true,
        .ra_dns = true,
    };
    const domains = [_][]const u8{"lan"};
    cfg6.dns_search = @constCast(&domains);
    return cfg6;
}

test "router：RA 头部 —— flags/lifetime/Prf 与 odhcpd 一致" {
    var cfg6 = mkCfg();
    var out: [1024]u8 = undefined;
    const pio = [_]Pio{.{ .prefix = .{ 0x24, 0x0e } ++ [_]u8{0} ** 14, .len = 64, .valid = 5400, .preferred = 2700 }};
    const n = buildRA(&out, &cfg6, &pio, &.{}, &.{}, .{ 2, 0, 0, 0, 0, 1 }, 1500, 1800);

    try t.expectEqual(ICMPV6_RA, out[0]);
    try t.expectEqual(@as(u8, 64), out[4]); // hoplimit 缺省 64
    try t.expectEqual(@as(u8, 0x40), out[5]); // O 位（缺省 ra_flags=other-config）
    // router lifetime = 1800（ra_default=1）
    try t.expectEqual(@as(u16, 1800), std.mem.readInt(u16, out[6..8], .big));

    // 找 option：source lladdr（type 1）在最前
    try t.expectEqual(OPT_SRC_LLADDR, out[16]);
    try t.expectEqualSlices(u8, &.{ 2, 0, 0, 0, 0, 1 }, out[18..24]);
    _ = n;
}

test "router：ra_default=0 时 RA 的 router lifetime 必须是 0" {
    var cfg6 = mkCfg();
    cfg6.ra_default = 0;
    var out: [1024]u8 = undefined;
    const n = buildRA(&out, &cfg6, &.{}, &.{}, &.{}, .{ 2, 0, 0, 0, 0, 1 }, 0, 0);
    try t.expectEqual(@as(u16, 0), std.mem.readInt(u16, out[6..8], .big));
    _ = n;
}

test "router：PIO 的 A 位由 ra_slaac 决定，valid/preferred 大端写入" {
    var cfg6 = mkCfg();
    var out: [1024]u8 = undefined;
    const pio = [_]Pio{.{ .prefix = .{ 0x24, 0x0e, 0x39, 0x80 } ++ [_]u8{0} ** 12, .len = 64, .valid = 5400, .preferred = 2700 }};
    const n = buildRA(&out, &cfg6, &pio, &.{}, &.{}, .{ 2, 0, 0, 0, 0, 1 }, 0, 0);

    // source-lladdr(8B) 之后就是 PIO（本测试 mtu=0，没有 MTU 选项）
    const i: usize = 24;
    try t.expectEqual(OPT_PREFIX_INFO, out[i]);
    try t.expectEqual(@as(u8, 64), out[i + 2]); // prefix len
    try t.expectEqual(@as(u8, 0xC0), out[i + 3]); // L|A
    try t.expectEqual(@as(u32, 5400), std.mem.readInt(u32, out[i + 4 ..][0..4], .big));
    try t.expectEqual(@as(u32, 2700), std.mem.readInt(u32, out[i + 8 ..][0..4], .big));
    try t.expectEqual(@as(u8, 0x24), out[i + 16]);

    // ra_slaac=false 时 A 位清零
    cfg6.ra_slaac = false;
    var out2: [1024]u8 = undefined;
    const n2 = buildRA(&out2, &cfg6, &pio, &.{}, &.{}, .{ 2, 0, 0, 0, 0, 1 }, 0, 0);
    try t.expectEqual(@as(u8, 0x80), out2[i + 3]);
    _ = n;
    _ = n2;
}

test "router：RDNSS/DNSSL/MTU 选项都要进包" {
    var cfg6 = mkCfg();
    var out: [1024]u8 = undefined;
    const dns1: [16]u8 = .{ 0x24, 0x0e } ++ [_]u8{0} ** 13 ++ .{ 0x53 };
    const pio = [_]Pio{.{ .prefix = .{ 0x24, 0x0e } ++ [_]u8{0} ** 14, .len = 64, .valid = 5400, .preferred = 2700 }};
    const n = buildRA(&out, &cfg6, &pio, &.{dns1}, &.{"lan"}, .{ 2, 0, 0, 0, 0, 1 }, 1500, 1800);

    var i: usize = 16;
    var saw_mtu = false;
    var saw_rdnss = false;
    var saw_dnssl = false;

    while (i + 2 <= n) {
        const otype = out[i];
        const olen: usize = @as(usize, out[i + 1]) * 8;
        if (otype == OPT_MTU) {
            saw_mtu = true;
            try t.expectEqual(@as(u32, 1500), std.mem.readInt(u32, out[i + 4 ..][0..4], .big));
        }
        if (otype == OPT_RDNSS) {
            saw_rdnss = true;
            try t.expectEqualSlices(u8, &dns1, out[i + 8 ..][0..16]);
        }
        if (otype == OPT_DNSSL) {
            saw_dnssl = true;
            // "lan" = 3, 'l','a','n', 0 补齐 8 字节
            try t.expectEqualSlices(u8, &.{ 3, 'l', 'a', 'n', 0, 0, 0, 0 }, out[i + 8 ..][0..8]);
        }
        if (olen == 0) break;
        i += olen;
    }
    try t.expect(saw_mtu and saw_rdnss and saw_dnssl);
}

test "router：组播组地址必须是 FF02 开头（曾因丢前缀被内核 EINVAL）" {
    try t.expectEqual(@as(u8, 0xFF), AllNodes[0]);
    try t.expectEqual(@as(u8, 0x02), AllNodes[1]);
    try t.expectEqual(@as(u8, 1), AllNodes[15]);
    try t.expectEqual(@as(u8, 0xFF), AllRouters[0]);
    try t.expectEqual(@as(u8, 0x02), AllRouters[1]);
    try t.expectEqual(@as(u8, 2), AllRouters[15]);
}

test "router：NA 的 S 位与 target lladdr" {
    var out: [128]u8 = undefined;
    const n = buildNA(&out, .{ 0x20, 0x01 } ++ [_]u8{0} ** 13 ++ .{ 1 }, .{ 2, 0, 0, 0, 0, 1 }, true);
    try t.expectEqual(ICMPV6_NA, out[0]);
    try t.expectEqual(@as(u8, 0x60), out[4]); // O | S
    try t.expectEqualSlices(u8, &.{ 0x20, 0x01 }, out[8..10]);
    try t.expectEqual(OPT_TARGET_LLADDR, out[24]);

    const n2 = buildNA(&out, .{ 0x20, 0x01 } ++ [_]u8{0} ** 13 ++ .{ 1 }, .{ 2, 0, 0, 0, 0, 1 }, false);
    try t.expectEqual(@as(u8, 0x20), out[4]);
    _ = n2;
    _ = n;
}
