// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! v6conf.zig —— DHCPv6 / RA / NDP 的配置模型。
//!
//! ## 定位
//!
//! 这一层**只描述配置，不碰 socket**：字段与取值逐条对齐 odhcpd
//! `config.c` 的 `iface_attrs[]`（第 100-198 行，v6 那一半）与
//! `set_interface_defaults()`（config.c:308-342）。真正的发 RA、答 DHCPv6
//! 在 `router.zig` / `dhcpv6.zig` 里，它们只读这里的结构体。
//!
//! 之所以单独成文件：v6 的选项数量是 v4 的三倍多（LuCI 的「IPv6 设置」页
//! 一屏放不下），塞进 `odhcpd_main.Config` 会让 v4 那部分难以阅读；而且
//! 这样 v6 的取值/夹取规则可以纯函数化、逐条单测。
//!
//! ## 必须复刻的几处「看起来像 bug」的行为
//!
//! * **`ra_default` 缺省是 0，不是 1**：`set_interface_defaults()` 根本没碰
//!   `default_router`，而 `router.c:878` 只有 `default_route && valid_prefix`
//!   才填 `nd_ra_router_lifetime`。也就是说不写 `option ra_default '1'` 时
//!   RA 里的 router lifetime 就是 0 —— 照抄，不加「贴心默认值」，否则我们
//!   会和 odhcpd 在同一个 UCI 上表现不同。
//! * **所有时间参数都要夹取**（RFC4861 §6.2.1）：MaxRtrAdvInterval 限
//!   4..1800，MinRtrAdvInterval 限 3..0.75*max，AdvReachableTime 限
//!   3600000，AdvRetransTimer 限 60000，AdvCurHopLimit 限 255。
//!   夹取而不是报错，与 odhcpd 一致（它只 warn 一句）。
//! * **`ra_mininterval` 的缺省依赖 `ra_maxinterval`**
//!   （config.c:335-339）：改了 max 之后 min 要跟着重算，否则会出现
//!   min > max 这种 RFC 明确禁止的组合。见 `clampIntervals()`。

const std = @import("std");
const addr = @import("addr.zig");

// ---------------------------------------------------------------------------
// 服务模式（ra / dhcpv6 / ndp 三个开关共用同一套取值）
// ---------------------------------------------------------------------------

/// odhcpd `odhcpd.h:184-189` 的 `MODE_*`。
pub const Mode = enum(u8) {
    disabled = 0,
    server = 1,
    relay = 2,
    hybrid = 3,
};

/// config.c:390-402 的 `parse_mode()`：只认这四个词，别的都算配置错误。
pub fn modeOf(text: []const u8) ?Mode {
    if (std.mem.eql(u8, text, "disabled")) return .disabled;
    if (std.mem.eql(u8, text, "server")) return .server;
    if (std.mem.eql(u8, text, "relay")) return .relay;
    if (std.mem.eql(u8, text, "hybrid")) return .hybrid;
    return null;
}

// ---------------------------------------------------------------------------
// RA 标志位（RFC4861 §4.2 的 8 位 flags）
// ---------------------------------------------------------------------------

pub const RA_FLAG_MANAGED: u8 = 0x80; // M 位：地址也走 DHCPv6
pub const RA_FLAG_OTHER: u8 = 0x40; // O 位：只有其它配置走 DHCPv6
pub const RA_FLAG_HOME_AGENT: u8 = 0x20; // RFC3775

/// config.c:275-281 的 `ra_flags[]` 表。注意 UCI 里写的是 `managed-config`
/// 而不是 `managed`（LuCI 下拉框里是「M 标记」「O 标记」）。
/// `none` 是显式清零用的哨兵，值为 0。
pub fn raFlagOf(text: []const u8) ?u8 {
    if (std.mem.eql(u8, text, "managed-config")) return RA_FLAG_MANAGED;
    if (std.mem.eql(u8, text, "other-config")) return RA_FLAG_OTHER;
    if (std.mem.eql(u8, text, "home-agent")) return RA_FLAG_HOME_AGENT;
    if (std.mem.eql(u8, text, "none")) return 0;
    return null;
}

/// 路由优先级（RA 头里的 Prf 字段）。config.c:1702-1712。
/// `default` 与 `medium` 同义 —— 老配置里两种写法都有。
pub const RoutePreference = enum(i8) {
    low = -1,
    medium = 0,
    high = 1,
};

pub fn preferenceOf(text: []const u8) ?RoutePreference {
    if (std.mem.eql(u8, text, "high")) return .high;
    if (std.mem.eql(u8, text, "low")) return .low;
    if (std.mem.eql(u8, text, "medium") or std.mem.eql(u8, text, "default")) return .medium;
    return null;
}

// ---------------------------------------------------------------------------
// 夹取常量（router.h / config.c）
// ---------------------------------------------------------------------------

pub const ADV_REACHABLE_TIME: u32 = 3_600_000; // router.h:74
pub const RETRANS_TIMER_MAX: u32 = 60_000; // router.h:87
pub const ADV_CUR_HOP_LIMIT: u32 = 255; // RFC4861 的 8 位字段上限
pub const MAX_RTR_ADV_INTERVAL: u32 = 1800; // RFC4861
pub const MIN_RTR_ADV_INTERVAL: u32 = 4;
pub const RA_MTU_MIN: u32 = 1280; // IPv6 最小 MTU
pub const RA_MTU_MAX: u32 = 65535;

pub const ND_PREFERRED_LIMIT: u32 = 2700; // odhcpd.h:51
pub const ND_VALID_LIMIT: u32 = 5400; // odhcpd.h:52
pub const PD_MIN_LEN_DEFAULT: u8 = 62; // config.c:73
pub const PD_MIN_LEN_MAX: u8 = 64; // config.c:72
pub const HOSTID_LEN_MIN: u8 = 12; // config.c:68
pub const HOSTID_LEN_MAX: u8 = 64; // config.c:69

pub const RA_MAXINTERVAL_DEFAULT: u32 = 600; // config.c:334

pub fn clampRaMtu(v: u32, if_mtu: u32) u32 {
    var m = v;
    if (m < RA_MTU_MIN) m = RA_MTU_MIN;
    if (m > RA_MTU_MAX) m = RA_MTU_MAX;
    if (if_mtu != 0 and m > if_mtu) m = if_mtu;
    return m;
}

/// 把 min/max 两个间隔一起夹回 RFC4861 的合法区间，并按
/// config.c:335-339 的规则重算缺省的 min。
pub fn clampIntervals(min_in: ?u32, max_in: ?u32) struct { min: u32, max: u32 } {
    var max: u32 = RA_MAXINTERVAL_DEFAULT;
    if (max_in) |v| {
        max = v;
        if (max < MIN_RTR_ADV_INTERVAL) max = MIN_RTR_ADV_INTERVAL;
        if (max > MAX_RTR_ADV_INTERVAL) max = MAX_RTR_ADV_INTERVAL;
    }

    if (min_in) |v| {
        var min = v;
        if (min < 3) min = 3;
        // MinRtrAdvInterval MUST be no greater than .75 * MaxRtrAdvInterval
        const ceiling = (max * 3) / 4;
        if (min > ceiling) min = ceiling;
        return .{ .min = min, .max = max };
    }
    // 缺省：MaxRtrAdvInterval >= 9 时取 0.33*max，否则取 max
    return .{ .min = if (max >= 9) max / 3 else max, .max = max };
}

/// `addr/len` 形式的前缀（`prefix_filter`、`ra_pref64` 都用它）。
pub const Prefix6 = struct {
    addr: [16]u8 = [_]u8{0} ** 16,
    len: u8 = 0,
};

pub fn parsePrefix6(text: []const u8) ?Prefix6 {
    const slash = std.mem.indexOfScalar(u8, text, '/') orelse return null;
    var out: [16]u8 = [_]u8{0} ** 16;
    if (!addr.parseIp6(text[0..slash], &out)) return null;
    const len = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch return null;
    if (len > 128) return null;
    return .{ .addr = out, .len = len };
}

// ---------------------------------------------------------------------------
// 接口级 v6 配置
// ---------------------------------------------------------------------------

pub const Iface6 = struct {
    /// 逻辑接口名（`lan`）
    name: []const u8 = "",
    /// 设备名（`br-lan`）—— 绑 socket、取地址都用它
    ifname: []const u8 = "",

    // ---- 三个总开关（缺省全关，config.c:313-315） ----
    ra: Mode = .disabled,
    dhcpv6: Mode = .disabled,
    ndp: Mode = .disabled,

    // ---- RA ----
    /// 直接进 RA 头的 8 位 flags。缺省 `other-config`（config.c:336）
    ra_flags: u8 = RA_FLAG_OTHER,
    ra_slaac: bool = true,
    /// UCI `ra_offlink` → odhcpd 内部字段名是 `ra_not_onlink`（config.c:1577）
    ra_offlink: bool = false,
    ra_advrouter: bool = false,
    ra_preference: RoutePreference = .medium,
    /// UCI `ra_default`：缺省 0。**注意**：0 不等于「永不宣告默认路由」——
    /// odhcpd router.c:716 在 ra_default=0 时也会 parse_routes() 扫
    /// /proc/net/ipv6_route，系统有非 lo 的 IPv6 默认路由就宣告
    /// （lifetime 见 router.c:878 与 v6rt.calcRaLifetime）。>1 额外强制
    /// valid_prefix（无公网前缀也宣告）。（router.c:701-705）
    ra_default: u32 = 0,
    ra_mininterval: u32 = 200,
    ra_maxinterval: u32 = RA_MAXINTERVAL_DEFAULT,
    ra_lifetime: u32 = 1800,
    ra_reachabletime: u32 = 0,
    ra_retranstime: u32 = 0,
    ra_hoplimit: u32 = 0,
    ra_mtu: u32 = 0,
    ra_dns: bool = true,
    /// RFC8781 PREF64（NAT64 前缀，通常 /96）
    ra_pref64: ?Prefix6 = null,

    // ---- DHCPv6 ----
    dhcpv6_assignall: bool = true,
    dhcpv6_pd: bool = true,
    dhcpv6_pd_preferred: bool = false,
    dhcpv6_pd_min_len: u8 = PD_MIN_LEN_DEFAULT,
    dhcpv6_na: bool = true,
    dhcpv6_hostid_len: u8 = HOSTID_LEN_MIN,
    /// UCI `dhcpv6_raw`：原样下发的十六进制选项串（PXE 等场景）
    dhcpv6_raw: ?[]const u8 = null,
    max_preferred_lifetime: u32 = ND_PREFERRED_LIMIT,
    max_valid_lifetime: u32 = ND_VALID_LIMIT,

    // ---- NDP ----
    /// UCI `ndproxy_routing` → odhcpd 的 `learn_routes`（config.c:1718）
    ndproxy_routing: bool = true,
    /// UCI `ndproxy_slave` → odhcpd 的 `external`（config.c:1721）
    ndproxy_slave: bool = false,
    ndp_from_link_local: bool = true,
    /// UCI `prefix_filter`：只宣告匹配该前缀的 PIO
    pio_filter: ?Prefix6 = null,

    // ---- 下发给客户端的选项 ----
    /// `list dns`（v6 地址）
    dns: [][16]u8 = &.{},
    /// `list domain`（DNS 搜索域，odhcpd 里叫 dns_search）
    dns_search: [][]const u8 = &.{},
    /// `list ntp`（v6 地址；v4 地址也要收，odhcpd 两个数组分开存）
    ntp: [][16]u8 = &.{},
    dns_service: bool = true,

    /// 三个开关全关的段不用起任何 socket —— odhcpd 里这就是 `ignore`
    pub fn anyEnabled(self: *const Iface6) bool {
        return self.ra != .disabled or self.dhcpv6 != .disabled or self.ndp != .disabled;
    }
};

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

const t = std.testing;

test "v6conf：模式串只认 odhcpd 那四个词" {
    try t.expectEqual(Mode.server, modeOf("server").?);
    try t.expectEqual(Mode.relay, modeOf("relay").?);
    try t.expectEqual(Mode.hybrid, modeOf("hybrid").?);
    try t.expectEqual(Mode.disabled, modeOf("disabled").?);
    try t.expectEqual(@as(?Mode, null), modeOf("Server")); // 大小写敏感
    try t.expectEqual(@as(?Mode, null), modeOf(""));
}

test "v6conf：ra_flags 用的是 managed-config / other-config 写法" {
    try t.expectEqual(@as(u8, 0x80), raFlagOf("managed-config").?);
    try t.expectEqual(@as(u8, 0x40), raFlagOf("other-config").?);
    try t.expectEqual(@as(u8, 0x20), raFlagOf("home-agent").?);
    try t.expectEqual(@as(u8, 0), raFlagOf("none").?);
    try t.expectEqual(@as(?u8, null), raFlagOf("managed")); // 不是 UCI 里的写法
}

test "v6conf：路由优先级 default 与 medium 同义" {
    try t.expectEqual(RoutePreference.high, preferenceOf("high").?);
    try t.expectEqual(RoutePreference.low, preferenceOf("low").?);
    try t.expectEqual(RoutePreference.medium, preferenceOf("medium").?);
    try t.expectEqual(RoutePreference.medium, preferenceOf("default").?);
    try t.expectEqual(@as(?RoutePreference, null), preferenceOf("High"));
}

test "v6conf：RA 间隔必须夹回 RFC4861 的区间，且 min 不能超 0.75*max" {
    // 缺省 600 -> min = 600/3 = 200
    const d = clampIntervals(null, null);
    try t.expectEqual(@as(u32, 600), d.max);
    try t.expectEqual(@as(u32, 200), d.min);

    // max 过小/过大都要夹
    try t.expectEqual(@as(u32, 4), clampIntervals(null, 1).max);
    try t.expectEqual(@as(u32, 1800), clampIntervals(null, 99999).max);

    // max 改小后，缺省 min 跟着重算（否则会 min > max）
    const small = clampIntervals(null, 60);
    try t.expectEqual(@as(u32, 60), small.max);
    try t.expectEqual(@as(u32, 20), small.min);

    // 显式 min 太大时夹到 0.75*max
    const big = clampIntervals(500, 600);
    try t.expectEqual(@as(u32, 450), big.min);
    // 显式 min 太小
    try t.expectEqual(@as(u32, 3), clampIntervals(0, 600).min);
}

test "v6conf：RA MTU 夹在 1280..65535，且不超过网卡 MTU" {
    try t.expectEqual(@as(u32, 1280), clampRaMtu(100, 1500));
    try t.expectEqual(@as(u32, 65535), clampRaMtu(70000, 0));
    try t.expectEqual(@as(u32, 1500), clampRaMtu(9000, 1500));
    try t.expectEqual(@as(u32, 1480), clampRaMtu(1480, 1500));
}

test "v6conf：前缀文本解析" {
    const p = parsePrefix6("2001:db8:1::/64").?;
    try t.expectEqual(@as(u8, 64), p.len);
    try t.expectEqual(@as(u8, 0x20), p.addr[0]);
    try t.expectEqual(@as(u8, 0x01), p.addr[1]);
    try t.expectEqual(@as(?Prefix6, null), parsePrefix6("2001:db8::")); // 缺 /len
    try t.expectEqual(@as(?Prefix6, null), parsePrefix6("2001:db8::/129")); // 超出 128
    try t.expectEqual(@as(?Prefix6, null), parsePrefix6("not-an-ip/64"));
}

test "v6conf：默认值必须与 set_interface_defaults 一致" {
    var i = Iface6{};
    try t.expectEqual(Mode.disabled, i.ra);
    try t.expectEqual(Mode.disabled, i.dhcpv6);
    try t.expectEqual(Mode.disabled, i.ndp);
    try t.expect(!i.anyEnabled());
    try t.expectEqual(@as(u8, RA_FLAG_OTHER), i.ra_flags);
    try t.expect(i.ra_slaac);
    try t.expect(i.ra_dns);
    try t.expect(i.dhcpv6_assignall);
    try t.expect(i.dhcpv6_pd);
    try t.expect(i.dhcpv6_na);
    try t.expectEqual(@as(u8, 62), i.dhcpv6_pd_min_len);
    try t.expectEqual(@as(u8, 12), i.dhcpv6_hostid_len);
    try t.expectEqual(@as(u32, 2700), i.max_preferred_lifetime);
    try t.expectEqual(@as(u32, 5400), i.max_valid_lifetime);
    try t.expect(i.ndproxy_routing);
    try t.expect(i.ndp_from_link_local);
    try t.expectEqual(@as(u32, 600), i.ra_maxinterval);
    try t.expectEqual(@as(u32, 200), i.ra_mininterval);
    try t.expectEqual(@as(u32, 1800), i.ra_lifetime);
    // ra_default 缺省必须是 0：这是 odhcpd 的真实行为，别「贴心」地改成 1
    //（0 时是否宣告默认路由由运行时按系统路由自动判定，见 v6rt）
    try t.expectEqual(@as(u32, 0), i.ra_default);

    i.ra = .server;
    try t.expect(i.anyEnabled());
}
