// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! dhcp.zig — DHCP 数据结构层，对应 C 源码 src/dnsmasq.h 里的 struct 定义。
//!
//! 本文件只放**结构与常量**，不放协议逻辑。这样阶段 2（配置解析）、
//! 阶段 3（rfc2131 报文）、阶段 4（运行时）都能直接复用，且不引入网络依赖。
//!
//! 对照关系（dnsmasq.h 行号）：
//!   struct dhcp_lease    864   -> DhcpLease
//!   struct dhcp_netid    898   -> DhcpNetid
//!   struct dhcp_netid_list 903 -> DhcpNetidList
//!   struct hwaddr_config 920   -> HwaddrConfig
//!   struct dhcp_config   927   -> DhcpConfig
//!   struct dhcp_opt      959   -> DhcpOpt
//!   struct dhcp_boot     988   -> DhcpBoot
//!   struct dhcp_vendor  1019   -> DhcpVendor
//!   struct dhcp_context 1062   -> DhcpContext
//!   struct dhcp_relay   1152   -> DhcpRelay
//!
//! 与 C 的差异（有意为之）：
//!   * C 用 `union all_addr` 同时装 v4/v6 地址；这里沿用本移植已有的
//!     `addr.AllAddr`，与 cache.zig 保持一致，避免第二套地址表示。
//!   * C 的 `struct dhcp_context` 把 v4/v6 字段混在一起（靠 `#ifdef HAVE_DHCP6`
//!     和运行时的 addr6 是否为零来区分）；这里保留同一结构，但 v6 字段
//!     在阶段 5 之前不会被读取。
//!   * 链表的 `next` 指针保留（与 C 一致），顺序语义依赖它，不要改成动态数组。

const std = @import("std");
const addr = @import("addr.zig");

/// 对应 dnsmasq.h 的 DHCP_CHADDR_MAX（链路层地址最大长度）。
/// 16 字节足够 Ethernet(6) / InfiniBand(20 会截断) / 各种隧道头。
pub const DHCP_CHADDR_MAX = 16;

/// Linux 的 ARPHRD_ETHER。dnsmasq 用它判断「租约文件里是否要写显式硬件类型」。
pub const ARPHRD_ETHER = 1;

/// BOOTP 各字段长度（对应 dnsmasq.h 的 BOOTREQUEST 附近定义）
pub const BOOTP_REQUEST = 1;
pub const BOOTP_REPLY = 2;

pub const DHCP_SERVER_PORT = 67;
pub const DHCP_CLIENT_PORT = 68;
pub const DHCPV6_SERVER_PORT = 547;
pub const DHCPV6_CLIENT_PORT = 546;

/// 租约标志位 —— 逐条对照 dnsmasq.h:848-856。
///
/// 注意：2.93 里**只有这 9 个** LEASE_* 位。历史上出现过的 `LEASE_TEMP`、
/// `LEASE_DECLINED`，以及 CLID/HOSTNAME/FQDN 的「HAVE_*」位在本版本中
/// **不存在** —— 那些信息由 `lease->clid`/`hostname` 是否为空、以及
/// `dhcp_config` 的 `CONFIG_DECLINED` 表达。之前按印象猜过一组十六进制值，
/// 已按 dnsmasq.h 修正（差值会静默影响租约文件解析与 DNS 名字注入）。
pub const LEASE_NEW: u32 = 1; // 新建
pub const LEASE_CHANGED: u32 = 2; // 有实质修改
pub const LEASE_AUX_CHANGED: u32 = 4; // CLID 或到期时间变了
pub const LEASE_AUTH_NAME: u32 = 8; // 名字来自配置而非客户端
pub const LEASE_USED: u32 = 16; // 本轮 DHCPv6 事务里用过
pub const LEASE_NA: u32 = 32; // IPv6 非临时租约（唯一标识 v6 租约）
pub const LEASE_TA: u32 = 64; // IPv6 临时租约（唯一标识 v6 租约）
pub const LEASE_HAVE_HWADDR: u32 = 128; // hwaddr 字段有效
pub const LEASE_EXP_CHANGED: u32 = 256; // 到期时间被改写

/// `dhcp_context` 的标志位 —— 对照 dnsmasq.h:1090-1109。
///
/// 全部是 `1u << n` 的位号形式（不是顺序十六进制！），n 从 0 到 19 连续。
/// 之前按 0x0001..0x8000 顺序编号写错过，这里按源码逐条对齐。
pub const CONTEXT_STATIC: u32 = 1 << 0;
pub const CONTEXT_NETMASK: u32 = 1 << 1;
pub const CONTEXT_BRDCAST: u32 = 1 << 2; // 注意 C 里是 BRDCAST，不是 BROADCAST
pub const CONTEXT_PROXY: u32 = 1 << 3;
pub const CONTEXT_RA_ROUTER: u32 = 1 << 4;
pub const CONTEXT_RA_DONE: u32 = 1 << 5;
pub const CONTEXT_RA_NAME: u32 = 1 << 6;
pub const CONTEXT_RA_STATELESS: u32 = 1 << 7;
pub const CONTEXT_DHCP: u32 = 1 << 8;
pub const CONTEXT_DEPRECATE: u32 = 1 << 9;
pub const CONTEXT_TEMPLATE: u32 = 1 << 10; // 由地址生成池
pub const CONTEXT_CONSTRUCTED: u32 = 1 << 11;
pub const CONTEXT_GC: u32 = 1 << 12;
pub const CONTEXT_RA: u32 = 1 << 13;
pub const CONTEXT_CONF_USED: u32 = 1 << 14;
pub const CONTEXT_USED: u32 = 1 << 15;
pub const CONTEXT_OLD: u32 = 1 << 16;
pub const CONTEXT_V6: u32 = 1 << 17;
pub const CONTEXT_RA_OFF_LINK: u32 = 1 << 18;
pub const CONTEXT_SETLEASE: u32 = 1 << 19;

/// dhcp_config 的 flags（dnsmasq.h:946-957）
pub const CONFIG_DISABLE: u32 = 1;
pub const CONFIG_CLID: u32 = 2;
pub const CONFIG_TIME: u32 = 8;
pub const CONFIG_NAME: u32 = 16;
pub const CONFIG_ADDR: u32 = 32;
pub const CONFIG_NOCLID: u32 = 128;
pub const CONFIG_FROM_ETHERS: u32 = 256;
pub const CONFIG_ADDR_HOSTS: u32 = 512;
pub const CONFIG_DECLINED: u32 = 1024;
pub const CONFIG_BANK: u32 = 2048;
pub const CONFIG_ADDR6: u32 = 4096;
pub const CONFIG_ADDR6_HOSTS: u32 = 16384;

/// dhcp_opt 的 flags（dnsmasq.h:971-986）
pub const DHOPT_ADDR: u32 = 1;
pub const DHOPT_STRING: u32 = 2;
pub const DHOPT_ENCAPSULATE: u32 = 4;
pub const DHOPT_ENCAP_MATCH: u32 = 8;
pub const DHOPT_FORCE: u32 = 16;
pub const DHOPT_BANK: u32 = 32;
pub const DHOPT_ENCAP_DONE: u32 = 64;
pub const DHOPT_MATCH: u32 = 128;
pub const DHOPT_VENDOR: u32 = 256;
pub const DHOPT_HEX: u32 = 512;
pub const DHOPT_VENDOR_MATCH: u32 = 1024;
pub const DHOPT_RFC3925: u32 = 2048;
pub const DHOPT_TAGOK: u32 = 4096;
pub const DHOPT_ADDR6: u32 = 8192;
pub const DHOPT_VENDOR_PXE: u32 = 16384;
pub const DHOPT_PXE_OPT: u32 = 32768;

/// `have_config(config, mask)`（dnsmasq.h:944）
pub fn haveConfig(config: ?*const DhcpConfig, mask: u32) bool {
    const c = config orelse return false;
    return (c.flags & mask) != 0;
}

/// 一条 DHCP 租约。对应 `struct dhcp_lease`（dnsmasq.h:864）。
///
/// 字段分组与 C 一致：先是客户端标识与名字，再是硬件地址，再是地址与
/// 扩展数据，最后是 DHCPv6 部分。
pub const DhcpLease = struct {
    clid_len: i32 = 0,
    clid: ?[]u8 = null,

    /// 客户端通过 option 12 上报的主机名
    hostname: ?[]u8 = null,
    /// hostname + --domain 拼出的全限定名（lease_calc_fqdns 维护）
    fqdn: ?[]u8 = null,
    /// 租约被转移到别的地址前的旧主机名（lease.c 用它把 DNS 里的旧名字清掉）
    old_hostname: ?[]u8 = null,

    flags: u32 = 0,
    /// 到期时刻（dnsmasqTime() 基准，即墙钟秒）
    expires: i64 = 0,

    hwaddr_len: i32 = 0,
    hwaddr_type: i32 = 0,
    hwaddr: [DHCP_CHADDR_MAX]u8 = [_]u8{0} ** DHCP_CHADDR_MAX,

    /// IPv4 地址，网络字节序（与 `addr.AllAddr` 的 ip4 一致）
    addr4: u32 = 0,
    /// 客户端显式请求过的地址（option 50 requested-ip）
    override4: u32 = 0,
    /// 中继场景下 BOOTP 的 giaddr
    giaddr: u32 = 0,

    extradata: ?[]u8 = null,

    /// 收到该租约请求的接口 ifindex
    last_interface: i32 = 0,
    /// 「可能发起方」接口（DHCPv6 用）
    new_interface: i32 = 0,
    new_prefixlen: i32 = 0,

    agent_id: ?[]u8 = null,
    vendorclass: ?[]u8 = null,

    // ---------------- DHCPv6（阶段 5 才会读取）----------------
    addr6: [16]u8 = [_]u8{0} ** 16,
    iaid: u32 = 0,
    vendorclass_count: i32 = 0,

    next: ?*DhcpLease = null,

    /// 该租约是否为 v4（对照 C 里 `lease->flags & (LEASE_TA|LEASE_NA)` 的反面）
    pub fn isV4(self: *const DhcpLease) bool {
        return (self.flags & (LEASE_NA | LEASE_TA)) == 0;
    }

    pub fn isV6(self: *const DhcpLease) bool {
        return (self.flags & (LEASE_NA | LEASE_TA)) != 0;
    }
};

/// 对应 `struct dhcp_netid`（dnsmasq.h:898）：单个 tag。
pub const DhcpNetid = struct {
    net: []const u8,
    next: ?*DhcpNetid = null,
};

/// 对应 `struct dhcp_netid_list`（dnsmasq.h:903）：给配置项挂一组 tag。
pub const DhcpNetidList = struct {
    list: ?*DhcpNetid = null,
    next: ?*DhcpNetidList = null,
};

/// 对应 `struct tag_if`（dnsmasq.h:908）
pub const TagIf = struct {
    set: ?*DhcpNetidList = null,
    tag: ?*DhcpNetid = null,
    next: ?*TagIf = null,
};

/// 对应 `struct delay_config`（dnsmasq.h:914）
pub const DelayConfig = struct {
    delay: i32 = 0,
    netid: ?*DhcpNetid = null,
    next: ?*DelayConfig = null,
};

/// 对应 `struct hwaddr_config`（dnsmasq.h:920）：
/// 一条 `--dhcp-host=00:11:22:*:*:*` 里的硬件地址匹配条件。
pub const HwaddrConfig = struct {
    hwaddr_len: i32 = 0,
    hwaddr_type: i32 = 0,
    hwaddr: [DHCP_CHADDR_MAX]u8 = [_]u8{0} ** DHCP_CHADDR_MAX,
    /// 位掩码：bit i 置位表示 hwaddr[i] 是 `*` 通配。
    /// 注意 C 的位移方向是「从最低位开始」，与 util.memcmpMasked 的约定一致。
    wildcard_mask: u32 = 0,
    next: ?*HwaddrConfig = null,
};

/// 对应 `struct dhcp_config`（dnsmasq.h:927）：一条 `--dhcp-host=` 规则。
pub const DhcpConfig = struct {
    flags: u32 = 0,
    clid_len: i32 = 0,
    clid: ?[]u8 = null,
    hostname: ?[]u8 = null,
    domain: ?[]u8 = null,
    netid: ?*DhcpNetidList = null,
    filter: ?*DhcpNetid = null,
    addr6: ?*DhcpNetidList = null, // C 是 struct addrlist*，阶段 5 再补
    addr4: u32 = 0,
    decline_time: i64 = 0,
    lease_time: u32 = 0,
    hwaddr: ?*HwaddrConfig = null,
    next: ?*DhcpConfig = null,
};

/// 对应 `struct dhcp_opt`（dnsmasq.h:959）：一条 `--dhcp-option=` 规则。
pub const DhcpOpt = struct {
    opt: i32 = 0,
    len: i32 = 0,
    flags: u32 = 0,
    /// C 里是 union { int encap; unsigned int wildcard_mask; unsigned char *vendor_class; }
    /// u_encap / u_wildcard_mask 二选一，vendor_class 用独立字段承载。
    u_encap: i32 = 0,
    u_wildcard_mask: u32 = 0,
    vendor_class: ?[]u8 = null,
    val: ?[]u8 = null,
    netid: ?*DhcpNetid = null,
    next: ?*DhcpOpt = null,
};

/// 对应 `struct dhcp_boot`（dnsmasq.h:988）：`--dhcp-boot=` 规则。
pub const DhcpBoot = struct {
    file: ?[]const u8 = null,
    sname: ?[]const u8 = null,
    tftp_sname: ?[]const u8 = null,
    next_server: u32 = 0,
    netid: ?*DhcpNetid = null,
    next: ?*DhcpBoot = null,
};

/// 对应 `struct dhcp_vendor`（dnsmasq.h:1019）：`--dhcp-vendorclass=` 规则。
pub const DhcpVendor = struct {
    vendor_class: ?[]const u8 = null,
    netid: ?*DhcpNetid = null,
    next: ?*DhcpVendor = null,
};

/// 对应 `struct dhcp_context`（dnsmasq.h:1062）：一个地址池
/// （`--dhcp-range=` 或 `--dhcp-range=::` 得到的东西）。
///
/// v4 字段在阶段 2/4 使用；v6 字段（start6/end6/prefix 等）阶段 5 再启用。
pub const DhcpContext = struct {
    flags: u32 = 0,

    // ---------------- 地址池 ----------------
    start4: u32 = 0,
    end4: u32 = 0,
    netmask4: u32 = 0,
    broadcast4: u32 = 0,
    router4: u32 = 0,

    /// 网络字节序的 v6 起止地址（阶段 5）
    start6: [16]u8 = [_]u8{0} ** 16,
    end6: [16]u8 = [_]u8{0} ** 16,
    prefix: i32 = 0,

    /// 模板池（`--dhcp-range=tag:x,constructor:...`）指向的源池
    template_interface: ?[]const u8 = null,

    /// --dhcp-range 上带的 tag
    netid: ?*DhcpNetid = null,
    filter: ?*DhcpNetid = null,
    local: ?*DhcpNetid = null,

    /// 该池绑定的名字（--interface 或构造器给出的名字）
    interface: ?[]const u8 = null,
    /// 该池适用的接口 ifindex（0 表示不限）
    if_index: i32 = 0,

    lease_time: u32 = 0,

    /// 池标签（用于日志与模板匹配）
    label: ?[]const u8 = null,

    next: ?*DhcpContext = null,
};

/// 对应 `struct dhcp_relay`（dnsmasq.h:1152）
pub const DhcpRelay = struct {
    local: addr.AllAddr = .{ .none = {} },
    server: u32 = 0,
    interface: ?[]const u8 = null,
    next: ?*DhcpRelay = null,
};

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

test "dhcp：v4/v6 租约判定与 LEASE_* 位一致" {
    var l = DhcpLease{};
    try std.testing.expect(l.isV4());
    try std.testing.expect(!l.isV6());

    l.flags = LEASE_NA;
    try std.testing.expect(!l.isV4());
    try std.testing.expect(l.isV6());

    l.flags = LEASE_TA | LEASE_HAVE_HWADDR;
    try std.testing.expect(l.isV6());
}

test "dhcp：have_config 空指针与掩码语义（对照 C 的 have_config 宏）" {
    try std.testing.expect(!haveConfig(null, CONFIG_ADDR));

    var c = DhcpConfig{};
    try std.testing.expect(!haveConfig(&c, CONFIG_ADDR));

    c.flags = CONFIG_ADDR | CONFIG_NAME;
    try std.testing.expect(haveConfig(&c, CONFIG_ADDR));
    try std.testing.expect(haveConfig(&c, CONFIG_ADDR | CONFIG_TIME)); // 交集非空即真
    try std.testing.expect(!haveConfig(&c, CONFIG_CLID));
    try std.testing.expect(!haveConfig(&c, 0));
}

test "dhcp：常数取值不得与 C 漂移（改这里等于改协议）" {
    // 这些值若与 dnsmasq.h 不一致，租约文件的解析与 tag 匹配会静默出错
    try std.testing.expectEqual(@as(u32, 1), CONFIG_DISABLE);
    try std.testing.expectEqual(@as(u32, 32), CONFIG_ADDR);
    try std.testing.expectEqual(@as(u32, 2048), CONFIG_BANK);
    try std.testing.expectEqual(@as(u32, 16), DHOPT_FORCE);
    try std.testing.expectEqual(@as(u32, 32768), DHOPT_PXE_OPT);
    try std.testing.expectEqual(@as(i32, 1), ARPHRD_ETHER);
    try std.testing.expectEqual(@as(usize, 16), DHCP_CHADDR_MAX);

    // LEASE_*：dnsmasq.h:848-856 是连续小整数，不是位掩码风格的十六进制
    try std.testing.expectEqual(@as(u32, 1), LEASE_NEW);
    try std.testing.expectEqual(@as(u32, 2), LEASE_CHANGED);
    try std.testing.expectEqual(@as(u32, 4), LEASE_AUX_CHANGED);
    try std.testing.expectEqual(@as(u32, 8), LEASE_AUTH_NAME);
    try std.testing.expectEqual(@as(u32, 16), LEASE_USED);
    try std.testing.expectEqual(@as(u32, 32), LEASE_NA);
    try std.testing.expectEqual(@as(u32, 64), LEASE_TA);
    try std.testing.expectEqual(@as(u32, 128), LEASE_HAVE_HWADDR);
    try std.testing.expectEqual(@as(u32, 256), LEASE_EXP_CHANGED);

    // CONTEXT_*：dnsmasq.h:1090-1109 是 1u<<0 .. 1u<<19
    try std.testing.expectEqual(@as(u32, 1 << 0), CONTEXT_STATIC);
    try std.testing.expectEqual(@as(u32, 1 << 3), CONTEXT_PROXY);
    try std.testing.expectEqual(@as(u32, 1 << 6), CONTEXT_RA_NAME);
    try std.testing.expectEqual(@as(u32, 1 << 8), CONTEXT_DHCP);
    try std.testing.expectEqual(@as(u32, 1 << 10), CONTEXT_TEMPLATE);
    try std.testing.expectEqual(@as(u32, 1 << 13), CONTEXT_RA);
    try std.testing.expectEqual(@as(u32, 1 << 17), CONTEXT_V6);
    try std.testing.expectEqual(@as(u32, 1 << 19), CONTEXT_SETLEASE);
}
