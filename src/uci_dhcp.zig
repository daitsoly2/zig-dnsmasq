// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! uci_dhcp.zig —— 把 OpenWrt 的 `/etc/config/dhcp` 读成 DHCPv4 配置。
//!
//! ## 为什么需要它（这是 odhcpd 的「无参数」用法）
//!
//! 真实的 odhcpd **不接受任何命令行参数**：procd 的启动脚本就是
//! `procd_set_param command /usr/sbin/odhcpd`（见 `ref/openwrt-pkg-odhcpd/
//! files/odhcpd.init`），配置全部来自 UCI。本移植因此在 `odhcpd` applet 的
//! **无参数**调用下走这条路：
//!
//! | 调用方式 | 配置来源 | 语义 |
//! | --- | --- | --- |
//! | `odhcpd`（procd，无参数） | `/etc/config/dhcp` | odhcpd 风格 |
//! | `odhcpd --dhcp-range=…` | 命令行 | dnsmasq 风格 |
//!
//! 这样既有「把 `/usr/sbin/odhcpd` 换成我们的二进制就能直接用」的落地方式，
//! 又保留 `--dhcp-range` 那套 dnsmasq 兼容参数用于手工测试。
//!
//! ## 逐条对齐的语义（都能指回 odhcpd 源码）
//!
//! * `config odhcpd` 的 `maindhcp` 是 v4 的总开关：
//!   `config.c:1282` 的 `iface->dhcpv4 = config.main_dhcpv4 ? mode : MODE_DISABLED`
//!   —— 所以 `option maindhcp '0'` 时**即使** `option dhcpv4 'server'` 也不做 v4。
//! * 池**不是绝对地址**，而是「网段内偏移」：`config.c:1233-1238` 记
//!   `pool_start = start`、`pool_end = start + limit - 1`，
//!   `dhcpv4.c:1425` 才 `(addr & netmask) | htonl(offset)` 加上网段基址。
//! * `start`/`limit` 缺省时的兜底池按前缀长度查表（`dhcpv4.c:1405-1420`）：
//!   /28→3-12、/27→10-29、/26→10-59、/25→20-119、其余→100-249。
//! * 前缀长度 > 28 的地址直接跳过（`dhcpv4.h:21` 的 `DHCPV4_MAX_PREFIX_LEN`）。
//! * 选项 3 用 `list router`，为空则用接口自己的地址；选项 6 同理用 `list dns`
//!   （`dhcpv4.c:1112-1136`）。
//! * `config host`：`ip` / `list mac` / `name` / `leasetime`
//!   （`config.c:204-212` 的 `lease_cfg_attrs`）。
//! * `ignore` **不是** UCI 选项：`config.c:311` 里默认 `ignore = true`，
//!   任何 `ra`/`dhcpv4`/`dhcpv6`/`ndp` 被打开才置 false（`config.c:1274-1307`）。
//!   所以这里不读 `ignore`，以免造出「只有我们有」的行为差异。
//!
//! ## 与 odhcpd 的唯一实质差异：ubus 的替身
//!
//! odhcpd 用 `ubus_get_ifname(name)`（`config.c:1154`）把**逻辑接口名**（`lan`）
//! 换成**设备名**（`br-lan`）。没有 ubus 时 `use_ubus=0` 的分支只认显式的
//! `option ifname` / `option networkid`，那会让标准配置（只写 `option
//! interface 'lan'`）直接被丢掉 —— 不能这么干。所以这里复刻 netifd 会给
//! ubus 的那份信息，按下列顺序查：
//!
//!   1. 显式 `option ifname`（非空则直接用，等价 use_ubus=0 的语义）
//!   2. 显式 `option networkid`
//!   3. `/var/state/network`（netifd 运行时状态，形如
//!      `network.lan.ifname='br-lan'`；实机 192.168.0.1/192.168.0.2 都有）
//!   4. `/etc/config/network` 里 `config interface 'lan'` 的 `option device`
//!   5. 逻辑名本身若是一张真实网卡，就用它（老配置 `interface 'eth0'`）
//!
//! 查不到就跳过该段并打警告（对应 odhcpd 的 `goto err`）。

const std = @import("std");
const posix = std.posix;

const Allocator = std.mem.Allocator;
const log = @import("log.zig");
const uci = @import("uci.zig");
const dhcpv4 = @import("dhcpv4.zig");
const v6conf = @import("v6conf.zig");
const addr = @import("addr.zig");
const ifaddr = @import("ifaddr.zig");
const odhcpd_main = @import("odhcpd_main.zig");

pub const Config = odhcpd_main.Config;

/// odhcpd 的默认路径（与 `ref/odhcpd/src/config.c` 的用法一致）
pub const DEFAULT_DHCP_PATH = "/etc/config/dhcp";
pub const DEFAULT_NETWORK_PATH = "/etc/config/network";
pub const DEFAULT_STATE_PATH = "/var/state/network";

/// `config.c:66` ：只写 `start` 不写 `limit` 时的默认条数
const POOL_LIMIT_DEFAULT: u32 = 150;
/// `dhcpv4.h:21`
const MAX_PREFIX_LEN: u8 = 28;

/// 默认租期 `config.c:319`：`iface->dhcp_leasetime = 43200`（12h）
pub const DEFAULT_LEASE_TIME: u32 = 43200;

pub const Opts = struct {
    dhcp_path: []const u8 = DEFAULT_DHCP_PATH,
    network_path: []const u8 = DEFAULT_NETWORK_PATH,
    state_path: []const u8 = DEFAULT_STATE_PATH,
};

pub const Stats = struct {
    /// `config dhcp` 段总数
    sections: usize = 0,
    /// 真正建成地址池的个数
    pools: usize = 0,
    /// 建成的静态绑定条数
    statics: usize = 0,
    /// 因各种原因跳过的段数
    skipped: usize = 0,
    /// 全局 `maindhcp` 的取值
    maindhcp: bool = false,
    /// 建成的 v6 接口配置条数（三个开关至少一个不是 disabled）
    v6: usize = 0,
};

/// 给 `apply()` 用的输入。拆成结构体是为了让单元测试能直接灌字符串，
/// 不必真的写 /etc/config。
pub const Source = struct {
    dhcp: *const uci.Package,
    /// netifd 运行时状态文本（`network.lan.ifname='br-lan'`）
    netifd_state: ?[]const u8 = null,
    network: ?*const uci.Package = null,
    /// 测试用：强制「逻辑名 -> 设备名」，跳过 2~5 步
    ifname_override: ?[]const u8 = null,
};

/// 从三个文件读配置并应用。
pub fn loadFromFiles(cfg: *Config, opts: Opts) !Stats {
    var dhcp_pkg: ?uci.ParseResult = null;
    defer if (dhcp_pkg) |*r| r.package.deinit();

    dhcp_pkg = uci.load(cfg.allocator, opts.dhcp_path) catch |e| {
        log.notice("{s} 读不到（{s}），UCI 模式无配置可用", .{ opts.dhcp_path, @errorName(e) });
        return .{};
    };

    var arena = std.heap.ArenaAllocator.init(cfg.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var net_pkg: ?uci.ParseResult = null;
    defer if (net_pkg) |*r| r.package.deinit();
    net_pkg = uci.load(a, opts.network_path) catch null;

    const state_text: ?[]const u8 = blk: {
        const fd = posix.openat(posix.AT.FDCWD, opts.state_path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0) catch break :blk null;
        defer _ = std.os.linux.close(fd);
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        var tmp: [1024]u8 = undefined;
        while (true) {
            const n = posix.read(fd, &tmp) catch break;
            if (n == 0) break;
            try buf.appendSlice(a, tmp[0..n]);
            if (buf.items.len > 1 << 16) break;
        }
        break :blk buf.items;
    };

    return apply(cfg, .{
        .dhcp = &dhcp_pkg.?.package,
        .netifd_state = state_text,
        .network = if (net_pkg) |*r| &r.package else null,
    });
}

/// 解析 netifd 的 `/var/state/network`：一行一项 `network.<逻辑名>.<键>='<值>'`。
pub fn netifdValue(state_text: []const u8, logical: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, state_text, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const lhs = line[0..eq];
        var rhs = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (rhs.len >= 2 and (rhs[0] == '\'' or rhs[0] == '"') and rhs[rhs.len - 1] == rhs[0]) {
            rhs = rhs[1 .. rhs.len - 1];
        }
        // lhs 形如 network.lan.ifname
        if (!std.mem.startsWith(u8, lhs, "network.")) continue;
        const rest = lhs["network.".len..];
        const dot = std.mem.lastIndexOfScalar(u8, rest, '.') orelse continue;
        if (!std.mem.eql(u8, rest[0..dot], logical)) continue;
        if (!std.mem.eql(u8, rest[dot + 1 ..], key)) continue;
        return rhs;
    }
    return null;
}

/// 逻辑接口名 -> 设备名。顺序见文件头注释。返回的是 cfg 分配的副本。
pub fn resolveDevice(allocator: Allocator, src: Source, sec: *const uci.Section, logical: []const u8) ?[]const u8 {
    if (src.ifname_override) |o| return allocator.dupe(u8, o) catch null;
    if (sec.get("ifname")) |v| {
        if (v.len > 0) return allocator.dupe(u8, v) catch null;
    }
    if (sec.get("networkid")) |v| {
        if (v.len > 0) return allocator.dupe(u8, v) catch null;
    }
    if (src.netifd_state) |st| {
        if (netifdValue(st, logical, "ifname")) |v| return allocator.dupe(u8, v) catch null;
    }
    if (src.network) |np| {
        if (np.byName("interface", logical)) |is| {
            if (is.get("device")) |v| return allocator.dupe(u8, v) catch null;
            if (is.get("ifname")) |v| return allocator.dupe(u8, v) catch null;
        }
    }
    // 老式写法：逻辑名就是网卡名
    if (ifaddr.lookup(allocator, logical) != null) return allocator.dupe(u8, logical) catch null;
    return null;
}

/// 按前缀长度查 odhcpd 的兜底池（`dhcpv4.c:1405-1420`）
fn defaultPoolFor(prefixlen: u8) struct { u32, u32 } {
    return switch (prefixlen) {
        28 => .{ 3, 12 },
        27 => .{ 10, 29 },
        26 => .{ 10, 59 },
        25 => .{ 20, 119 },
        else => .{ 100, 249 },
    };
}

pub const PoolPlan = struct {
    start: [4]u8,
    end: [4]u8,
    netmask: [4]u8,
    prefixlen: u8,
    /// 接口自己的地址（= option 54 服务端标识、option 3/6 的兜底）
    own: [4]u8,
};

/// 由「接口地址 + start/limit 偏移」算出真正的池边界。
/// 复刻 odhcpd `config.c:1233-1244` + `dhcpv4.c:1379-1428`，返回值 null
/// 表示「该网段不适合做池」（对应 odhcpd 的 `goto error`）。
pub fn planPool(a: ifaddr.Ipv4Iface, start_off_in: ?i64, limit_in: ?i64) ?PoolPlan {
    if (a.prefixlen > MAX_PREFIX_LEN) return null;

    var off_start: u32 = 0;
    var off_end: u32 = 0;
    const has_start = start_off_in != null;
    off_start = if (start_off_in) |v| @intCast(@max(v, 0)) else 0;
    if (limit_in) |lim| {
        // odhcpd 用无符号运算，limit=0 会下溢成天文数字，随后被
        // 「> UINT16_MAX」检查判为非法 —— 这里用 +% 保留同样的行为。
        off_end = off_start +% @as(u32, @intCast(@max(lim, 0))) -% 1;
    } else if (has_start) {
        off_end = off_start + POOL_LIMIT_DEFAULT - 1;
    }

    if (off_start > 0xFFFF or off_end > 0xFFFF or off_start > off_end) return null;

    const hostmask: u32 = ~dhcpv4.ipToU32(a.netmask);
    // 偏移必须落在主机位范围内（`dhcpv4.c:1392-1398`）
    if (off_start != 0 and (off_start & hostmask) != off_start) return null;
    if (off_end != 0 and (off_end & hostmask) != off_end) return null;
    if (off_end != 0 and off_end == hostmask) return null;

    if (off_start == 0 or off_end == 0) {
        const d = defaultPoolFor(a.prefixlen);
        off_start = d[0];
        off_end = d[1];
    }

    const base = dhcpv4.ipToU32(a.network);
    return .{
        .start = dhcpv4.u32ToIp(base | off_start),
        .end = dhcpv4.u32ToIp(base | off_end),
        .netmask = a.netmask,
        .prefixlen = a.prefixlen,
        .own = a.addr,
    };
}

/// 把一份 `config dhcp` 段落成池。返回 false 表示跳过。
pub fn applyDhcpSection(cfg: *Config, src: Source, sec: *const uci.Section, maindhcp: bool, st: *Stats) !bool {
    const logical = sec.get("interface") orelse sec.name orelse {
        log.warning("uci: config dhcp 段（第 {d} 行）没有 interface 也没有段名，跳过", .{sec.line});
        return false;
    };

    // `config.c:1282`：maindhcp 是 v4 的总闸
    if (!maindhcp) {
        log.notice("uci: 接口 {s}：option maindhcp 不是 1，按 odhcpd 语义不做 DHCPv4", .{logical});
        return false;
    }
    const mode = sec.get("dhcpv4") orelse "disabled";
    if (std.mem.eql(u8, mode, "disabled")) {
        return false;
    }
    if (!std.mem.eql(u8, mode, "server")) {
        // relay / hybrid 还没实现（DHCP-PLAN 第七节的未完成项）
        log.warning("uci: 接口 {s}：dhcpv4 模式 '{s}' 需要 v6 侧支持，本移植暂未实现，跳过", .{ logical, mode });
        return false;
    }

    const dev = resolveDevice(try cfg.strs(), src, sec, logical) orelse {
        log.warning("uci: 接口 {s}：解析不出对应网卡（ifname/networkid/netifd 状态/network 配置都没有），跳过", .{logical});
        return false;
    };

    const a = ifaddr.lookup(cfg.allocator, dev) orelse {
        log.warning("uci: 接口 {s} -> 网卡 {s} 没有 IPv4 地址，跳过", .{ logical, dev });
        return false;
    };

    // 如果用户写了 list dhcp_option，那是 dnsmasq 的指令，odhcpd 不认
    if (sec.get("dhcp_option") != null) {
        log.warning("uci: 接口 {s} 的 list dhcp_option 是 dnsmasq 专用指令，odhcpd 语义下不下发（需要自定义选项请用命令行的 --dhcp-option）", .{logical});
    }

    const plan = planPool(a, sec.getInt("start"), sec.getInt("limit")) orelse {
        log.warning("uci: 接口 {s}（{s}/{d}）算不出合法的地址池，跳过", .{ logical, dev, a.prefixlen });
        return false;
    };

    var lease_time: u32 = DEFAULT_LEASE_TIME;
    if (sec.get("leasetime")) |lt| {
        if (odhcpd_main.parseLeaseTime(lt)) |v| {
            lease_time = v;
        } else {
            log.warning("uci: 接口 {s} 的 leasetime '{s}' 无法解析，用默认 {d}s", .{ logical, lt, DEFAULT_LEASE_TIME });
        }
    }

    // 选项 3 / 6 的来源（`dhcpv4.c:1112-1136`）：list 有就用 list，没有用自身地址
    const routers = try sec.collect(cfg.allocator, "router");
    defer cfg.allocator.free(routers);
    var router = plan.own;
    if (routers.len > 0) {
        router = dhcpv4.parseIpv4(routers[0]) orelse blk: {
            log.warning("uci: 接口 {s} 的 router '{s}' 不是合法地址，改用自身地址", .{ logical, routers[0] });
            break :blk plan.own;
        };
        if (routers.len > 1) {
            log.warning("uci: 接口 {s} 配了 {d} 个 router，本移植的 Pool 只支持 1 个，只用第一个", .{ logical, routers.len });
        }
    }

    const dns_list = try sec.collect(cfg.allocator, "dns");
    defer cfg.allocator.free(dns_list);
    var dns_buf: std.ArrayListUnmanaged([4]u8) = .empty;
    defer dns_buf.deinit(cfg.allocator);
    if (dns_list.len == 0) {
        try dns_buf.append(cfg.allocator, plan.own);
    } else {
        for (dns_list) |d| {
            if (dhcpv4.parseIpv4(d)) |v| {
                try dns_buf.append(cfg.allocator, v);
            } else {
                log.warning("uci: 接口 {s} 的 dns '{s}' 不是合法地址，忽略", .{ logical, d });
            }
        }
        if (dns_buf.items.len == 0) try dns_buf.append(cfg.allocator, plan.own);
    }
    const dns_slice = try (try cfg.strs()).dupe([4]u8, dns_buf.items);

    const domains = try sec.collect(cfg.allocator, "domain");
    defer cfg.allocator.free(domains);
    const domain: ?[]const u8 = if (domains.len > 0) try cfg.strDup(domains[0]) else null;

    try cfg.pools.append(cfg.allocator, .{
        .start = plan.start,
        .end = plan.end,
        .netmask = plan.netmask,
        .router = router,
        // 显式配过 router 就不再运行期刷新（否则会随接口地址变化被覆盖）
        .router_from_config = routers.len > 0,
        .dns = dns_slice,
        .domain = domain,
        .lease_time = lease_time,
        .interface = dev,
    });
    if (cfg.interface == null) cfg.interface = dev;

    log.notice("uci: 接口 {s}（网卡 {s}）池 {d}.{d}.{d}.{d}-{d}.{d}.{d}.{d}/{d} 租期 {d}s", .{
        logical,        dev,
        plan.start[0],  plan.start[1],
        plan.start[2],  plan.start[3],
        plan.end[0],    plan.end[1],
        plan.end[2],    plan.end[3],
        plan.prefixlen, lease_time,
    });
    st.pools += 1;
    return true;
}

/// 把一份 `config host` 段落成静态绑定（支持 `list mac` 展开成多条）。
pub fn applyHostSection(cfg: *Config, sec: *const uci.Section, st: *Stats) !void {
    const ip_txt = sec.get("ip") orelse {
        log.warning("uci: config host（第 {d} 行）没有 ip，跳过", .{sec.line});
        st.skipped += 1;
        return;
    };
    const ip = dhcpv4.parseIpv4(ip_txt) orelse {
        log.warning("uci: config host 的 ip '{s}' 不合法，跳过", .{ip_txt});
        st.skipped += 1;
        return;
    };
    const macs = try sec.collect(cfg.allocator, "mac");
    defer cfg.allocator.free(macs);
    if (macs.len == 0) {
        // 只有 duid/hostid 的是 v6 静态租约，v4 侧用不上
        if (sec.get("duid") != null or sec.get("hostid") != null) {
            log.notice("uci: config host '{s}' 只配了 IPv6 标识（duid/hostid），v4 侧跳过", .{sec.name orelse "?"});
        } else {
            log.warning("uci: config host（第 {d} 行）没有 mac，跳过", .{sec.line});
        }
        st.skipped += 1;
        return;
    }

    var lease_time: u32 = 0;
    if (sec.get("leasetime")) |lt| {
        lease_time = odhcpd_main.parseLeaseTime(lt) orelse 0;
    }
    const name: ?[]const u8 = if (sec.get("name")) |n| try cfg.strDup(n) else null;

    for (macs) |m| {
        const mac = dhcpv4.parseMac(m) orelse {
            log.warning("uci: config host 的 mac '{s}' 不合法，忽略该条", .{m});
            st.skipped += 1;
            continue;
        };
        try cfg.statics.append(cfg.allocator, .{
            .mac = mac,
            .ip = ip,
            .hostname = name,
            .lease_time = lease_time,
        });
        st.statics += 1;
    }
}

/// 应用一份已解析好的 UCI 包。
/// 读一个模式开关（ra / dhcpv6 / ndp）。odhcpd 对非法取值是 `error()` 后
/// 保持原值，这里改成警告 + 保持 disabled —— 一个拼错的单词不该让整个
/// 接口的其他服务也跟着停掉。
fn modeOpt(sec: *const uci.Section, key: []const u8, logical: []const u8) v6conf.Mode {
    const v = sec.get(key) orelse return .disabled;
    return v6conf.modeOf(v) orelse {
        log.warning("uci: 接口 {s} 的 option {s} = '{s}' 不是合法模式（server/relay/hybrid/disabled），按 disabled 处理", .{ logical, key, v });
        return .disabled;
    };
}

/// 读一个需要夹取的 u32 选项（RA 的各种时间/跳数/MTU）
fn clampOpt(sec: *const uci.Section, key: []const u8, ceiling: u32, logical: []const u8) u32 {
    const raw = sec.getInt(key) orelse return 0;
    if (raw < 0) {
        log.warning("uci: 接口 {s} 的 option {s} 是负数，按 0 处理", .{ logical, key });
        return 0;
    }
    const v: u32 = @intCast(raw);
    if (v <= ceiling) return v;
    log.warning("uci: 接口 {s} 的 option {s} = {d} 超过上限 {d}，已夹取", .{ logical, key, v, ceiling });
    return ceiling;
}

/// 把一份 `config dhcp` 段的 **v6 部分** 读成 `v6conf.Iface6`。
///
/// 与 v4 分开走的原因：`maindhcp` 只是 **v4** 的总闸（`config.c:1282`），
/// `option maindhcp '0'` 时 RA / DHCPv6 / NDP 照样要开 —— 挂在
/// `applyDhcpSection()` 里会被那句 `if (!maindhcp) return false` 一起关掉，
/// 那就是「只有我们有」的行为差异。
///
/// 返回 null 表示「三个开关全关」或「解析不出网卡」，不需要建任何 socket。
pub fn applyV6Section(cfg: *Config, src: Source, sec: *const uci.Section) !?v6conf.Iface6 {
    const logical = sec.get("interface") orelse sec.name orelse {
        log.warning("uci: config dhcp 段（第 {d} 行）没有 interface 也没有段名，跳过 v6 配置", .{sec.line});
        return null;
    };

    var iface6 = v6conf.Iface6{ .name = try cfg.strDup(logical) };
    iface6.ra = modeOpt(sec, "ra", logical);
    iface6.dhcpv6 = modeOpt(sec, "dhcpv6", logical);
    iface6.ndp = modeOpt(sec, "ndp", logical);

    if (!iface6.anyEnabled()) return null;

    const dev = resolveDevice(try cfg.strs(), src, sec, logical) orelse {
        log.warning("uci: 接口 {s}：解析不出对应网卡，v6 服务（RA/DHCPv6/NDP）不启动", .{logical});
        return null;
    };
    iface6.ifname = try cfg.strDup(dev);

    // ---- RA 标志位（list ra_flags） ----
    const flags = try sec.collect(cfg.allocator, "ra_flags");
    defer cfg.allocator.free(flags);
    if (flags.len > 0) {
        // odhcpd 是「先清零再 OR」（config.c:1509），所以写 list ra_flags 就
        // 是完全覆盖缺省的 other-config，而不是叠加。
        iface6.ra_flags = 0;
        for (flags) |f| {
            const bit = v6conf.raFlagOf(f) orelse {
                log.warning("uci: 接口 {s} 的 ra_flags 含非法值 '{s}'（合法：managed-config/other-config/home-agent/none），忽略该项", .{ logical, f });
                continue;
            };
            iface6.ra_flags |= bit;
        }
    }

    if (sec.getBool("ra_slaac")) |v| iface6.ra_slaac = v;
    if (sec.getBool("ra_offlink")) |v| iface6.ra_offlink = v;
    if (sec.getBool("ra_advrouter")) |v| iface6.ra_advrouter = v;
    if (sec.getBool("ra_dns")) |v| iface6.ra_dns = v;

    if (sec.get("ra_preference")) |p| {
        iface6.ra_preference = v6conf.preferenceOf(p) orelse blk: {
            log.warning("uci: 接口 {s} 的 ra_preference '{s}' 非法（high/medium/low/default），用 medium", .{ logical, p });
            break :blk v6conf.RoutePreference.medium;
        };
    }

    if (sec.getInt("ra_default")) |v| iface6.ra_default = @intCast(@max(v, 0));

    // 间隔必须一起夹：只改 max 不改 min 会造出 min > max 的非法组合
    const iv = v6conf.clampIntervals(
        if (sec.getInt("ra_mininterval")) |v| @intCast(@max(v, 0)) else null,
        if (sec.getInt("ra_maxinterval")) |v| @intCast(@max(v, 0)) else null,
    );
    iface6.ra_mininterval = iv.min;
    iface6.ra_maxinterval = iv.max;
    // RFC4861：缺省 AdvDefaultLifetime = 3 * MaxRtrAdvInterval
    iface6.ra_lifetime = if (sec.getInt("ra_lifetime")) |v| @intCast(@max(v, 0)) else 3 * iv.max;

    iface6.ra_reachabletime = clampOpt(sec, "ra_reachabletime", v6conf.ADV_REACHABLE_TIME, logical);
    iface6.ra_retranstime = clampOpt(sec, "ra_retranstime", v6conf.RETRANS_TIMER_MAX, logical);
    iface6.ra_hoplimit = clampOpt(sec, "ra_hoplimit", v6conf.ADV_CUR_HOP_LIMIT, logical);
    // MTU 只夹上下限；「不超过网卡 MTU」那条留给发送侧（那时才知道真实 MTU）
    if (sec.getInt("ra_mtu")) |v| iface6.ra_mtu = v6conf.clampRaMtu(@intCast(@max(v, 0)), 0);

    if (sec.get("ra_pref64")) |v| {
        iface6.ra_pref64 = v6conf.parsePrefix6(v) orelse blk: {
            log.warning("uci: 接口 {s} 的 ra_pref64 '{s}' 不是合法前缀（如 64:ff9b::/96），忽略", .{ logical, v });
            break :blk null;
        };
    }

    // ---- DHCPv6 ----
    if (sec.getBool("dhcpv6_assignall")) |v| iface6.dhcpv6_assignall = v;
    if (sec.getBool("dhcpv6_pd")) |v| iface6.dhcpv6_pd = v;
    if (sec.getBool("dhcpv6_pd_preferred")) |v| iface6.dhcpv6_pd_preferred = v;
    if (sec.getBool("dhcpv6_na")) |v| iface6.dhcpv6_na = v;
    if (sec.getBool("dns_service")) |v| iface6.dns_service = v;

    if (sec.getInt("dhcpv6_pd_min_len")) |v| {
        if (v < 0) {
            log.warning("uci: 接口 {s} 的 dhcpv6_pd_min_len 是负数，忽略", .{logical});
        } else {
            // config.c:1473-1481：只有上界，超了就夹
            const clamped = @min(v, @as(i64, v6conf.PD_MIN_LEN_MAX));
            if (clamped != v) {
                log.warning("uci: 接口 {s} 的 dhcpv6_pd_min_len = {d} 超过 {d}，已夹取", .{ logical, v, v6conf.PD_MIN_LEN_MAX });
            }
            iface6.dhcpv6_pd_min_len = @intCast(clamped);
        }
    }

    if (sec.getInt("dhcpv6_hostidlength")) |v| {
        // config.c:1488-1501：越界就夹，不报错
        const clamped = @min(@max(v, @as(i64, v6conf.HOSTID_LEN_MIN)), @as(i64, v6conf.HOSTID_LEN_MAX));
        if (clamped != v) {
            log.warning("uci: 接口 {s} 的 dhcpv6_hostidlength = {d} 越界，夹到 {d}", .{ logical, v, clamped });
        }
        iface6.dhcpv6_hostid_len = @intCast(clamped);
    }

    if (sec.get("dhcpv6_raw")) |v| iface6.dhcpv6_raw = try cfg.strDup(v);

    // 生命周期上限（字符串，走与 leasetime 同一套解析）
    for ([_][]const u8{ "max_preferred_lifetime", "max_valid_lifetime" }) |key| {
        const v = sec.get(key) orelse continue;
        const secs = odhcpd_main.parseLeaseTime(v) orelse {
            log.warning("uci: 接口 {s} 的 {s} '{s}' 无法解析，保留默认", .{ logical, key, v });
            continue;
        };
        if (secs == 0) {
            log.warning("uci: 接口 {s} 的 {s} '{s}' 解析为 0，保留默认", .{ logical, key, v });
            continue;
        }
        if (std.mem.eql(u8, key, "max_preferred_lifetime")) {
            iface6.max_preferred_lifetime = secs;
        } else {
            iface6.max_valid_lifetime = secs;
        }
    }

    // ---- NDP ----
    if (sec.getBool("ndproxy_routing")) |v| iface6.ndproxy_routing = v;
    if (sec.getBool("ndproxy_slave")) |v| iface6.ndproxy_slave = v;
    if (sec.getBool("ndp_from_link_local")) |v| iface6.ndp_from_link_local = v;
    if (sec.get("prefix_filter")) |v| {
        iface6.pio_filter = v6conf.parsePrefix6(v) orelse blk: {
            log.warning("uci: 接口 {s} 的 prefix_filter '{s}' 不是合法前缀，忽略", .{ logical, v });
            break :blk null;
        };
    }

    // ---- 下发的选项：list dns / list domain / list ntp（都要 v6 地址） ----
    const arena = try cfg.strs();
    iface6.dns = try parseAddr6List(cfg, arena, sec, "dns", logical);
    iface6.ntp = try parseAddr6List(cfg, arena, sec, "ntp", logical);

    const doms = try sec.collect(cfg.allocator, "domain");
    defer cfg.allocator.free(doms);
    var ds: std.ArrayListUnmanaged([]const u8) = .empty;
    defer ds.deinit(cfg.allocator);
    for (doms) |d| {
        try ds.append(cfg.allocator, try arena.dupe(u8, d));
    }
    iface6.dns_search = try arena.dupe([]const u8, ds.items);

    return iface6;
}

/// 解析 `list <key>` 里的一组 IPv6 地址。非法项只警告不中断，
/// 与 odhcpd `config.c` 处理 `list dns` 的做法一致。
fn parseAddr6List(
    cfg: *Config,
    arena: Allocator,
    sec: *const uci.Section,
    key: []const u8,
    logical: []const u8,
) ![]align(1) [16]u8 {
    const vals = try sec.collect(cfg.allocator, key);
    defer cfg.allocator.free(vals);
    var out: std.ArrayListUnmanaged([16]u8) = .empty;
    defer out.deinit(cfg.allocator);
    for (vals) |v| {
        var a: [16]u8 = [_]u8{0} ** 16;
        if (addr.parseIp6(v, &a)) {
            try out.append(cfg.allocator, a);
        } else {
            log.warning("uci: 接口 {s} 的 list {s} 里 '{s}' 不是合法 IPv6 地址，忽略", .{ logical, key, v });
        }
    }
    return try arena.dupe([16]u8, out.items);
}

pub fn apply(cfg: *Config, src: Source) !Stats {
    var st = Stats{};
    const pkg = src.dhcp;

    // 1. 全局段 `config odhcpd 'odhcpd'`
    if (pkg.byName("odhcpd", "odhcpd") orelse pkg.first("odhcpd")) |od| {
        if (od.getBool("maindhcp")) |v| st.maindhcp = v;
        if (od.get("leasefile")) |v| {
            cfg.state_file = try cfg.strDup(v);
        }
        if (od.get("hostsdir")) |v| {
            cfg.hosts_dir = try cfg.strDup(v);
        }
        if (od.get("leasetrigger")) |v| {
            cfg.script = try cfg.strDup(v);
        }
        if (od.get("piodir")) |_| {
            log.notice("uci: 忽略 option piodir（RA 前缀信息，属 DHCPv6/RA 阶段）", .{});
        }
        if (od.get("loglevel")) |_| {
            log.notice("uci: 忽略 option loglevel，请用命令行 --log-dhcp 控制日志", .{});
        }
    } else {
        log.warning("uci: 没有 config odhcpd 段，按 odhcpd 默认取 maindhcp=0（不做 DHCPv4）", .{});
    }

    // 1b. `config dnsmasq` 的 leasefile —— LuCI 概览的「DHCP 租约」读这个
    //     dnsmasq 格式文件；v4 DHCP 被本 applet 接管后由我们补位写出
    //     （writeDnsmasqLeases），否则概览租约信息缺失。
    if (pkg.byName("dnsmasq", "dnsmasq") orelse pkg.first("dnsmasq")) |dn| {
        if (dn.get("leasefile")) |v| cfg.dnsmasq_leasefile = try cfg.strDup(v);
    }

    // 2. `config dhcp` —— 地址池
    for (pkg.sections) |*s| {
        if (!std.mem.eql(u8, s.typ, "dhcp")) continue;
        st.sections += 1;
        const ok = try applyDhcpSection(cfg, src, s, st.maindhcp, &st);
        if (!ok) st.skipped += 1;

        // v6 与 v4 互不相干：maindhcp 只管 v4，RA/DHCPv6/NDP 照样要读
        if (try applyV6Section(cfg, src, s)) |v6| {
            try cfg.v6.append(cfg.allocator, v6);
            st.v6 += 1;
        }
    }

    // 3. `config host` —— 静态绑定（与接口无关，odhcpd 也是全局匹配 MAC）
    for (pkg.sections) |*s| {
        if (!std.mem.eql(u8, s.typ, "host")) continue;
        try applyHostSection(cfg, s, &st);
    }

    // 4. `config boot6`（IPv6 PXE）等：记一条提示，别静默
    var k: usize = 0;
    while (k < pkg.sections.len) : (k += 1) {
        const t = pkg.sections[k].typ;
        if (std.mem.eql(u8, t, "boot6")) {
            log.notice("uci: 忽略 config {s}（IPv6 PXE，尚未实现）", .{t});
        }
    }

    return st;
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

const testing = std.testing;

/// 造一个「网卡 lan = 192.168.0.1/24、br-lan」的假接口配置，
/// 并让逻辑名解析完全走注入，不依赖运行测试的机器。
const FIXTURE_DHCP =
    \\config dhcp 'lan'
    \\    option interface 'lan'
    \\    option start '100'
    \\    option limit '150'
    \\    option leasetime '12h'
    \\    option dhcpv4 'server'
    \\    option dhcpv6 'server'
    \\    option ra 'server'
    \\    list ra_flags 'other-config'
    \\
    \\config odhcpd 'odhcpd'
    \\    option maindhcp '1'
    \\    option leasefile '/tmp/hosts/odhcpd'
    \\    option leasetrigger '/usr/sbin/odhcpd-update'
    \\
    \\config host 'nas'
    \\    option name 'nas'
    \\    list mac 'aa:bb:cc:dd:ee:ff'
    \\    option ip '192.168.0.5'
    \\
;

test "uci_dhcp：netifdValue 按行取值" {
    const st =
        \\network.lan.up='1'
        \\network.lan.ifname='br-lan'
        \\network.loopback.ifname='lo'
        \\
    ;
    try testing.expectEqualStrings("br-lan", netifdValue(st, "lan", "ifname").?);
    try testing.expectEqualStrings("lo", netifdValue(st, "loopback", "ifname").?);
    try testing.expectEqual(@as(?[]const u8, null), netifdValue(st, "wan", "ifname"));
    try testing.expectEqual(@as(?[]const u8, null), netifdValue(st, "lan", "device"));
    // 无引号的写法也要认
    try testing.expectEqualStrings("br-lan", netifdValue("network.lan.ifname=br-lan", "lan", "ifname").?);
    // 前缀相近的名字不能误配
    try testing.expectEqual(@as(?[]const u8, null), netifdValue(st, "la", "ifname"));
}

test "uci_dhcp：兜底池按前缀长度查表（odhcpd dhcpv4.c:1405-1420）" {
    const mk = struct {
        fn f(pl: u8) ifaddr.Ipv4Iface {
            return .{
                .addr = .{ 192, 168, 0, 1 },
                .netmask = ifaddr.prefixLenToMask(pl),
                .prefixlen = pl,
                .network = dhcpv4.networkOf(.{ 192, 168, 0, 1 }, ifaddr.prefixLenToMask(pl)),
            };
        }
    }.f;

    // /24 且不写 start/limit -> 100..249
    const p24 = planPool(mk(24), null, null).?;
    try testing.expectEqual([4]u8{ 192, 168, 0, 100 }, p24.start);
    try testing.expectEqual([4]u8{ 192, 168, 0, 249 }, p24.end);

    // /25 -> 20..119
    const p25 = planPool(mk(25), null, null).?;
    try testing.expectEqual([4]u8{ 192, 168, 0, 20 }, p25.start);
    try testing.expectEqual([4]u8{ 192, 168, 0, 119 }, p25.end);

    // /26 -> 10..59 、/27 -> 10..29 、/28 -> 3..12
    try testing.expectEqual(@as(u8, 10), planPool(mk(26), null, null).?.start[3]);
    try testing.expectEqual(@as(u8, 59), planPool(mk(26), null, null).?.end[3]);
    try testing.expectEqual(@as(u8, 10), planPool(mk(27), null, null).?.start[3]);
    try testing.expectEqual(@as(u8, 29), planPool(mk(27), null, null).?.end[3]);
    try testing.expectEqual(@as(u8, 3), planPool(mk(28), null, null).?.start[3]);
    try testing.expectEqual(@as(u8, 12), planPool(mk(28), null, null).?.end[3]);
}

test "uci_dhcp：前缀长度 > 28 直接跳过（DHCPV4_MAX_PREFIX_LEN）" {
    const a: ifaddr.Ipv4Iface = .{
        .addr = .{ 10, 0, 0, 1 },
        .netmask = .{ 255, 255, 255, 252 },
        .prefixlen = 30,
        .network = .{ 10, 0, 0, 0 },
    };
    try testing.expectEqual(@as(?PoolPlan, null), planPool(a, null, null));
}

test "uci_dhcp：start/limit 是相对网段的偏移，不是绝对地址" {
    // 10.9.0.1/24 且 start=10 limit=20 -> 10.9.0.10 .. 10.9.0.29
    const a: ifaddr.Ipv4Iface = .{
        .addr = .{ 10, 9, 0, 1 },
        .netmask = .{ 255, 255, 255, 0 },
        .prefixlen = 24,
        .network = .{ 10, 9, 0, 0 },
    };
    const p = planPool(a, 10, 20).?;
    try testing.expectEqual([4]u8{ 10, 9, 0, 10 }, p.start);
    try testing.expectEqual([4]u8{ 10, 9, 0, 29 }, p.end);
    try testing.expectEqual([4]u8{ 10, 9, 0, 1 }, p.own);

    // 只写 start 不写 limit -> limit 取默认 150
    const q = planPool(a, 100, null).?;
    try testing.expectEqual([4]u8{ 10, 9, 0, 100 }, q.start);
    try testing.expectEqual([4]u8{ 10, 9, 0, 249 }, q.end);
}

test "uci_dhcp：非法 start/limit 一律判为不可用（不能崩）" {
    const a: ifaddr.Ipv4Iface = .{
        .addr = .{ 192, 168, 1, 1 },
        .netmask = .{ 255, 255, 255, 0 },
        .prefixlen = 24,
        .network = .{ 192, 168, 1, 0 },
    };
    // limit=0 在 odhcpd 里会下溢 -> 被 >UINT16_MAX 拦下
    try testing.expectEqual(@as(?PoolPlan, null), planPool(a, 100, 0));
    // 起始偏移超出 /24 的主机位
    try testing.expectEqual(@as(?PoolPlan, null), planPool(a, 300, 10));
    // 结束偏移超出主机位
    try testing.expectEqual(@as(?PoolPlan, null), planPool(a, 100, 200));
    // 结束偏移 == 广播地址（偏移 255）
    try testing.expectEqual(@as(?PoolPlan, null), planPool(a, 250, 6));
    // 负数按 0 处理，不能崩
    _ = planPool(a, -5, -1);
}

test "uci_dhcp：整份配置读懂（静态绑定 + 全局段；网卡不存在则池跳过）" {
    var r = try uci.parse(testing.allocator, FIXTURE_DHCP);
    defer r.package.deinit();

    var cfg = Config{ .allocator = testing.allocator };
    defer cfg.deinit();

    const st = try apply(&cfg, .{
        .dhcp = &r.package,
        .ifname_override = "lan0",
    });

    try testing.expectEqual(true, st.maindhcp);
    try testing.expectEqual(@as(usize, 1), st.sections);
    try testing.expectEqual(@as(usize, 1), st.statics);
    try testing.expectEqualStrings("/tmp/hosts/odhcpd", cfg.state_file.?);
    try testing.expectEqualStrings("/usr/sbin/odhcpd-update", cfg.script.?);

    // ifname_override 让接口名解析不依赖本机网卡；本机没有 lan0，
    // 所以 ifaddr.lookup 失败 -> 该段被跳过（这也是要测的：不能崩、
    // 也不能留下半成品状态）
    try testing.expectEqual(@as(usize, 0), st.pools);
    try testing.expectEqual(@as(usize, 1), st.skipped);
    try testing.expectEqual(@as(?[]const u8, null), cfg.interface);

    // 静态绑定不依赖网卡，应当已经落地
    try testing.expectEqual(@as(usize, 1), cfg.statics.items.len);
    try testing.expectEqual([6]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, cfg.statics.items[0].mac);
    try testing.expectEqual([4]u8{ 192, 168, 0, 5 }, cfg.statics.items[0].ip);
    try testing.expectEqualStrings("nas", cfg.statics.items[0].hostname.?);
}

test "uci_dhcp：dnsmasq 段的 leasefile 进 cfg.dnsmasq_leasefile（LuCI 概览补位）" {
    const fixture =
        \\config dnsmasq 'dnsmasq'
        \\  option leasefile '/tmp/dhcp.leases'
        \\
        \\config odhcpd 'odhcpd'
        \\  option maindhcp '1'
        \\  option leasefile '/tmp/hosts/odhcpd'
        \\
    ;
    var r = try uci.parse(testing.allocator, fixture);
    defer r.package.deinit();
    var cfg = Config{ .allocator = testing.allocator };
    defer cfg.deinit();
    _ = try apply(&cfg, .{ .dhcp = &r.package, .ifname_override = "lan0" });
    // odhcpd 段的 leasefile 是状态文件；dnsmasq 段的是 LuCI 概览读的那份
    try testing.expectEqualStrings("/tmp/hosts/odhcpd", cfg.state_file.?);
    try testing.expectEqualStrings("/tmp/dhcp.leases", cfg.dnsmasq_leasefile.?);
}

test "uci_dhcp：在真实存在的网卡（lo）上真的建出池 —— 端到端走通" {
    // lo = 127.0.0.1/8。odhcpd 的兜底池对「其它前缀」（<=24）是 100..249，
    // 于是 start=100 limit=150 应当算出 127.0.0.100 - 127.0.0.249。
    // 这条测试不碰网络，只是读内核的接口地址。
    var r = try uci.parse(testing.allocator, FIXTURE_DHCP);
    defer r.package.deinit();

    var cfg = Config{ .allocator = testing.allocator };
    defer cfg.deinit();

    const st = try apply(&cfg, .{ .dhcp = &r.package, .ifname_override = "lo" });
    try testing.expectEqual(@as(usize, 1), st.pools);
    try testing.expectEqual(@as(usize, 0), st.skipped);
    try testing.expectEqual(@as(usize, 1), cfg.pools.items.len);

    const p = cfg.pools.items[0];
    try testing.expectEqual([4]u8{ 127, 0, 0, 100 }, p.start);
    try testing.expectEqual([4]u8{ 127, 0, 0, 249 }, p.end);
    try testing.expectEqual([4]u8{ 255, 0, 0, 0 }, p.netmask);
    // list router/dns/domain 都没写 -> 选项 3/6 用接口自身地址（odhcpd 同）
    try testing.expectEqual([4]u8{ 127, 0, 0, 1 }, p.router);
    try testing.expectEqual(@as(usize, 1), p.dns.len);
    try testing.expectEqual([4]u8{ 127, 0, 0, 1 }, p.dns[0]);
    try testing.expectEqual(@as(?[]const u8, null), p.domain);
    // option leasetime '12h'
    try testing.expectEqual(@as(u32, 43200), p.lease_time);
    try testing.expectEqualStrings("lo", p.interface.?);
    try testing.expectEqualStrings("lo", cfg.interface.?);
}

test "uci_dhcp：list router / dns / domain 覆盖兜底值" {
    var r = try uci.parse(testing.allocator,
        \\config dhcp 'lan'
        \\    option interface 'lan'
        \\    option start '10'
        \\    option limit '20'
        \\    option leasetime '1h'
        \\    option dhcpv4 'server'
        \\    list router '10.9.0.254'
        \\    list dns '1.1.1.1'
        \\    list dns '8.8.8.8'
        \\    list domain 'home.lan'
        \\
        \\config odhcpd 'odhcpd'
        \\    option maindhcp '1'
        \\
    );
    defer r.package.deinit();
    var cfg = Config{ .allocator = testing.allocator };
    defer cfg.deinit();
    const st = try apply(&cfg, .{ .dhcp = &r.package, .ifname_override = "lo" });
    try testing.expectEqual(@as(usize, 1), st.pools);
    const p = cfg.pools.items[0];
    try testing.expectEqual([4]u8{ 10, 9, 0, 254 }, p.router);
    try testing.expectEqual(@as(usize, 2), p.dns.len);
    try testing.expectEqual([4]u8{ 1, 1, 1, 1 }, p.dns[0]);
    try testing.expectEqual([4]u8{ 8, 8, 8, 8 }, p.dns[1]);
    try testing.expectEqualStrings("home.lan", p.domain.?);
    try testing.expectEqual(@as(u32, 3600), p.lease_time);
    try testing.expectEqual([4]u8{ 127, 0, 0, 10 }, p.start);
    try testing.expectEqual([4]u8{ 127, 0, 0, 29 }, p.end);
}

test "uci_dhcp：maindhcp=0 时不做 v4（odhcpd config.c:1282 的语义）" {
    var r = try uci.parse(testing.allocator,
        \\config dhcp 'lan'
        \\    option interface 'lan'
        \\    option start '100'
        \\    option limit '150'
        \\    option dhcpv4 'server'
        \\
        \\config odhcpd 'odhcpd'
        \\    option maindhcp '0'
        \\
    );
    defer r.package.deinit();

    var cfg = Config{ .allocator = testing.allocator };
    defer cfg.deinit();
    const st = try apply(&cfg, .{ .dhcp = &r.package, .ifname_override = "lo" });
    try testing.expectEqual(false, st.maindhcp);
    try testing.expectEqual(@as(usize, 0), st.pools);
    try testing.expectEqual(@as(usize, 1), st.skipped);
}

test "uci_dhcp：dhcpv4 模式 disabled / relay 时跳过，且不误报池" {
    var r = try uci.parse(testing.allocator,
        \\config dhcp 'a'
        \\    option interface 'lan'
        \\    option dhcpv4 'disabled'
        \\
        \\config dhcp 'b'
        \\    option interface 'lan'
        \\    option dhcpv4 'relay'
        \\
        \\config odhcpd 'odhcpd'
        \\    option maindhcp '1'
        \\
    );
    defer r.package.deinit();
    var cfg = Config{ .allocator = testing.allocator };
    defer cfg.deinit();
    const st = try apply(&cfg, .{ .dhcp = &r.package, .ifname_override = "lo" });
    try testing.expectEqual(@as(usize, 2), st.sections);
    try testing.expectEqual(@as(usize, 0), st.pools);
    try testing.expectEqual(@as(usize, 2), st.skipped);
}

test "uci_dhcp：host 段的 list mac 会展开成多条静态绑定" {
    var r = try uci.parse(testing.allocator,
        \\config host 'multi'
        \\    option ip '192.168.0.9'
        \\    option name 'multi'
        \\    list mac 'aa:aa:aa:aa:aa:01'
        \\    list mac 'aa:aa:aa:aa:aa:02'
        \\    option leasetime '1h'
        \\
    );
    defer r.package.deinit();
    var cfg = Config{ .allocator = testing.allocator };
    defer cfg.deinit();
    const st = try apply(&cfg, .{ .dhcp = &r.package });
    try testing.expectEqual(@as(usize, 2), st.statics);
    try testing.expectEqual(@as(usize, 2), cfg.statics.items.len);
    try testing.expectEqual(@as(u32, 3600), cfg.statics.items[0].lease_time);
    try testing.expectEqual([4]u8{ 192, 168, 0, 9 }, cfg.statics.items[1].ip);
}

test "uci_dhcp：host 段缺 ip 或 mac 非法时不落库、只计数" {
    var r = try uci.parse(testing.allocator,
        \\config host 'noip'
        \\    option name 'x'
        \\    list mac 'aa:bb:cc:dd:ee:01'
        \\
        \\config host 'badmac'
        \\    option ip '192.168.0.10'
        \\    list mac 'not-a-mac'
        \\
        \\config host 'v6only'
        \\    option duid '0001000112345678aabbccddeeff'
        \\    option hostid '1'
        \\
    );
    defer r.package.deinit();
    var cfg = Config{ .allocator = testing.allocator };
    defer cfg.deinit();
    const st = try apply(&cfg, .{ .dhcp = &r.package });
    try testing.expectEqual(@as(usize, 0), st.statics);
    try testing.expectEqual(@as(usize, 3), st.skipped);
}

test "uci_dhcp：没有 config odhcpd 段时默认 maindhcp=0" {
    var r = try uci.parse(testing.allocator,
        \\config dhcp 'lan'
        \\    option interface 'lan'
        \\    option dhcpv4 'server'
        \\
    );
    defer r.package.deinit();
    var cfg = Config{ .allocator = testing.allocator };
    defer cfg.deinit();
    const st = try apply(&cfg, .{ .dhcp = &r.package, .ifname_override = "lo" });
    try testing.expectEqual(false, st.maindhcp);
    try testing.expectEqual(@as(usize, 0), st.pools);
}

test "uci_dhcp：hostsdir 缺省保持 /tmp/hosts（odhcpd 默认）" {
    var r = try uci.parse(testing.allocator,
        \\config odhcpd 'odhcpd'
        \\    option maindhcp '1'
        \\
    );
    defer r.package.deinit();
    var cfg = Config{ .allocator = testing.allocator };
    defer cfg.deinit();
    _ = try apply(&cfg, .{ .dhcp = &r.package });
    try testing.expectEqualStrings("/tmp/hosts", cfg.hosts_dir);
}

test "uci_dhcp：读不到 /etc/config/dhcp 时安静降级（不报错、不崩）" {
    var cfg = Config{ .allocator = testing.allocator };
    defer cfg.deinit();
    const st = try loadFromFiles(&cfg, .{ .dhcp_path = "/nonexistent/etc/config/dhcp" });
    try testing.expectEqual(@as(usize, 0), st.pools);
    try testing.expectEqual(false, st.maindhcp);
}

// ---------------------------------------------------------------------------
// v6（DHCPv6 / RA / NDP）UCI 解析
// ---------------------------------------------------------------------------

/// 对着 LuCI「IPv6 设置」页能出现的字段写的夹具。
/// 关键点：**不写 option maindhcp 的反面（写 0）** —— v6 必须不受 maindhcp 影响。
const FIXTURE_V6 =
    \\config dhcp 'lan'
    \\    option interface 'lan'
    \\    option dhcpv4 'server'
    \\    option dhcpv6 'hybrid'
    \\    option ra 'server'
    \\    option ndp 'disabled'
    \\    option ra_default '1'
    \\    option ra_slaac '1'
    \\    option ra_offlink '0'
    \\    option ra_advrouter '0'
    \\    option ra_preference 'high'
    \\    option ra_maxinterval '300'
    \\    option ra_mininterval '100'
    \\    option ra_lifetime '900'
    \\    option ra_reachabletime '120000'
    \\    option ra_retranstime '1000'
    \\    option ra_hoplimit '64'
    \\    option ra_mtu '1480'
    \\    option ra_dns '1'
    \\    option ra_pref64 '64:ff9b::/96'
    \\    option dhcpv6_pd '0'
    \\    option dhcpv6_pd_preferred '1'
    \\    option dhcpv6_pd_min_len '60'
    \\    option dhcpv6_assignall '0'
    \\    option dhcpv6_na '1'
    \\    option dhcpv6_hostidlength '24'
    \\    option max_preferred_lifetime '1800'
    \\    option max_valid_lifetime '3600'
    \\    option ndproxy_routing '0'
    \\    option ndproxy_slave '1'
    \\    option ndp_from_link_local '0'
    \\    option prefix_filter '2001:db8:1::/56'
    \\    option dns_service '0'
    \\    list dns '2001:db8::53'
    \\    list dns 'not-an-address'
    \\    list ntp '2001:db8::123'
    \\    list domain 'lan'
    \\
    \\config odhcpd 'odhcpd'
    \\    option maindhcp '0'
    \\
;

test "uci_dhcp：v6 全套 UCI 选项 —— 且不受 maindhcp=0 影响" {
    var r = try uci.parse(testing.allocator, FIXTURE_V6);
    defer r.package.deinit();

    var cfg = Config{ .allocator = testing.allocator };
    defer cfg.deinit();

    const st = try apply(&cfg, .{ .dhcp = &r.package, .ifname_override = "br-lan" });

    // maindhcp=0 只关 v4；ra/dhcpv6/ndp 照样要读（config.c:1282 只在 v4 路径上）
    try testing.expectEqual(false, st.maindhcp);
    try testing.expectEqual(@as(usize, 0), st.pools);
    try testing.expectEqual(@as(usize, 1), st.v6);

    try testing.expectEqual(@as(usize, 1), cfg.v6.items.len);
    const v6 = cfg.v6.items[0];

    try testing.expectEqualStrings("lan", v6.name);
    try testing.expectEqualStrings("br-lan", v6.ifname);
    try testing.expectEqual(v6conf.Mode.server, v6.ra);
    try testing.expectEqual(v6conf.Mode.hybrid, v6.dhcpv6);
    try testing.expectEqual(v6conf.Mode.disabled, v6.ndp);
    try testing.expect(v6.anyEnabled());

    // RA
    try testing.expectEqual(@as(u32, 1), v6.ra_default);
    try testing.expect(v6.ra_slaac);
    try testing.expect(!v6.ra_offlink);
    try testing.expect(!v6.ra_advrouter);
    try testing.expectEqual(v6conf.RoutePreference.high, v6.ra_preference);
    try testing.expectEqual(@as(u32, 300), v6.ra_maxinterval);
    try testing.expectEqual(@as(u32, 100), v6.ra_mininterval); // <= 0.75*300，保留
    try testing.expectEqual(@as(u32, 900), v6.ra_lifetime); // 显式写的优先
    try testing.expectEqual(@as(u32, 120000), v6.ra_reachabletime);
    try testing.expectEqual(@as(u32, 1000), v6.ra_retranstime);
    try testing.expectEqual(@as(u32, 64), v6.ra_hoplimit);
    try testing.expectEqual(@as(u32, 1480), v6.ra_mtu);
    try testing.expect(v6.ra_dns);
    try testing.expectEqual(@as(u8, 96), v6.ra_pref64.?.len);

    // DHCPv6
    try testing.expect(!v6.dhcpv6_pd);
    try testing.expect(v6.dhcpv6_pd_preferred);
    try testing.expectEqual(@as(u8, 60), v6.dhcpv6_pd_min_len);
    try testing.expect(!v6.dhcpv6_assignall);
    try testing.expect(v6.dhcpv6_na);
    try testing.expectEqual(@as(u8, 24), v6.dhcpv6_hostid_len);
    try testing.expectEqual(@as(u32, 1800), v6.max_preferred_lifetime);
    try testing.expectEqual(@as(u32, 3600), v6.max_valid_lifetime);
    try testing.expect(!v6.dns_service);

    // NDP
    try testing.expect(!v6.ndproxy_routing);
    try testing.expect(v6.ndproxy_slave);
    try testing.expect(!v6.ndp_from_link_local);
    try testing.expectEqual(@as(u8, 56), v6.pio_filter.?.len);

    // 下发的选项：非法地址过滤掉，不中断
    try testing.expectEqual(@as(usize, 1), v6.dns.len);
    try testing.expectEqual(@as(usize, 1), v6.ntp.len);
    try testing.expectEqual(@as(usize, 1), v6.dns_search.len);
    try testing.expectEqualStrings("lan", v6.dns_search[0]);
}

test "uci_dhcp：三个 v6 开关全关的接口不进 v6 表" {
    const txt =
        \\config dhcp 'lan'
        \\    option interface 'lan'
        \\    option dhcpv4 'server'
        \\
    ;
    var r = try uci.parse(testing.allocator, txt);
    defer r.package.deinit();

    var cfg = Config{ .allocator = testing.allocator };
    defer cfg.deinit();

    const st = try apply(&cfg, .{ .dhcp = &r.package, .ifname_override = "lo" });
    try testing.expectEqual(@as(usize, 0), st.v6);
    try testing.expectEqual(@as(usize, 0), cfg.v6.items.len);
}

test "uci_dhcp：ra_flags 的 list 写法是完全覆盖而不是叠加" {
    // odhcpd config.c:1508-1514：先清零再逐项 OR
    const txt =
        \\config dhcp 'lan'
        \\    option interface 'lan'
        \\    option ra 'server'
        \\    list ra_flags 'managed-config'
        \\    list ra_flags 'other-config'
        \\
    ;
    var r = try uci.parse(testing.allocator, txt);
    defer r.package.deinit();

    var cfg = Config{ .allocator = testing.allocator };
    defer cfg.deinit();
    _ = try apply(&cfg, .{ .dhcp = &r.package, .ifname_override = "lo" });

    const v6 = cfg.v6.items[0];
    try testing.expectEqual(@as(u8, v6conf.RA_FLAG_MANAGED | v6conf.RA_FLAG_OTHER), v6.ra_flags);
}
