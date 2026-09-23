// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! odhcpd_main.zig —— DHCPv4 守护进程的入口（「odhcpd」applet）。
//!
//! ## 定位
//!
//! 用户的要求是三条：
//!   1. 能跑就行，不需要多线程；
//!   2. **兼容 dnsmasq C 版的参数命令**，能设静态地址；
//!   3. 实现方式**复刻 odhcpd**，而不是照搬 dnsmasq 的 DHCP 代码。
//!
//! 因此这里的分工是：
//!   * **配置界面 = dnsmasq 风格命令行**（`--dhcp-range` / `--dhcp-host` /
//!     `--dhcp-option` / `--interface` / `--pid-file` / `--conf-file` …）。
//!     这样现有 dnsmasq 配置可以直接拿来用，也符合「兼容 C 版参数」。
//!   * **运行时 = odhcpd 的做法**：一个 UDP socket（`IP_PKTINFO` 取收包网卡、
//!     `SO_BINDTODEVICE` 限定网卡、`SO_BROADCAST` 发广播），无 fork、
//!     无 raw socket、无 BPF 过滤器 —— 这正是 odhcpd 与 dnsmasq 在
//!     DHCP 实现上的最大分野（dnsmasq 用 AF_PACKET + BPF）。
//!   * **输出文件 = odhcpd 的格式**：`<dir>/odhcpd.hosts.<ifname>`
//!     （hosts 格式，给 dnsmasq/我们的 DNS 侧读）以及 `#` 记录的状态文件。
//!
//! 报文编解码与地址分配在 `dhcpv4.zig` 里，是纯函数、有逐字节测试。
//!
//! ## 已知未实现（会打警告，不会静默吞掉）
//!
//!   * DHCPv6 / RA / NDP（阶段 5）
//!   * TFTP（阶段 6）
//!   * option overload（选项 52）、PXE 相关选项
//!   * 中继（`--dhcp-relay`）、`--dhcp-boot` 之外的 PXE 启动链
//!   * ubus 暴露租约（OpenWrt 的 LuCI 靠它显示，目前只写文件）

const std = @import("std");
const posix = std.posix;
const system = std.os.linux;
const net = @import("net.zig");
const addr = @import("addr.zig");
const log = @import("log.zig");
const util = @import("util.zig");
const dhcpv4 = @import("dhcpv4.zig");
const uci_dhcp = @import("uci_dhcp.zig");
const v6conf = @import("v6conf.zig");
const v6rt = @import("v6rt.zig");

const Allocator = std.mem.Allocator;

/// 最大收包长度。RFC2131 §2 要求服务端能收 576 字节，实际客户端常带
/// 更大的选项区，1500 足够覆盖常见 MTU 且不会截断。
const MAX_PACKET: usize = 1500;

/// 最多支持的地址池 / 静态绑定 / 用户选项条数（路由器上足够）
const MAX_POOLS = 8;
const MAX_STATICS = 128;
const MAX_LEASES = 512;

const MAX_USER_OPTS = 32;

/// DECLINE 之后的退避时间（秒）。dnsmasq 用 600（rfc2131.c 的 DECLINE_BACKOFF）。
const DECLINE_BACKOFF: i64 = 600;

/// odhcpd 状态文件里 `valid_until = -1` 表示「永不过期」（INFINITE_VALID）。
/// 我们内部没有真正的无穷，用一个足够远的时刻表示（100 年）。
const LEASE_INFINITE_SECS: i64 = 100 * 365 * 86400;

/// 状态文件里 `valid_until` 的「绝对时间 / 相对剩余」判据：小于这个值（2000-01-01）
/// 就认为是本移植早期版本写的「剩余秒数」。真实租约的到期时间不可能落在 2000 年之前。
const ABSOLUTE_TIME_FLOOR: i64 = 946684800;

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

/// 一条 `--dhcp-option=`
pub const UserOpt = struct {
    code: u8,
    data: [255]u8 = [_]u8{0} ** 255,
    len: u8 = 0,
};

pub const Config = struct {
    allocator: Allocator,

    pools: std.ArrayListUnmanaged(dhcpv4.Pool) = .empty,
    statics: std.ArrayListUnmanaged(dhcpv4.StaticHost) = .empty,
    dns: std.ArrayListUnmanaged([4]u8) = .empty,
    user_opts: std.ArrayListUnmanaged(UserOpt) = .empty,
    /// DHCPv6 / RA / NDP 的**每接口**配置（UCI 的 v6 部分，见 v6conf.zig）。
    /// 与 v4 分开存：v4 的池/静态绑定是与接口无关的扁平表，而 v6 的三个开关、
    /// RA 参数都是按接口走的 —— odhcpd 里也是 `struct interface` 一份。
    v6: std.ArrayListUnmanaged(v6conf.Iface6) = .empty,

    domain: ?[]const u8 = null,
    interface: ?[]const u8 = null,
    pid_file: ?[]const u8 = null,
    /// hosts 文件输出目录（对应 odhcpd 的 dhcp_hostsdir，默认 /tmp/hosts）
    hosts_dir: []const u8 = "/tmp/hosts",
    /// 状态文件路径（对应 dnsmasq 的 --dhcp-leasefile）
    state_file: ?[]const u8 = null,
    /// 租约变化时执行的脚本（dnsmasq 的 --dhcp-script）
    script: ?[]const u8 = null,
    /// dnsmasq 格式租约文件（UCI `config dnsmasq` 的 `option leasefile`，缺省
    /// /tmp/dhcp.leases）。LuCI 概览的「DHCP 租约」读它；v4 DHCP 被本 applet
    /// 接管后必须由我们补位写出，否则概览租约信息缺失（2026-09-21）。
    /// 命令行模式不写（自己的 state_file 已够）。
    dnsmasq_leasefile: ?[]const u8 = null,

    lease_time: u32 = 43200,
    log_dhcp: bool = false,
    authoritative: bool = false,
    /// 显式指定 server-identifier（本移植的扩展，dnsmasq 没有这个开关；
    /// 不加时按「收包网卡的地址」推导，与 dnsmasq 行为一致）
    server_id: ?[4]u8 = null,
    /// 只校验配置、不建 socket（`--test`）
    test_only: bool = false,
    /// 本机回环自检（`--zd-selftest`）：起服务端 → 发 DISCOVER/REQUEST → 校验应答。
    /// 全程走 127.0.0.0/8，**一个字节都不上物理网卡**，因此在生产网段里
    /// 也可以随时跑（不会和上游 DHCP 服务器抢答）。详见 runSelfTest()。
    selftest: bool = false,

    /// 单实例锁的文件路径（`--zd-lock-file`）。null = 用 INSTANCE_LOCK_PATH。
    /// 只有测试需要覆盖：本地 e2e 用 tmpdir 隔离，免得几份测试抢同一把全局锁。
    lock_file: ?[]const u8 = null,

    /// **测试用扩展**：服务端 UDP 端口（默认 67）。
    /// 133 行里的本机回归测试需要一个不需要特权端口的运行方式 ——
    /// 容器/沙箱里即使 uid=0 也可能没有 CAP_NET_BIND_SERVICE，
    /// 绑 67 会直接 EACCES。生产部署一律用默认值。
    port: u16 = dhcpv4.SERVER_PORT,
    /// **测试用扩展**：应答的目标端口（默认 68）。理由同上。
    client_port: u16 = dhcpv4.CLIENT_PORT,

    // ---- 配置来源的选择（UCI 风格 vs dnsmasq 命令行风格） ----------------
    /// 命令行里出现过任何**配置类**选项（`--dhcp-range` / `--dhcp-host` /
    /// `--dhcp-option` / `--conf-file`）时就置位 —— 此时按 dnsmasq 风格，
    /// **不读 UCI**。全都没出现则读 UCI，即 odhcpd 的原生用法。
    cli_conf_seen: bool = false,
    /// 强制不读 UCI（调试「纯命令行」行为时用）
    no_uci: bool = false,
    /// UCI 配置文件路径（默认 `/etc/config/dhcp`，与 odhcpd 一致）
    uci_path: []const u8 = uci_dhcp.DEFAULT_DHCP_PATH,
    uci_network_path: []const u8 = uci_dhcp.DEFAULT_NETWORK_PATH,
    uci_state_path: []const u8 = uci_dhcp.DEFAULT_STATE_PATH,

    /// UCI 路径下所有**持久**字符串（接口名、域名、DNS 列表、脚本路径…）
    /// 都从这块 arena 里出。命令行路径用的是 argv 的切片，根本不进这里，
    /// 所以 deinit 只需要销毁 arena，不必逐个 free —— 也就不会出现
    /// 「argv 的指针被 free 掉」这种致命错误。首次用到时才创建。
    str_arena: ?*std.heap.ArenaAllocator = null,

    /// 取「持久字符串」的分配器（懒创建）
    pub fn strs(self: *Config) !Allocator {
        if (self.str_arena == null) {
            const ar = try self.allocator.create(std.heap.ArenaAllocator);
            ar.* = std.heap.ArenaAllocator.init(self.allocator);
            self.str_arena = ar;
        }
        return self.str_arena.?.allocator();
    }

    /// 把一段文本复制进持久区
    pub fn strDup(self: *Config, s: []const u8) ![]const u8 {
        return (try self.strs()).dupe(u8, s);
    }

    pub fn deinit(self: *Config) void {
        if (self.str_arena) |ar| {
            ar.deinit();
            self.allocator.destroy(ar);
            self.str_arena = null;
        }
        self.pools.deinit(self.allocator);
        self.statics.deinit(self.allocator);
        self.v6.deinit(self.allocator);
        self.dns.deinit(self.allocator);
        self.user_opts.deinit(self.allocator);
    }
};

/// 解析 `12h` / `30m` / `45s` / `3600` / `infinite`
pub fn parseLeaseTime(s: []const u8) ?u32 {
    if (s.len == 0) return null;
    if (std.mem.eql(u8, s, "infinite")) return 0xFFFFFFFF;
    var mult: u32 = 1;
    var num = s;
    const last = s[s.len - 1];
    if (last == 'h' or last == 'H') {
        mult = 3600;
        num = s[0 .. s.len - 1];
    } else if (last == 'm' or last == 'M') {
        mult = 60;
        num = s[0 .. s.len - 1];
    } else if (last == 's' or last == 'S') {
        mult = 1;
        num = s[0 .. s.len - 1];
    }
    const v = std.fmt.parseInt(u32, num, 10) catch return null;
    return v *| mult;
}

/// 选项名 -> 选项号（只列我们会下发的那些）
fn optNameToCode(name: []const u8) ?u8 {
    const map = [_]struct { n: []const u8, c: u8 }{
        .{ .n = "netmask", .c = dhcpv4.Opt.netmask },
        .{ .n = "router", .c = dhcpv4.Opt.router },
        .{ .n = "dns-server", .c = dhcpv4.Opt.dnsserver },
        .{ .n = "dnsserver", .c = dhcpv4.Opt.dnsserver },
        .{ .n = "domain-name", .c = dhcpv4.Opt.domain },
        .{ .n = "domain", .c = dhcpv4.Opt.domain },
        .{ .n = "hostname", .c = dhcpv4.Opt.hostname },
        .{ .n = "broadcast", .c = dhcpv4.Opt.broadcast },
        .{ .n = "mtu", .c = dhcpv4.Opt.mtu },
        .{ .n = "lease-time", .c = dhcpv4.Opt.lease_time },
    };
    for (map) |e| {
        if (std.mem.eql(u8, name, e.n)) return e.c;
    }
    return null;
}

/// 解析 `--dhcp-range=<start>,<end>[,<netmask>[,<leasetime>]]`
fn parseRange(cfg: *Config, arg: []const u8) !void {
    var it = std.mem.splitScalar(u8, arg, ',');
    const s_start = it.next() orelse return error.BadRange;
    const s_end = it.next() orelse return error.BadRange;

    const start = dhcpv4.parseIpv4(s_start) orelse return error.BadRange;
    const end = dhcpv4.parseIpv4(s_end) orelse return error.BadRange;

    var netmask: [4]u8 = .{ 255, 255, 255, 0 };
    var lease: u32 = cfg.lease_time;
    if (it.next()) |s_mask| {
        if (s_mask.len > 0) {
            if (std.mem.eql(u8, s_mask, "static")) {
                log.warning("--dhcp-range 的 static 模式（只为 --dhcp-host 服务）暂不支持，已跳过该池", .{});
                return;
            }
            netmask = dhcpv4.parseIpv4(s_mask) orelse return error.BadRange;
        }
    }
    if (it.next()) |s_lt| {
        if (s_lt.len > 0) lease = parseLeaseTime(s_lt) orelse return error.BadRange;
    }

    if (dhcpv4.maskPrefixLen(netmask)) |pl| {
        if (pl > dhcpv4.MAX_PREFIX_LEN and pl != 0) {
            // odhcpd 的 DHCPV4_MAX_PREFIX_LEN 限制：池不能比 /28 更小
            log.warning("--dhcp-range 的掩码 /{d} 比 /{d} 还小，dnsmasq/odhcpd 均不接受", .{ pl, dhcpv4.MAX_PREFIX_LEN });
        }
    }
    if (cfg.pools.items.len >= MAX_POOLS) return error.TooManyRanges;

    var p = dhcpv4.Pool{
        .start = start,
        .end = end,
        .netmask = netmask,
        .lease_time = lease,
        .interface = cfg.interface,
        .domain = cfg.domain,
    };
    // 广播地址按掩码推导（下发 option 28 用）
    p.router = dhcpv4.networkOf(start, netmask);
    // 网络号 +1 当作默认网关（dnsmasq 的行为是取本机在该网段的地址；
    // 没配 --dhcp-option=option:router 时这里给一个合理默认值）
    p.router = dhcpv4.u32ToIp(dhcpv4.ipToU32(p.router) + 1);
    try cfg.pools.append(cfg.allocator, p);
}

/// 解析 `--dhcp-host=<hwaddr>[,<ip>][,<name>][,<leasetime>]`
fn parseHost(cfg: *Config, arg: []const u8) !void {
    var mac: ?[6]u8 = null;
    var ip: ?[4]u8 = null;
    var name: ?[]const u8 = null;
    var lease: u32 = 0;
    var ignored = false;

    var it = std.mem.splitScalar(u8, arg, ',');
    while (it.next()) |f| {
        if (f.len == 0) continue;
        if (std.mem.eql(u8, f, "ignore")) {
            ignored = true;
            continue;
        }
        if (std.mem.startsWith(u8, f, "id:")) {
            log.warning("--dhcp-host 的 id:<client-id> 匹配尚未实现，该条只按 MAC 匹配", .{});
            continue;
        }
        if (std.mem.eql(u8, f, "set:") or std.mem.startsWith(u8, f, "set:") or
            std.mem.startsWith(u8, f, "tag:"))
        {
            log.warning("--dhcp-host 的 tag/set 尚未实现，已忽略字段 '{s}'", .{f});
            continue;
        }
        if (mac == null) {
            if (dhcpv4.parseMac(f)) |m| {
                mac = m;
                continue;
            }
        }
        if (ip == null) {
            if (dhcpv4.parseIpv4(f)) |v| {
                // 纯数字会被 parseIpv4 当 IP 接受（"12" -> 12.0.0.0），
                // 所以先看是不是租期写法
                if (std.mem.indexOfAny(u8, f, "hmsHMS") != null or ip != null) {
                    ip = v;
                    continue;
                }
                if (f.len <= 3 and std.mem.indexOfScalar(u8, f, '.') == null) {
                    // 形如 "12" —— 更可能是租期（12h 会带单位，这里只可能是秒数）
                    lease = parseLeaseTime(f) orelse v[0];
                    continue;
                }
                ip = v;
                continue;
            }
        }
        // 主机名：剩下的第一个非空字段。
        // 直接借用 argv 里的切片而不是 dupe —— 配置的生命周期不超过进程，
        // 每次 dupe 只会制造需要额外跟踪释放的内存。
        if (name == null and f.len > 0) {
            name = f;
            continue;
        }
        if (parseLeaseTime(f)) |lt| lease = lt;
    }

    if (ignored) {
        log.warning("--dhcp-host 的 ignore 语义（整条禁用某客户端）尚未实现，已忽略", .{});
        return;
    }
    if (mac == null) {
        log.warning("--dhcp-host='{s}' 里没有可识别的 MAC，已忽略", .{arg});
        return;
    }
    if (ip == null) {
        log.warning("--dhcp-host='{s}' 没有指定地址（仅按名字/租期绑定的语义尚未实现），已忽略", .{arg});
        return;
    }
    if (cfg.statics.items.len >= MAX_STATICS) return error.TooManyHosts;

    try cfg.statics.append(cfg.allocator, .{
        .mac = mac.?,
        .ip = ip.?,
        .hostname = name,
        .lease_time = lease,
    });
}

/// 解析 `--dhcp-option=[tag:]<code|option:name>[,<value>...]`
fn parseOption(cfg: *Config, arg: []const u8) !void {
    var it = std.mem.splitScalar(u8, arg, ',');
    const first = it.next() orelse return error.BadOption;
    if (std.mem.startsWith(u8, first, "tag:") or std.mem.startsWith(u8, first, "vendor:") or
        std.mem.startsWith(u8, first, "encap:"))
    {
        log.warning("--dhcp-option 的 tag/vendor/encap 形式尚未实现，已忽略 '{s}'", .{arg});
        return;
    }

    var code: u8 = 0;
    if (std.mem.startsWith(u8, first, "option:")) {
        code = optNameToCode(first["option:".len..]) orelse {
            log.warning("--dhcp-option 不认识的选项名 '{s}'，已忽略", .{first});
            return;
        };
    } else {
        code = std.fmt.parseInt(u8, first, 0) catch return error.BadOption;
    }

    var o = UserOpt{ .code = code };
    while (it.next()) |v| {
        if (v.len == 0) continue;
        if (dhcpv4.parseIpv4(v)) |ip4| {
            // 只要不含字母就是地址（纯数字形式如 "3" 也会被当成 0.0.0.3，
            // 这与 dnsmasq 对 option:router 这类地址型选项的处理一致）
            if (o.len + 4 > 255) break;
            @memcpy(o.data[o.len .. o.len + 4], &ip4);
            o.len += 4;
            continue;
        }
        if (o.len + v.len > 255) break;
        @memcpy(o.data[o.len .. o.len + v.len], v);
        o.len += @intCast(v.len);
    }
    if (o.len == 0) {
        log.warning("--dhcp-option='{s}' 没有值，已忽略", .{arg});
        return;
    }
    if (cfg.user_opts.items.len >= MAX_USER_OPTS) return error.TooManyOptions;
    try cfg.user_opts.append(cfg.allocator, o);
}

/// 解析整条命令行。返回 false 表示「有致命错误」。
///
/// 与 dnsmasq 一致的地方：`--dhcp-range` 必须存在才会启用 DHCP；
/// 不认识的选项直接报错（而不是静默忽略），避免配置写错了却毫无提示。
pub fn parseArgs(cfg: *Config, args: []const []const u8) !bool {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];

        if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-w")) {
            try writeStdout(usage_text);
            return false;
        }
        if (std.mem.eql(u8, a, "--version") or std.mem.eql(u8, a, "-v")) {
            try writeStdout("zig-dnsmasq (odhcpd applet) 2.93-zig\n");
            return false;
        }
        if (std.mem.eql(u8, a, "--test")) {
            cfg.test_only = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--zd-selftest")) {
            cfg.selftest = true;
            continue;
        }
        if (std.mem.eql(u8, a, "-d") or std.mem.eql(u8, a, "--no-daemon") or
            std.mem.eql(u8, a, "-k") or std.mem.eql(u8, a, "--keep-in-foreground"))
        {
            continue; // 本移植始终前台运行
        }
        if (std.mem.eql(u8, a, "--log-dhcp")) {
            cfg.log_dhcp = true;
            continue;
        }
        if (std.mem.eql(u8, a, "--dhcp-authoritative")) {
            cfg.authoritative = true;
            continue;
        }

        if (argOf(a, "--dhcp-range")) |v| {
            cfg.cli_conf_seen = true;
            try parseRange(cfg, v);
        } else if (argOf(a, "--dhcp-host")) |v| {
            cfg.cli_conf_seen = true;
            try parseHost(cfg, v);
        } else if (argOf(a, "--dhcp-option")) |v| {
            cfg.cli_conf_seen = true;
            try parseOption(cfg, v);
        } else if (argOf(a, "--dhcp-leasefile")) |v| {
            cfg.state_file = v;
        } else if (argOf(a, "--zd-dnsmasq-leasefile")) |v| {
            // v4 的租约文件（dnsmasq 格式）。
            //
            // **为什么必须是独立的一项**：2026-09-21 起 v4 只写这里、状态文件只写
            // v6 行（对齐 OpenWrt 原版分工，见 writeStateFile 的说明）。
            // 而 `--dhcp-leasefile` 只设状态文件路径，所以**命令行模式**下若不显式
            // 指定本项，v4 租约就会既写不出去、也读不回来 —— 后果正是
            // 「重启一次，全网设备重新拿地址」。UCI 模式不受影响
            // （那条路径由 `dhcp.@dnsmasq[0].leasefile` 提供）。
            cfg.dnsmasq_leasefile = v;
        } else if (argOf(a, "--dhcp-script")) |v| {
            cfg.script = v;
        } else if (std.mem.eql(u8, a, "--no-uci")) {
            cfg.no_uci = true;
        } else if (argOf(a, "--uci-file")) |v| {
            cfg.uci_path = v;
        } else if (argOf(a, "--uci-network")) |v| {
            cfg.uci_network_path = v;
        } else if (argOf(a, "--uci-state")) |v| {
            cfg.uci_state_path = v;
        } else if (argOf(a, "--zd-hosts-dir")) |v| {
            cfg.hosts_dir = v;
        } else if (argOf(a, "--zd-lock-file")) |v| {
            // 单实例锁的路径。生产用默认 /var/run/odhcpd.lock；
            // 本地 e2e 用 tmpdir 隔离（与 pidfile/statefile 一个思路），
            // 否则多个测试会互相抢同一把全局锁。
            cfg.lock_file = v;
        } else if (argOf(a, "--zd-server-id")) |v| {
            cfg.server_id = dhcpv4.parseIpv4(v) orelse {
                log.err("--zd-server-id='{s}' 不是合法 IPv4 地址", .{v});
                return false;
            };
        } else if (argOf(a, "--zd-port")) |v| {
            cfg.port = std.fmt.parseInt(u16, v, 10) catch {
                log.err("--zd-port='{s}' 不是合法端口号", .{v});
                return false;
            };
        } else if (argOf(a, "--zd-client-port")) |v| {
            cfg.client_port = std.fmt.parseInt(u16, v, 10) catch {
                log.err("--zd-client-port='{s}' 不是合法端口号", .{v});
                return false;
            };
        } else if (argOf(a, "--interface")) |v| {
            cfg.interface = v;
        } else if (argOf(a, "--pid-file")) |v| {
            cfg.pid_file = v;
        } else if (argOf(a, "--domain")) |v| {
            cfg.domain = v;
        } else if (argOf(a, "--dhcp-option-force")) |v| {
            cfg.cli_conf_seen = true;
            try parseOption(cfg, v);
        } else if (std.mem.startsWith(u8, a, "--dhcp-option-force=")) {
            cfg.cli_conf_seen = true;
            try parseOption(cfg, a["--dhcp-option-force=".len..]);
        } else if (std.mem.startsWith(u8, a, "--conf-file=") or
            std.mem.startsWith(u8, a, "--dhcp-ignore") or
            std.mem.startsWith(u8, a, "--dhcp-broadcast") or
            std.mem.startsWith(u8, a, "--dhcp-no-override") or
            std.mem.startsWith(u8, a, "--dhcp-boot") or
            std.mem.startsWith(u8, a, "--dhcp-relay") or
            std.mem.startsWith(u8, a, "--leasefile-ro"))
        {
            if (std.mem.startsWith(u8, a, "--conf-file=")) cfg.cli_conf_seen = true;
            log.warning("选项 '{s}' 已识别但尚未实现，已忽略", .{a});
        } else if (std.mem.startsWith(u8, a, "-")) {
            log.err("无法识别的选项 '{s}'", .{a});
            return false;
        } else {
            // 位置参数：dnsmasq 里是配置文件
            log.warning("位置参数（配置文件）'{s}' 暂不支持，已忽略", .{a});
        }
    }
    return true;
}

/// 取 `--opt=value` 的 value；不是这个选项则返回 null
fn argOf(a: []const u8, name: []const u8) ?[]const u8 {
    if (a.len <= name.len) return null;
    if (!std.mem.startsWith(u8, a, name)) return null;
    if (a[name.len] != '=') return null;
    return a[name.len + 1 ..];
}

/// 在命令行里找一个「裸值」（用于 `--pid-file /tmp/x.pid` 这种空格分隔形式）
fn nextValue(args: []const []const u8, i: *usize) ?[]const u8 {
    if (i.* + 1 >= args.len) return null;
    i.* += 1;
    return args[i.*];
}

const usage_text =
    \\用法: dnsmasq [选项]          与 dnsmasq 2.93 兼容的子集
    \\      odhcpd [选项]           （通过软链接调用同一个二进制）
    \\
    \\配置来源（二选一，自动判断）：
    \\  无参数（procd 的启动方式）  读 /etc/config/dhcp，odhcpd 风格
    \\  有配置类参数               用下面的命令行参数，dnsmasq 风格（不读 UCI）
    \\
    \\DHCPv4 地址池：
    \\  --dhcp-range=<起始>,<结束>[,<掩码>[,<租期>]]
    \\  --dhcp-host=<mac>[,<ip>[,<主机名>[,<租期>]]]      静态绑定
    \\  --dhcp-option=<号|option:名>,<值>[,<值>...]
    \\  --dhcp-leasefile=<路径>      租约状态文件（v6 状态；v4 见下一项）
    \\  --zd-dnsmasq-leasefile=<路径>  v4 租约文件（dnsmasq 格式；不指定则 v4 不持久化）
    \\  --dhcp-script=<路径>         租约变化时执行 <路径> <add|del> <mac> <ip> <名字>
    \\  --dhcp-authoritative         对未知请求也回 NAK
    \\通用：
    \\  --interface=<网卡>  --pid-file=<路径>  --domain=<域名>
    \\  --log-dhcp  --test  --help  --version
    \\UCI 模式（odhcpd 风格）：
    \\  --uci-file=<路径>           默认 /etc/config/dhcp
    \\  --uci-network=<路径>        默认 /etc/config/network（解析逻辑接口名用）
    \\  --uci-state=<路径>          默认 /var/state/network（netifd 运行时状态）
    \\  --no-uci                    强制忽略 UCI，只认命令行
    \\本移植扩展：
    \\  --zd-hosts-dir=<目录>        hosts 格式租约文件的输出目录（默认 /tmp/hosts）
    \\  --zd-lock-file=<路径>        单实例锁文件（默认 /var/run/odhcpd.lock）
    \\  --zd-server-id=<地址>        强制 server-identifier（默认按收包网卡推导）
    \\  --zd-port=<端口>             服务端口（默认 67，**仅供本机测试**）
    \\  --zd-client-port=<端口>      应答目标端口（默认 68，**仅供本机测试**）
    \\  --zd-selftest               回环自检：跑一次完整握手后退出（不碰物理网卡）
    \\  --applet=odhcpd              显式指定身份（不方便造软链接时用）
    \\
;

/// 直接往 fd 写，避免为了 --help/--version 引入一套 Io。
/// （std.debug.print 走的是 stderr，帮助信息应当到 stdout。）
fn writeStdout(text: []const u8) !void {
    var off: usize = 0;
    while (off < text.len) {
        const rc = system.write(1, text[off..].ptr, text.len - off);
        if (net.errno(rc) != .SUCCESS) return;
        const w = @as(usize, rc);
        if (w == 0) return;
        off += w;
    }
}

// ---------------------------------------------------------------------------
// 运行时
// ---------------------------------------------------------------------------

var g_stop = std.atomic.Value(bool).init(false);

/// 信号处理函数必须是 async-signal-safe：这里只做一次原子写。
/// 参数类型要用 `posix.SIG`（与本移植 server.zig 的 signalHandler 一致），
/// 写 `c_int` 会与 kernel 侧的 SIG 枚举对不上。
fn onSignal(_: posix.SIG) callconv(.c) void {
    g_stop.store(true, .monotonic);
}

/// SIGHUP → 触发配置重载（对齐上游 signal_reload → odhcpd_reload）。
/// **绝不能当退出**：官方 init 有 `procd_add_reload_trigger "dhcp"`，
/// 任何 `uci commit dhcp` 都会 SIGHUP 我们，若当退出就是一次不必要的重启。
var g_reload = std.atomic.Value(bool).init(false);

fn onSignalHup(_: posix.SIG) callconv(.c) void {
    g_reload.store(true, .monotonic);
}

/// IP_PKTINFO 控制消息的对齐辅助（对应内核的 CMSG_ALIGN/CMSG_SPACE/CMSG_LEN）
inline fn cmsgAlign(n: usize) usize {
    const a: usize = @sizeOf(usize);
    return (n + a - 1) & ~(a - 1);
}

/// 按 fd 写的小缓冲写入器。
///
/// 本移植整体不用 `std.fs`（0.16 起文件 IO 走新的 Io 接口，而这个项目的
/// 其它模块一律用 `posix.openat` + `posix.write` 的裸 fd 方式）。为了不引入
/// 第二套 IO 风格，这里自带一个 4 KiB 缓冲。
const FdWriter = struct {
    fd: posix.fd_t,
    buf: [4096]u8 = undefined,
    n: usize = 0,

    fn write(self: *FdWriter, bytes: []const u8) void {
        var rest = bytes;
        while (rest.len > 0) {
            const space = self.buf.len - self.n;
            if (space == 0) {
                self.flush();
                continue;
            }
            const take = @min(space, rest.len);
            @memcpy(self.buf[self.n .. self.n + take], rest[0..take]);
            self.n += take;
            rest = rest[take..];
        }
    }

    fn print(self: *FdWriter, comptime fmt: []const u8, args: anytype) void {
        var tmp: [1024]u8 = undefined;
        const s = std.fmt.bufPrint(&tmp, fmt, args) catch return;
        self.write(s);
    }

    fn flush(self: *FdWriter) void {
        var off: usize = 0;
        while (off < self.n) {
            const rc = system.write(self.fd, self.buf[off..].ptr, self.n - off);
            if (net.errno(rc) != .SUCCESS) break;
            const w = @as(usize, rc);
            if (w == 0) break;
            off += w;
        }
        self.n = 0;
    }
};

// ---------------------------------------------------------------------------
// 内核 ARP 表注入
// ---------------------------------------------------------------------------
//
// 背景：DHCP 应答里有一种情况是**单播到刚分配给客户端的地址**（yiaddr）。
// 此时客户端还没有配置这个地址，内核要发出去必须先解析 yiaddr -> MAC，
// 它只能发 ARP 请求；但没有任何主机持有该地址，所以不会有 ARP 应答，
// 包就被静默丢掉了。表现是「服务端日志显示发了 OFFER，客户端却一直
// broadcasting discover 直到放弃」。
//
// odhcpd 的做法（`dhcpv4.c:745-768`）：发包前先 `ioctl(SIOCSARP)` 插一条
// `ATF_COM` 条目，把「刚分配的地址」和「客户端 MAC」绑起来，让内核直接有
// 二层的下一跳。我们照抄这个做法。
//
// 布局照 glibc 的 `net/if_arp.h`：
//   struct arpreq { sockaddr arp_pa; sockaddr arp_ha; int arp_flags;
//                   sockaddr arp_netmask; char arp_dev[16]; };
// 这里直接用定长字节数组摆位，避免把 sockaddr 当 sockaddr_in 用带来的对齐坑。

const ATF_COM: c_int = 0x02;

const ArpReq = extern struct {
    /// sockaddr_in：family(u16) + port(u16, 网络序) + addr(4) + zero(8)
    arp_pa: [16]u8 = [_]u8{0} ** 16,
    /// odhcpd 把 MAC 拷进 `sa_data[0..6]`，即结构体第 2..8 字节
    arp_ha: [16]u8 = [_]u8{0} ** 16,
    arp_flags: c_int = 0,
    arp_netmask: [16]u8 = [_]u8{0} ** 16,
    arp_dev: [16]u8 = [_]u8{0} ** 16,
};

/// 往内核 ARP 表插一条「ip <-> mac」的临时条目（对应 odhcpd 的 ioctl(SIOCSARP)）。
///
/// `fd` 只要是任意 AF_INET 的 socket 就行（ioctl 用 fd 找 net namespace）。
fn arpSet(fd: posix.fd_t, ifname: []const u8, mac: []const u8, ip: [4]u8) !void {
    if (mac.len < 6) return error.BadMac;

    var req = ArpReq{};
    // arp_pa = sockaddr_in{ AF_INET, 68, ip }
    std.mem.writeInt(u16, req.arp_pa[0..2], posix.AF.INET, .little);
    std.mem.writeInt(u16, req.arp_pa[2..4], dhcpv4.CLIENT_PORT, .big);
    @memcpy(req.arp_pa[4..8], &ip);
    // arp_ha.sa_data[0..6] = mac
    @memcpy(req.arp_ha[2..8], mac[0..6]);
    req.arp_flags = ATF_COM;
    // arp_netmask 保持全 0（只用于 proxy arp）
    const n = @min(ifname.len, 15);
    @memcpy(req.arp_dev[0..n], ifname[0..n]);

    const rc = system.ioctl(fd, system.SIOCSARP, @intFromPtr(&req));
    const e = net.errno(rc);
    if (e != .SUCCESS) return error.ArpFailed;
}

/// `mkdir -p` 的单层版本（目录已存在时忽略 EEXIST）
fn mkdirIfNeeded(path: []const u8) void {
    var buf: [4096]u8 = undefined;
    if (path.len == 0 or path.len >= buf.len) return;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    _ = system.mkdir(buf[0..path.len :0].ptr, 0o755);
}

/// 解析一行状态记录：
/// `# <iface> <hexhwaddr> ipv4 <hostname> <valid_until> <hexaddr> 32 <addr>/32`
fn parseStateLine(line: []const u8, now: i64) ?dhcpv4.Lease {
    var f: [12][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.tokenizeAny(u8, line, " \t");
    while (it.next()) |tok| {
        if (n >= f.len) break;
        f[n] = tok;
        n += 1;
    }
    // 至少 9 个字段，且第 4 个是字面量 "ipv4"（v6 记录这一位不是它，天然排除）
    if (n < 9) return null;
    if (!std.mem.eql(u8, f[0], "#")) return null;
    if (!std.mem.eql(u8, f[3], "ipv4")) return null;

    const mac = parseMacText(f[2]) orelse return null;
    const ip = dhcpv4.parseIpv4(beforeSlash(f[8])) orelse return null;
    const valid = std.fmt.parseInt(i64, f[5], 10) catch return null;

    var l = dhcpv4.Lease{
        .ip = ip,
        .mac = mac,
        .mac_len = 6,
        .state = .bound,
    };

    // valid_until 的三种写法：
    //   * `-1`  = odhcpd 的 INFINITE_VALID（永不过期）
    //   * `0`   = 已过期
    //   * 其它 = **绝对墙钟秒**（odhcpd statefiles.c:576 写的是
    //            `valid_until - now + wall_time`，不是剩余秒数）
    // 另有一条兼容分支：本移植早期版本写的是「剩余秒数」，数值远小于
    // 2000-01-01，遇到就按相对时间解释，免得升级后旧文件里的租约全部
    // 被当成「1970 年就过期了」而丢弃。
    if (valid < 0) {
        l.expires = now + LEASE_INFINITE_SECS;
    } else if (valid < ABSOLUTE_TIME_FLOOR) {
        l.expires = now + valid;
    } else {
        l.expires = valid;
    }

    // 主机名：`broken\x20` 前缀是 odhcpd 标记「客户端报了非法名字」，
    // 这种名字不可用（同上 GHSA-hhmc-92hw-535f 的背景），直接不还原。
    var hbuf: [256]u8 = undefined;
    const esc = if (std.mem.startsWith(u8, f[4], "broken\\x20")) f[4]["broken\\x20".len..] else f[4];
    const broken = esc.ptr != f[4].ptr;
    const name = unescapeHostname(&hbuf, esc);
    if (!broken and !std.mem.eql(u8, name, "-") and hostnameValid(name)) {
        l.setHostname(name);
    }
    return l;
}

/// 解析一行 **dnsmasq 格式**的租约记录（v4 的权威来源）。
///
/// 格式对照 C `lease.c:286 lease_update_file()`：
///   `<到期epoch> <mac> <ip> <主机名|*> <client-id|*>`
/// 其中 MAC 是**带冒号**的小写十六进制（C 用 `%.2x` + `:` 拼出来）；
/// 非以太网类型的硬件地址会多一个 `%.2x-` 前缀（如 `6-aa:bb:...`）。
///
/// 为什么需要它：把 v4 状态行从 `/tmp/hosts/odhcpd` 摘掉之后（见
/// `writeStateFile` 的说明），启动恢复就不能再从那里读 v4 了，
/// 否则重启后每条续租都会当成新客户端 → 全网重新分配地址。
fn parseDnsmasqLeaseLine(line: []const u8) ?dhcpv4.Lease {
    var f: [8][]const u8 = undefined;
    var n: usize = 0;
    var it = std.mem.tokenizeAny(u8, line, " \t");
    while (it.next()) |tok| {
        if (n >= f.len) break;
        f[n] = tok;
        n += 1;
    }
    if (n < 4) return null;
    if (line.len > 0 and line[0] == '#') return null;

    const expires = std.fmt.parseInt(i64, f[0], 10) catch return null;

    // 非以太网地址形如 `6-aa:bb:cc:dd:ee:ff`：硬件类型在前，用 `-` 分隔。
    // 以太网地址本身不含 `-`，所以按第一个 `-` 截断是安全的。
    const mac_field = if (std.mem.indexOfScalar(u8, f[1], '-')) |dash| f[1][dash + 1 ..] else f[1];
    const mac = parseMacText(mac_field) orelse return null;
    const ip = dhcpv4.parseIpv4(f[2]) orelse return null;

    var l = dhcpv4.Lease{
        .ip = ip,
        .mac = mac,
        .mac_len = 6,
        .state = .bound,
        .expires = expires,
    };
    if (!std.mem.eql(u8, f[3], "*") and hostnameValid(f[3])) l.setHostname(f[3]);
    return l;
}

pub const Runtime = struct {
    cfg: *Config,
    allocator: Allocator,
    fd: posix.fd_t = -1,
    /// netlink 事件 socket（订阅 RTNLGRP_LINK + 地址组）：接口 up/增删/改 MTU
    /// 时内核会推 RTM_NEWLINK/RTM_DELLINK，据此重新绑定网卡、补起 v6。
    /// -1 表示没建起来（退化为 housekeep 里的定时重查）。
    nl_fd: posix.fd_t = -1,
    /// 收到 LINK 事件后置位，真正的重活在节拍里合并做（一次 up 会来好几个事件）。
    iface_dirty: bool = false,
    /// 建 socket 时 SO_BINDTODEVICE 是否成功。失败说明当时网卡还不存在，
    /// 需要在 LINK 事件到来时补绑。
    bound_to_device: bool = false,
    /// v4/v6 服务当前是否处于「已启动」状态（由 `reloadServices()` 按
    /// 接口 IFF_RUNNING 决定）。未启动时 DHCP 请求会被直接丢弃 ——
    /// 对齐上游「接口不在 RUNNING 就整个关闭，不存在半配置状态」的模型。
    services_active: bool = false,
    /// ioctl 用的常驻 socket（读 IFF_RUNNING；上游同样有一个 ioctl_sock）
    ctl_fd: posix.fd_t = -1,
    /// 单实例锁的 fd（`acquireInstanceLock()` 拿到后放这里）。
    /// **必须保持打开**：flock 的锁随 fd 关闭而释放，一旦关闭就形同没上锁。
    /// 进程退出时由内核统一收拾，所以这里不需要显式 close。
    instance_lock_fd: posix.fd_t = -1,
    /// 专供 `ioctl(SIOCSARP)` 用的临时 socket，进程生命周期内复用，
    /// 避免每次应答都建一次。
    arp_fd: posix.fd_t = -1,
    leases: dhcpv4.LeaseDb = undefined,
    lease_storage: [MAX_LEASES]dhcpv4.Lease = undefined,
    /// 每个客户端上一次被写入文件的地址指纹，用于判断是否需要重写文件
    hosts_hash: u64 = 0,
    last_reap: i64 = 0,
    packets_in: u64 = 0,
    packets_out: u64 = 0,
    /// buildReply 会把「构造出来的应答报文」留在这里，供 replyDest 读取
    /// hlen/yiaddr/msgType（odhcpd 也是把 reply 报文传进 set_dest_addr 的）。
    reply_of_finish: dhcpv4.Message = .{},
    /// DHCPv6 / RA / NDP 运行时（cfg.v6 里有启用的接口才建，见 v6rt.zig）。
    /// 生命周期挂在 run() 上，退出时销毁并关闭 socket。
    v6: ?*v6rt.V6Runtime = null,

    pub fn init(cfg: *Config) Runtime {
        return .{ .cfg = cfg, .allocator = cfg.allocator };
    }

    /// 建立 socket（逐条对照 odhcpd dhcpv4.c:1505-1555）
    fn openSocket(self: *Runtime) !void {
        const fd = try net.socketCreate(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
        errdefer net.close(fd);

        try net.setReuseAddr(fd);
        // 广播回复（255.255.255.255）必须显式打开，否则 sendto 直接 EACCES
        net.setBroadcast(fd);
        // IP_PKTINFO：收包时拿到「从哪块网卡进来的」，回包时指定从哪块网卡出去。
        // 没有它就只能靠内核选路由，多网卡（br-lan + wan）场景会发错网卡。
        try self.setSockOptInt(fd, posix.IPPROTO.IP, system.IP.PKTINFO, 1);
        // DHCP 报文不要分片发现（odhcpd 同样设 IP_PMTUDISC_DONT）
        self.setSockOptInt(fd, posix.IPPROTO.IP, system.IP.MTU_DISCOVER, 2) catch {};
        if (self.cfg.interface) |ifname| {
            // SO_BINDTODEVICE：只收该网卡的包（对应 odhcpd 的同名调用）
            const rc = system.setsockopt(fd, posix.SOL.SOCKET, posix.SO.BINDTODEVICE, ifname.ptr, @intCast(ifname.len));
            if (net.errno(rc) != .SUCCESS) {
                log.warning("SO_BINDTODEVICE({s}) 失败，改为监听所有网卡", .{ifname});
            } else {
                self.bound_to_device = true;
            }
        }

        var sa = addr.SockAddr.fromIp4(0, self.cfg.port);
        try net.bind(fd, &sa);
        self.fd = fd;

        // 用于 ioctl(SIOCSARP)。失败只降级：少了它单播应答发不出去，
        // 但日志里会明确报出来，不至于把整个 DHCP 服务拖死。
        self.arp_fd = net.socketCreate(posix.AF.INET, posix.SOCK.DGRAM, 0) catch |e| blk: {
            log.warning("无法建立 ARP 用的 socket（单播应答可能失败）: {s}", .{@errorName(e)});
            break :blk -1;
        };
    }

    fn closeArp(self: *Runtime) void {
        if (self.arp_fd >= 0) {
            net.close(self.arp_fd);
            self.arp_fd = -1;
        }
    }

    /// 发包前插一条 ARP 条目 —— 只针对「单播到刚分配的地址」那一种情况。
    fn ensureArp(self: *Runtime, req: *const dhcpv4.Message, dest: dhcpv4.Dest) void {
        if (!dest.needs_arp) return;
        // 回环自检（`--zd-selftest`，池落在 127/8）走的是本地交付，不需要也不该
        // 往 ARP 表里塞 127.x 的条目，否则只会刷一堆 EINVAL 噪音。
        if (isLoopback(dest.ip)) return;
        if (self.arp_fd < 0) return;
        const ifname = self.cfg.interface orelse "lan";
        arpSet(self.arp_fd, ifname, req.chaddrSlice(), dest.ip) catch |e| {
            log.warning("ioctl(SIOCSARP) {s} -> {d}.{d}.{d}.{d} 失败: {s}", .{
                macText(req.chaddrSlice()),
                dest.ip[0],
                dest.ip[1],
                dest.ip[2],
                dest.ip[3],
                @errorName(e),
            });
        };
    }

    fn setSockOptInt(self: *Runtime, fd: posix.fd_t, level: i32, name: u32, value: c_int) !void {
        _ = self;
        const bytes = std.mem.toBytes(value);
        const rc = system.setsockopt(fd, level, name, &bytes, @sizeOf(c_int));
        if (net.errno(rc) != .SUCCESS) return error.SockOptFailed;
    }

    /// 查某块网卡上的 IPv4 地址（用作 server-identifier 与 option 54）
    fn ifaceIp4(self: *Runtime, ifindex: u32) ?[4]u8 {
        var list: std.ArrayListUnmanaged(net.IfaceAddr) = .empty;
        defer list.deinit(self.allocator);
        net.listIfaceAddrs(self.allocator, &list) catch return null;
        for (list.items) |ia| {
            if (ia.ifindex != ifindex) continue;
            if (ia.sa.family() != posix.AF.INET) continue;
            const p: *const std.posix.sockaddr.in = @ptrCast(&ia.sa.store);
            return dhcpv4.u32ToIp(std.mem.bigToNative(u32, p.addr));
        }
        return null;
    }

    /// 按网卡名取它当前的 IPv4 地址（`ifaceIp4` 按 ifindex 查，这里包一层）。
    fn ifaceIp4ByName(self: *Runtime, name: []const u8) ?[4]u8 {
        const idx = net.ifaceIndex(name) orelse return null;
        return self.ifaceIp4(idx);
    }

    /// 接口当前是否处于 RUNNING（对齐上游的 `ifflags & IFF_RUNNING` 判断）。
    ///
    /// 网桥的 IFF_RUNNING 要等至少一个端口 forwarding 才置位 —— 冷启动时
    /// br-lan 在 STP listening 阶段它未置位（实测比进程启动晚 38 秒）。
    fn ifaceRunning(self: *Runtime) bool {
        const name = self.cfg.interface orelse return true; // 不限接口 → 视为就绪
        const flags = net.getIfFlags(self.ctl_fd, name) orelse return false;
        return (flags & net.IFF_RUNNING) != 0;
    }

    /// 对齐上游 `reload_services()`（config.c:2019-2034）：按接口 IFF_RUNNING
    /// 决定 v4/v6 服务的启停。
    ///
    /// 上游的规则是「接口不在 RUNNING 就整个 close_interface，**不存在半配置
    /// 状态**」。我们此前在冷启动时处于半配置：socket 起来了但网关是 0.0.0.0、
    /// RA 发不出去 —— 设备拿到 IP 却没有网关，必须手动重启才恢复。
    fn reloadServices(self: *Runtime) void {
        const running = self.ifaceRunning();
        const name = self.cfg.interface orelse "-";

        if (running) {
            if (!self.services_active) {
                self.services_active = true;
                log.notice("接口 {s} 已 RUNNING：DHCPv4/DHCPv6/RA/NDP 服务启动", .{name});
            }
            self.refreshGateway();
            self.startV6();
        } else {
            if (self.services_active) {
                self.services_active = false;
                log.warning("接口 {s} 未 RUNNING：暂停 DHCPv4/RA 服务，等待接口就绪" ++
                    "（STP listening / 端口未 forwarding 时属于正常现象）", .{name});
            }
            self.stopV6();
        }
        self.dumpBootState();
    }

    /// 刷新网关地址：`pool.router` 默认取「接口自己的 IPv4」，而那是在 UCI 解析
    /// （进程启动）那一刻取的 —— 接口还没配地址就是 0.0.0.0，option 3 会被
    /// 省略，设备拿到 IP 却没有网关。
    /// 上游在每次接口事件里重算：dhcpv4_setup_addresses() 把 own_ip 清成
    /// INADDR_ANY 后从 oaddrs4[0] 重取（dhcpv4.c:1367-1375）。
    /// 显式配置的网关（option router）不覆盖。
    fn refreshGateway(self: *Runtime) void {
        var cur: [4]u8 = undefined;
        var have_cur = false;
        if (self.cfg.interface) |ifname| {
            if (self.ifaceIp4ByName(ifname)) |ip| {
                cur = ip;
                have_cur = true;
            }
        }
        if (!have_cur) return;
        for (self.cfg.pools.items) |*p| {
            if (p.router_from_config) continue;
            if (std.mem.eql(u8, &p.router, &cur)) continue;
            var old: [16]u8 = undefined;
            const oldt = dhcpv4.ipText(p.router, &old);
            p.router = cur;
            var nb: [16]u8 = undefined;
            log.notice("网关地址刷新为 {s}（原 {s}）—— 来自网卡当前 IPv4", .{
                dhcpv4.ipText(cur, &nb), oldt,
            });
        }
    }

    /// 起 DHCPv6 / RA / NDP（UCI 里配了 ra/dhcpv6/ndp 才有内容）。
    /// 抽成独立方法，好让接口就绪/重载时反复调用（见 reloadServices()）。
    fn startV6(self: *Runtime) void {
        if (self.v6 != null) return;
        if (self.cfg.v6.items.len == 0) return;
        if (self.allocator.create(v6rt.V6Runtime)) |v| {
            v.* = v6rt.V6Runtime.init(self.cfg.allocator);
            v.start(self.cfg.v6.items);
            if (v.ifaces.items.len > 0) {
                self.v6 = v;
                log.notice("DHCPv6/RA/NDP 已启用：{d} 个 v6 接口", .{v.ifaces.items.len});
            } else {
                v.deinit();
                self.allocator.destroy(v);
            }
        } else |_| {
            log.warning("v6 运行时内存不足，DHCPv6/RA/NDP 不启用", .{});
        }
    }

    /// 停掉 v6（RA/DHCPv6/NDP）。接口未 RUNNING 时上游同样会关掉这些 socket。
    fn stopV6(self: *Runtime) void {
        if (self.v6) |v| {
            v.deinit();
            self.allocator.destroy(v);
            self.v6 = null;
            log.notice("DHCPv6/RA/NDP 已停用（接口未 RUNNING）", .{});
        }
    }

    /// 收到 LINK 事件后的重查：补绑网卡 → 按最新 RUNNING 状态重配服务。
    fn recheckInterface(self: *Runtime) void {
        self.iface_dirty = false;

        // ★ 冷启动特有的坑：池的网段要从「接口地址」推导，而 UCI 解析发生在
        // 进程启动那一刻 —— 那时 br-lan 还没地址，**池根本建不出来**
        // （cfg.pools 为空）。此后我的网关刷新无从谈起，整个 DHCP 永远起不来
        // （实测：冷启动后 udhcpc leasefail）。接口就绪后必须重读一次配置。
        if (self.cfg.pools.items.len == 0 and !self.cfg.cli_conf_seen and !self.cfg.no_uci) {
            log.notice("当前没有任何地址池（启动早于接口就绪），重读 UCI 配置", .{});
            self.reloadConfig();
            return; // reloadConfig 内部已做 refreshGateway + reloadServices + 落盘
        }

        // 补绑网卡：之前 BINDTODEVICE 失败（网卡还不存在），现在有了就重开 socket
        if (!self.bound_to_device) {
            if (self.cfg.interface) |ifname| {
                if (net.ifaceIndex(ifname)) |_| {
                    log.notice("网卡 {s} 已就绪，重新建立 DHCP socket 并绑定该网卡", .{ifname});
                    const old = self.fd;
                    self.openSocket() catch |e| {
                        log.warning("重新建立 socket 失败: {s}（保留原有 socket）", .{@errorName(e)});
                        return;
                    };
                    if (old >= 0 and old != self.fd) net.close(old);
                }
            }
        }

        self.reloadServices();
    }

    /// SIGHUP：重读 UCI 并按当前接口状态重配（对齐上游 `odhcpd_reload()`）。
    ///
    /// 之前把 SIGHUP 当退出 —— 而官方 init 有
    /// `procd_add_reload_trigger "dhcp"` + `reload_service(){ procd_send_signal odhcpd }`，
    /// 任何 `uci commit dhcp` 都会 SIGHUP 我们 → 进程退出 → 只能靠 procd respawn
    /// 兜底（冷启动时观察到的多个 PID 由此而来）。
    ///
    /// 注意：重复加载会泄漏上一轮 UCI 的字符串（字符串 arena 只增不减），
    /// reload 是低频操作，可接受。
    fn reloadConfig(self: *Runtime) void {
        log.notice("SIGHUP：重读 UCI 配置并按接口状态重配", .{});
        self.cfg.pools.clearRetainingCapacity();
        self.cfg.statics.clearRetainingCapacity();
        self.cfg.v6.clearRetainingCapacity();

        const st = uci_dhcp.loadFromFiles(self.cfg, .{
            .dhcp_path = self.cfg.uci_path,
            .network_path = self.cfg.uci_network_path,
            .state_path = self.cfg.uci_state_path,
        }) catch |e| {
            log.err("重读 UCI 失败：{s}（沿用当前配置继续服务）", .{@errorName(e)});
            return;
        };
        log.notice("重载完成：段 {d}，池 {d}，静态 {d}，maindhcp={s}", .{
            st.sections, st.pools, st.statics, if (st.maindhcp) "1" else "0",
        });
        self.refreshGateway();
        self.reloadServices();
    }

    pub fn run(self: *Runtime) !void {
        // ioctl 用的常驻 socket（读 IFF_RUNNING；上游同样有一个 ioctl_sock）
        self.ctl_fd = net.socketCreate(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP) catch -1;
        defer if (self.ctl_fd >= 0) net.close(self.ctl_fd);

        try self.openSocket();
        defer if (self.fd >= 0) net.close(self.fd);
        defer self.closeArp();

        self.leases = dhcpv4.LeaseDb.init(&self.lease_storage);

        try self.installSignals();
        self.writePidFile();

        log.notice("odhcpd applet 已启动：{d} 个地址池，{d} 条静态绑定，监听 UDP :{d}{s}", .{
            self.cfg.pools.items.len,
            self.cfg.statics.items.len,
            self.cfg.port,
            if (self.cfg.interface) |i| i else "（全部网卡）",
        });
        self.logPools();
        self.dumpBootState();

        if (self.cfg.pools.items.len == 0) {
            log.err("没有任何 --dhcp-range，DHCP 服务不会响应任何请求（与 dnsmasq 行为一致）", .{});
        }

        // 先把上一轮（可能是 odhcpd 留下的）租约读回来，再写文件 —— 顺序反了会
        // 先把文件 truncate 成空，恢复出来的永远是 0 条。
        self.loadLeaseFile();
        self.writeLeaseFiles() catch |e| log.warning("写租约文件失败: {s}", .{@errorName(e)});

        // ★ 对齐上游 reload_services()：按 IFF_RUNNING 决定 v4/v6 服务的启停。
        // 冷启动时 br-lan 在 STP listening、IFF_RUNNING 未置位 —— 此刻不服务，
        // 等端口 forwarding（内核推 LINK 事件）后自动启动。不再「半配置裸奔」。
        self.reloadServices();

        // 订阅接口事件：网卡 up/down、地址增删时据此重配服务。
        self.nl_fd = net.openRtnlEventSocket(
            net.RTNLGRP_LINK | net.RTNLGRP_IPV4_IFADDR | net.RTNLGRP_IPV6_IFADDR,
            "odhcpd",
        );
        if (self.nl_fd >= 0) {
            log.notice("已订阅 netlink 接口事件（RTNLGRP_LINK）：网卡就绪时自动补绑/补起 v6", .{});
            // 启动这一刻也可能刚好赶上接口变化，先置一次脏标记，让首个节拍重查
            self.iface_dirty = true;
        }
        defer if (self.nl_fd >= 0) net.close(self.nl_fd);

        var buf: [MAX_PACKET]u8 = undefined;
        var control: [128]u8 align(@alignOf(usize)) = undefined;
        var last_tick_ms: i64 = 0;

        while (!g_stop.load(.monotonic)) {
            // fds[0] = DHCPv4；其后是 v6 的（netlink 事件 socket + 每接口
            // ICMPv6 raw + UDP 547，最多 8 接口 = 17 个）；netlink 挂在最后
            var fds: [1 + 1 + 8 * 2 + 1]posix.pollfd = undefined;
            fds[0] = .{ .fd = self.fd, .events = posix.POLL.IN, .revents = 0 };
            var nfds: usize = 1;
            if (self.v6) |v| nfds += v.fillFds(fds[1..]);

            var nl_idx: ?usize = null;
            if (self.nl_fd >= 0) {
                fds[nfds] = .{ .fd = self.nl_fd, .events = posix.POLL.IN, .revents = 0 };
                nl_idx = nfds;
                nfds += 1;
            }

            // poll 的 EINTR 由 std 内部重试，错误集里没有 Interrupted
            const n = posix.poll(fds[0..nfds], 1000) catch |e| {
                log.warning("poll 失败: {s}", .{@errorName(e)});
                continue;
            };

            // 每秒一次公共节拍：v4 的租约回收 + v6 的地址刷新/周期 RA/租约清理。
            // 不能只放在 poll 超时路径 —— 流量一多 tick 会被饿死（RA 断供，
            // 客户端的 SLAAC 地址会跟着过期的那种事故）。
            const now_ms = util.monoMillis();
            if (now_ms - last_tick_ms >= 1000) {
                last_tick_ms = now_ms;
                // SIGHUP → 重读 UCI 并重配（对齐上游 odhcpd_reload）
                if (g_reload.swap(false, .monotonic)) self.reloadConfig();
                // 接口刚就绪（或刚变化）→ 补绑网卡 / 刷新网关 / 重配服务
                if (self.iface_dirty) self.recheckInterface();
                self.housekeep();
                if (self.v6) |v| {
                    v.tick();
                    if (v.dirty) {
                        // 新的 DHCPv6 分配 → 重写状态文件（LuCI v6 租约页）
                        v.dirty = false;
                        self.writeLeaseFiles() catch {};
                    }
                }
            }
            // ---- netlink 接口事件 ----
            // 网卡 up/增删/配地址都会推事件。这里只置标记，真正的重活在下面的
            // 节拍里合并做（一次 up 会连推好几个事件，逐个处理只是白干）。
            if (nl_idx) |i| {
                if ((fds[i].revents & posix.POLL.IN) != 0) {
                    const batch = net.drainRtnlEvents(self.nl_fd);
                    if (batch.link or batch.addr) self.iface_dirty = true;
                }
            }
            if (n == 0) continue;

            if ((fds[0].revents & posix.POLL.IN) != 0) {
                const got = self.recvPacket(&buf, &control) catch |e| switch (e) {
                    error.WouldBlock, error.Interrupted => continue,
                    else => continue,
                };
                if (got.len != 0) {
                    self.packets_in += 1;
                    self.handle(got.buf[0..got.len], got.ifindex, got.src);
                }
            }
            if (self.v6) |v| v.dispatch(fds[1..nfds]);
        }

        if (self.v6) |v| {
            log.notice("v6 统计：收 {d} / 发 {d}", .{ v.packets_in, v.packets_out });
            v.deinit();
            self.allocator.destroy(v);
            self.v6 = null;
        }

        log.notice("收到停止信号，正在退出（收 {d} / 发 {d}）", .{ self.packets_in, self.packets_out });
        self.removePidFile();
    }

    fn logPools(self: *Runtime) void {
        for (self.cfg.pools.items, 0..) |p, i| {
            var b1: [16]u8 = undefined;
            var b2: [16]u8 = undefined;
            var b3: [16]u8 = undefined;
            log.notice("  池#{d} {s}-{s} /{?d} 网关 {s} 租期 {d}s", .{
                i,
                dhcpv4.ipText(p.start, &b1),
                dhcpv4.ipText(p.end, &b2),
                dhcpv4.maskPrefixLen(p.netmask),
                dhcpv4.ipText(p.router, &b3),
                p.lease_time,
            });
        }
        for (self.cfg.statics.items) |s| {
            var b: [16]u8 = undefined;
            const ipt = dhcpv4.ipText(s.ip, &b);
            if (s.hostname) |h| {
                log.notice("  静态 {s} -> {s} ({s})", .{ macText(&s.mac), ipt, h });
            } else {
                log.notice("  静态 {s} -> {s}", .{ macText(&s.mac), ipt });
            }
        }
    }

    const RecvResult = struct {
        buf: *[MAX_PACKET]u8,
        ifindex: u32,
        src: dhcpv4.Dest,
        len: usize,
    };

    const RecvError = error{ WouldBlock, Interrupted, RecvFailed };

    /// 收一个包，并用 IP_PKTINFO 取出收包网卡的 ifindex
    fn recvPacket(self: *Runtime, buf: *[MAX_PACKET]u8, control: *[128]u8) RecvError!RecvResult {
        var src_store: addr.SockAddr = undefined;
        var iov = [1]posix.iovec{.{ .base = buf, .len = buf.len }};
        var msg = system.msghdr{
            .name = @ptrCast(&src_store.store),
            .namelen = @sizeOf(@TypeOf(src_store.store)),
            .iov = &iov,
            .iovlen = 1,
            .control = control,
            .controllen = control.len,
            .flags = 0,
        };
        const rc = system.recvmsg(self.fd, &msg, 0);
        switch (net.errno(rc)) {
            .SUCCESS => {},
            .AGAIN => return error.WouldBlock,
            .INTR => return error.Interrupted,
            else => |e| {
                log.warning("recvmsg 失败: errno={d}", .{@intFromEnum(e)});
                return error.RecvFailed;
            },
        }
        const len = @as(usize, rc);
        if (len == 0) return .{ .buf = buf, .ifindex = 0, .src = .{ .ip = dhcpv4.IP_ANY, .port = 0 }, .len = 0 };

        const sin: *const posix.sockaddr.in = @ptrCast(&src_store.store);
        const src = dhcpv4.Dest{
            .ip = dhcpv4.u32ToIp(std.mem.bigToNative(u32, sin.addr)),
            .port = std.mem.bigToNative(u16, sin.port),
        };

        // 从控制消息里取 ifindex
        var ifindex: u32 = 0;
        if (msg.controllen >= @sizeOf(system.cmsghdr)) {
            const base: [*]u8 = @ptrCast(control);
            var off: usize = 0;
            while (off + @sizeOf(system.cmsghdr) <= msg.controllen) {
                const c: *system.cmsghdr = @ptrCast(@alignCast(base + off));
                if (c.level == posix.IPPROTO.IP and c.type == system.IP.PKTINFO) {
                    const pi: *const system.in_pktinfo =
                        @ptrCast(@alignCast(base + off + cmsgAlign(@sizeOf(system.cmsghdr))));
                    ifindex = @intCast(pi.ifindex);
                    break;
                }
                if (c.len == 0) break;
                off += cmsgAlign(c.len);
            }
        }
        return .{ .buf = buf, .ifindex = ifindex, .src = src, .len = len };
    }

    /// 发一个包，并指定从哪块网卡出去（IP_PKTINFO 的 spec_dst/ifindex）
    /// 测试用端口重映射：把应答端口从协议默认值（67/68）换掉。
    /// 生产环境两个端口都用默认值，这里直接原样返回。
    fn remapDest(self: *Runtime, d: dhcpv4.Dest) dhcpv4.Dest {
        var out = d;
        if (self.cfg.client_port != dhcpv4.CLIENT_PORT and out.port == dhcpv4.CLIENT_PORT)
            out.port = self.cfg.client_port;
        return out;
    }

    fn sendPacket(self: *Runtime, dest: dhcpv4.Dest, ifindex: u32, payload: []const u8) !void {
        var dst = addr.SockAddr.fromIp4(std.mem.nativeToBig(u32, dhcpv4.ipToU32(dest.ip)), dest.port);
        var iov = [1]posix.iovec_const{.{ .base = payload.ptr, .len = payload.len }};

        var control: [64]u8 align(@alignOf(usize)) = [_]u8{0} ** 64;
        var msg = system.msghdr_const{
            .name = @ptrCast(&dst.store),
            .namelen = dst.len,
            .iov = &iov,
            .iovlen = 1,
            .control = null,
            .controllen = 0,
            .flags = 0,
        };

        if (ifindex != 0) {
            const c: *system.cmsghdr = @ptrCast(@alignCast(&control));
            c.level = posix.IPPROTO.IP;
            c.type = system.IP.PKTINFO;
            c.len = cmsgAlign(@sizeOf(system.cmsghdr)) + @sizeOf(system.in_pktinfo);
            const pi: *system.in_pktinfo = @ptrCast(@alignCast(&control[cmsgAlign(@sizeOf(system.cmsghdr))]));
            pi.* = .{ .ifindex = @intCast(ifindex), .spec_dst = 0, .addr = 0 };
            msg.control = &control;
            msg.controllen = c.len;
        }

        const rc = system.sendmsg(self.fd, &msg, 0);
        if (net.errno(rc) != .SUCCESS) return error.SendFailed;
        self.packets_out += 1;
    }

    fn housekeep(self: *Runtime) void {
        const now = util.dnsmasqTime();
        if (now - self.last_reap < 60) return;
        self.last_reap = now;
        const n = self.leases.reap(now);
        if (n > 0) {
            if (self.cfg.log_dhcp) log.info("回收了 {d} 条过期租约", .{n});
            self.writeLeaseFiles() catch |e| log.warning("写租约文件失败: {s}", .{@errorName(e)});
        }
    }

    // -----------------------------------------------------------------------
    // 协议处理
    // -----------------------------------------------------------------------

    fn handle(self: *Runtime, raw: []const u8, ifindex: u32, src: dhcpv4.Dest) void {
        // 接口未 RUNNING（STP listening 等）时不服务 —— 对齐上游
        // 「不在 RUNNING 就整个关闭」的模型，绝不给出半配置的应答。
        if (!self.services_active) return;
        const req = dhcpv4.parse(raw) orelse {
            if (self.cfg.log_dhcp) log.info("丢弃畸形报文（{d} 字节，无 magic cookie）", .{raw.len});
            return;
        };
        if (req.op != @intFromEnum(dhcpv4.Op.bootrequest)) return;

        const mt = req.msgType();
        if (self.cfg.log_dhcp) {
            log.info("收到 {s} xid={x} mac={s} ifindex={d}", .{
                msgName(mt),
                std.mem.readInt(u32, &req.xid, .big),
                macText(req.chaddrSlice()),
                ifindex,
            });
        }

        switch (mt) {
            @intFromEnum(dhcpv4.Msg.discover) => self.doDiscover(&req, ifindex, src),
            @intFromEnum(dhcpv4.Msg.request) => self.doRequest(&req, ifindex, src),
            @intFromEnum(dhcpv4.Msg.release) => self.doRelease(&req),
            @intFromEnum(dhcpv4.Msg.decline) => self.doDecline(&req),
            @intFromEnum(dhcpv4.Msg.inform) => self.doInform(&req, ifindex, src),
            else => {
                if (self.cfg.log_dhcp) log.info("  忽略的消息类型 {d}", .{mt});
            },
        }
    }

    /// 找到 request 适用的池。odhcpd/dnsmasq 都是按「收包网卡」选池；
    /// 这里再退一步：若池绑定了 interface 就要求网卡名匹配。
    fn pickPool(self: *Runtime, req: *const dhcpv4.Message) ?*dhcpv4.Pool {
        if (self.cfg.pools.items.len == 0) return null;
        // 单池场景直接用；多池时按 option 50 / giaddr 的网段挑
        if (self.cfg.pools.items.len == 1) return &self.cfg.pools.items[0];

        const hint = req.optionIp(dhcpv4.Opt.requested_ip) orelse req.ciaddr;
        if (!dhcpv4.ipIsZero(hint)) {
            for (self.cfg.pools.items) |*p| {
                // Zig 不允许对 [4]u8 直接用 ==，先取网络号再按数值比
                const hn = dhcpv4.ipToU32(dhcpv4.networkOf(hint, p.netmask));
                const pn = dhcpv4.ipToU32(dhcpv4.networkOf(p.start, p.netmask));
                if (hn == pn and p.contains(hint)) return p;
            }
        }
        return &self.cfg.pools.items[0];
    }

    fn serverId(self: *Runtime, ifindex: u32, pool: *const dhcpv4.Pool) [4]u8 {
        if (self.cfg.server_id) |s| return s;
        if (ifindex != 0) {
            if (self.ifaceIp4(ifindex)) |ip| return ip;
        }
        return pool.router;
    }

    fn doDiscover(self: *Runtime, req: *const dhcpv4.Message, ifindex: u32, src: dhcpv4.Dest) void {
        const pool = self.pickPool(req) orelse return;
        const now = util.dnsmasqTime();
        const mac = req.chaddrSlice();

        const l = self.leases.alloc(pool, self.cfg.statics.items, mac, req.clientId(), req.optionIp(dhcpv4.Opt.requested_ip), now) catch |e| {
            log.warning("无法为 {s} 分配地址: {s}", .{ macText(mac), @errorName(e) });
            return;
        };
        if (req.hostname()) |h| {
            self.applyClientHostname(l, mac, h);
        }

        const sid = self.serverId(ifindex, pool);
        var out: [MAX_PACKET]u8 = undefined;
        const n = self.buildReply(&out, req, l, pool, sid, .offer, req.optionIp(dhcpv4.Opt.requested_ip)) orelse return;
        const dest = self.remapDest(dhcpv4.replyDest(req, &self.reply_of_finish, src));
        // 单播到刚分配的地址时，先插一条 ARP 条目，否则内核发不出去
        self.ensureArp(req, dest);
        self.sendPacket(dest, ifindex, out[0..n]) catch |e| {
            log.warning("发 OFFER 失败: {s}", .{@errorName(e)});
            return;
        };
        if (self.cfg.log_dhcp) {
            var b: [16]u8 = undefined;
            log.info("  -> OFFER {s} 给 {s}", .{ dhcpv4.ipText(l.ip, &b), macText(mac) });
        }
    }

    fn doRequest(self: *Runtime, req: *const dhcpv4.Message, ifindex: u32, src: dhcpv4.Dest) void {
        const pool = self.pickPool(req) orelse return;
        const now = util.dnsmasqTime();
        const mac = req.chaddrSlice();

        // RFC2131 §4.3.2：REQUEST 里点名要的地址优先取 option 50，其次 ciaddr
        const want = req.optionIp(dhcpv4.Opt.requested_ip) orelse req.ciaddr;
        const sid = self.serverId(ifindex, pool);

        // 客户端在 option 54 里指定了别的服务器（SELECTING 阶段的广播）
        // —— 那是给别人的，我们必须闭嘴，否则会跟别的 DHCP 服务器打架。
        if (req.optionIp(dhcpv4.Opt.server_id)) |other| {
            if (dhcpv4.ipToU32(other) != dhcpv4.ipToU32(sid)) {
                if (self.cfg.log_dhcp) {
                    var b: [16]u8 = undefined;
                    log.info("  REQUEST 指名了别的服务器 {s}，不响应", .{dhcpv4.ipText(other, &b)});
                }
                return;
            }
        }

        // 提示地址要用 `want`（option 50 优先、其次 ciaddr），不能只给 option 50：
        // **续租（RENEWING）的 REQUEST 只有 ciaddr、不带 option 50** —— 少了这一半，
        // 租约表里又查不到该客户端时（典型就是重启后没恢复租约），分配器会跳过
        // 「客户端点名的地址」直接去池里顺着游标拿下一个，表现出来就是
        // 「重启一次，全网 IP 集体右移」（实测 `.120 -> .101`）。
        const hint: ?[4]u8 = if (dhcpv4.ipIsZero(want)) null else want;
        const l = self.leases.alloc(pool, self.cfg.statics.items, mac, req.clientId(), hint, now) catch |e| {
            if (self.cfg.log_dhcp) log.info("  REQUEST 无法分配: {s}", .{@errorName(e)});
            self.sendNak(req, pool, sid, ifindex, src);
            return;
        };

        // 要的地址给不了 -> NAK（只有被要求、或 --dhcp-authoritative 时才 NAK）
        if (!dhcpv4.ipIsZero(want) and dhcpv4.ipToU32(l.ip) != dhcpv4.ipToU32(want)) {
            const may_nak = self.cfg.authoritative or
                (!dhcpv4.ipIsZero(req.ciaddr) and pool.contains(req.ciaddr));
            if (may_nak) {
                if (self.cfg.log_dhcp) {
                    var b1: [16]u8 = undefined;
                    var b2: [16]u8 = undefined;
                    log.info("  要 {s} 但只能给 {s} -> NAK", .{ dhcpv4.ipText(want, &b1), dhcpv4.ipText(l.ip, &b2) });
                }
                self.sendNak(req, pool, sid, ifindex, src);
                return;
            }
            if (self.cfg.log_dhcp) log.info("  非权威模式：要的地址给不了，静默不响应", .{});
            return;
        }

        // 确认租约
        l.state = .bound;
        l.static = dhcpv4.LeaseDb.findStatic(self.cfg.statics.items, mac) != null;
        l.expires = now + self.leaseFor(pool, mac);
        if (req.hostname()) |h| self.applyClientHostname(l, mac, h);

        var out: [MAX_PACKET]u8 = undefined;
        const n = self.buildReply(&out, req, l, pool, sid, .ack, want) orelse return;
        const dest = self.remapDest(dhcpv4.replyDest(req, &self.reply_of_finish, src));
        // 单播到刚分配的地址时，先插一条 ARP 条目，否则内核发不出去
        self.ensureArp(req, dest);
        self.sendPacket(dest, ifindex, out[0..n]) catch |e| {
            log.warning("发 ACK 失败: {s}", .{@errorName(e)});
            return;
        };
        var b: [16]u8 = undefined;
        const ipt = dhcpv4.ipText(l.ip, &b);
        // 租约事件降为 debug：续租/重绑定会周期性出现（实测每 12 小时一轮 +
        // 每次地址分配），默认级别（info）下不刷屏。租约状态本身仍以
        // /tmp/dhcp.leases 与 /tmp/hosts/odhcpd 为权威，需要日志时改级别即可。
        if (l.hostname()) |h| {
            log.debug("租约 {s} -> {s} {s}（{d}s）", .{ macText(mac), ipt, h, self.leaseFor(pool, mac) });
        } else {
            log.debug("租约 {s} -> {s}（{d}s）", .{ macText(mac), ipt, self.leaseFor(pool, mac) });
        }
        self.afterLeaseChange(mac, l.ip, l.hostname(), "add");
    }

    fn doRelease(self: *Runtime, req: *const dhcpv4.Message) void {
        const ip = if (!dhcpv4.ipIsZero(req.ciaddr)) req.ciaddr else dhcpv4.IP_ANY;
        if (dhcpv4.ipIsZero(ip)) return;
        if (self.leases.find(ip)) |l| {
            l.state = .released;
            self.afterLeaseChange(req.chaddrSlice(), ip, l.hostname(), "del");
        }
    }

    fn doDecline(self: *Runtime, req: *const dhcpv4.Message) void {
        const ip = req.optionIp(dhcpv4.Opt.requested_ip) orelse req.ciaddr;
        if (dhcpv4.ipIsZero(ip)) return;
        const now = util.dnsmasqTime();
        if (self.leases.find(ip)) |l| {
            l.state = .declined;
            l.expires = now + DECLINE_BACKOFF;
            log.warning("客户端 {s} 声明 {s} 已被占用，退避 {d}s", .{
                macText(req.chaddrSlice()), ipTextTmp(ip), DECLINE_BACKOFF,
            });
        }
    }

    fn doInform(self: *Runtime, req: *const dhcpv4.Message, ifindex: u32, src: dhcpv4.Dest) void {
        // INFORM：客户端已有地址，只要配置参数，不要租约（不回租期相关选项）
        const pool = self.pickPool(req) orelse return;
        const sid = self.serverId(ifindex, pool);
        var l = dhcpv4.Lease{ .ip = req.ciaddr };
        if (!dhcpv4.ipIsZero(req.ciaddr)) {
            if (self.leases.find(req.ciaddr)) |ex| l = ex.*;
        }
        var out: [MAX_PACKET]u8 = undefined;
        const n = self.buildReply(&out, req, &l, pool, sid, .ack, req.ciaddr) orelse return;
        const dest = self.remapDest(dhcpv4.replyDest(req, &self.reply_of_finish, src));
        // 单播到刚分配的地址时，先插一条 ARP 条目，否则内核发不出去
        self.ensureArp(req, dest);
        self.sendPacket(dest, ifindex, out[0..n]) catch {};
    }

    fn sendNak(self: *Runtime, req: *const dhcpv4.Message, pool: *const dhcpv4.Pool, sid: [4]u8, ifindex: u32, src: dhcpv4.Dest) void {
        var l = dhcpv4.Lease{};
        var out: [MAX_PACKET]u8 = undefined;
        const n = self.buildReply(&out, req, &l, pool, sid, .nak, null) orelse return;
        const dest = self.remapDest(dhcpv4.replyDest(req, &self.reply_of_finish, src));
        // 单播到刚分配的地址时，先插一条 ARP 条目，否则内核发不出去
        self.ensureArp(req, dest);
        self.sendPacket(dest, ifindex, out[0..n]) catch {};
    }

    /// 该客户端的租期：静态绑定的 lease_time 优先，否则用池的
    fn leaseFor(self: *Runtime, pool: *const dhcpv4.Pool, mac: []const u8) u32 {
        if (dhcpv4.LeaseDb.findStatic(self.cfg.statics.items, mac)) |s| {
            if (s.lease_time != 0) return s.lease_time;
        }
        return pool.lease_time;
    }

    /// 把客户端上报的主机名（option 12）写进租约 —— **静态绑定的名字优先**。
    ///
    /// 对齐 odhcpd `dhcpv4.c:668` 的条件：
    ///   `req_hostname_len > 0 && (!lease->lease_cfg || !lease->lease_cfg->hostname)`
    /// 也就是 `config host` 的 `name` 一旦写了，客户端自报的名字就不再覆盖它。
    /// 这条不只是观感问题：租约文件里的名字会被 DNS 侧（`--addn-hosts`）
    /// 拿来当主机名，放任客户端改名等于让任何人给静态租约的地址挂个域名。
    fn applyClientHostname(self: *Runtime, l: *dhcpv4.Lease, mac: []const u8, reported: []const u8) void {
        if (dhcpv4.LeaseDb.findStatic(self.cfg.statics.items, mac)) |s| {
            if (s.hostname) |nm| {
                if (nm.len > 0) return; // 静态名字优先，客户端改不了
            }
        }
        l.setHostname(reported);
    }

    /// 构造 OFFER/ACK/NAK。返回写入长度。
    fn buildReply(
        self: *Runtime,
        out: []u8,
        req: *const dhcpv4.Message,
        lease: *const dhcpv4.Lease,
        pool: *const dhcpv4.Pool,
        sid: [4]u8,
        mt: dhcpv4.Msg,
        requested: ?[4]u8,
    ) ?usize {
        _ = requested;
        var rep = dhcpv4.Message{};
        rep.op = @intFromEnum(dhcpv4.Op.bootreply);
        rep.htype = req.htype;
        rep.hlen = req.hlen;
        rep.xid = req.xid;
        rep.flags = req.flags;
        rep.giaddr = req.giaddr;
        rep.ciaddr = req.ciaddr;
        rep.yiaddr = if (mt == .nak) dhcpv4.IP_ANY else lease.ip;
        rep.siaddr = req.siaddr;
        rep.chaddr = req.chaddr;
        rep.sname = req.sname;

        var b = dhcpv4.Builder.init(out);
        b.header(&rep) catch return null;

        b.optionU8v(dhcpv4.Opt.message, @intFromEnum(mt)) catch return null;
        b.optionU32v(dhcpv4.Opt.server_id, dhcpv4.ipToU32(sid)) catch return null;

        if (mt != .nak) {
            const lt = if (lease.static) self.leaseFor(pool, lease.mac[0..lease.mac_len]) else pool.lease_time;
            b.optionU32v(dhcpv4.Opt.lease_time, lt) catch return null;
            // T1 = 0.5 * lease, T2 = 0.875 * lease（RFC2131 §4.4.5）
            if (lt != 0 and lt != 0xFFFFFFFF) {
                b.optionU32v(dhcpv4.Opt.t1, t1Of(lt)) catch return null;
                b.optionU32v(dhcpv4.Opt.t2, t2Of(lt)) catch return null;
            }
            // 用户 --dhcp-option 覆盖优先：先摆内置，再让用户选项覆盖同号
            self.emitStandardOptions(&b, pool, sid) catch {};
            self.emitUserOptions(&b) catch {};
        }

        self.reply_of_finish = rep;
        self.reply_of_finish.opts = out[240..]; // 只用于 msgType()，下同
        return b.finish();
    }

    /// 下发标准选项（掩码/网关/DNS/域名/广播地址）。
    ///
    /// ## DNS 与域名的来源（这次修过的 bug）
    ///
    /// UCI 路径把 `list dns` / `list domain` 存在 **pool.dns / pool.domain**，
    /// CLI 路径存在 cfg.dns / cfg.domain —— 早期版本这里只读 cfg.*，结果
    /// UCI 模式下 **option 6/15 一个都不发**，手机拿不到 DNS 服务器地址，
    /// Wi-Fi 重联后就是感叹号（真机踩过：192.168.0.1，2026-09-20）。
    ///
    /// 缺省规则（用户明确要求）：**没配就通告自身为 DNS** —— `sid` 是
    /// server-identifier，取自收包网卡的地址（或 --zd-server-id），
    /// 这也正是 odhcpd `dns_service` 缺省开时的行为。
    fn emitStandardOptions(self: *Runtime, b: *dhcpv4.Builder, pool: *const dhcpv4.Pool, sid: [4]u8) !void {
        try b.optionIpv(dhcpv4.Opt.netmask, pool.netmask);
        if (!dhcpv4.ipIsZero(pool.router)) try b.optionIpv(dhcpv4.Opt.router, pool.router);

        // DNS：池的 list dns 优先；没有就通告自身
        var data: [255]u8 = undefined;
        var n: usize = 0;
        if (pool.dns.len > 0) {
            for (pool.dns) |ip| {
                if (n + 4 > data.len) break;
                @memcpy(data[n .. n + 4], &ip);
                n += 4;
            }
        } else {
            @memcpy(data[0..4], &sid);
            n = 4;
        }
        try b.option(dhcpv4.Opt.dnsserver, data[0..n]);

        // 域名：pool.domain（UCI）优先，回退 cfg.domain（CLI --domain）
        if (pool.domain orelse self.cfg.domain) |d| try b.option(dhcpv4.Opt.domain, d);
        // option 28：广播地址按池掩码推导（odhcpd 用接口自己的 broadcast）
        try b.optionIpv(dhcpv4.Opt.broadcast, dhcpv4.broadcastOf(pool.start, pool.netmask));
    }

    fn emitUserOptions(self: *Runtime, b: *dhcpv4.Builder) !void {
        for (self.cfg.user_opts.items) |o| {
            try b.option(o.code, o.data[0..o.len]);
        }
    }

    // -----------------------------------------------------------------------
    // 租约文件
    // -----------------------------------------------------------------------

    fn afterLeaseChange(self: *Runtime, mac: []const u8, ip: [4]u8, hostname: ?[]const u8, action: []const u8) void {
        self.writeLeaseFiles() catch |e| log.warning("写租约文件失败: {s}", .{@errorName(e)});
        if (self.cfg.script) |sc| self.runScript(sc, action, mac, ip, hostname);
    }

    /// 启动时把上一次的状态文件读回租约表。
    ///
    /// ## 为什么必须有这一段
    ///
    /// 不读的话，进程重启后客户端发来的续租在所有租约里都找不到，会被当成
    /// **新客户端重新分配**。实测在 .1 上就是「重启一次，全网设备 IP 全换掉」
    /// （`.120 -> .101`、`.238 -> .102`）—— odhcpd 原本发出去的租约我们一条都不知道。
    ///
    /// 回环自检（`--zd-selftest`）永远测不出这个缺陷：自检每次都是全新进程 +
    /// 全新客户端，「没有历史」本来就是自检的前提。
    ///
    /// ## 文件模型：两种都要认
    ///
    ///   * **上游 HEAD**：hosts 走 `<hosts_dir>/odhcpd.hosts.<ifname>`，状态单独一个文件；
    ///   * **.1 上已部署的旧版 odhcpd**：hosts 行与 `#` 状态行**混写在同一个文件**
    ///     （`/tmp/hosts/odhcpd`）。
    ///
    /// 因此解析按「行首是不是 `#`」分派：hosts 行只用来补主机名，不产生租约。
    ///
    /// ## v4 的权威来源已改为 dnsmasq 格式文件
    ///
    /// 2026-09-21 起 `writeStateFile` 不再写 v4 行（原因见那里的说明），
    /// 所以 v4 的恢复改从 `/tmp/dhcp.leases` 读（`parseDnsmasqLeaseLine`）。
    /// 状态文件里的 v4 行仍然会读 —— 老二进制留下的文件、或 .1 上旧版 odhcpd
    /// 的混写文件都还有它们，不能因为升级就丢掉租约。
    /// `LeaseDb.insert` 按 IP 覆盖去重，所以两个来源同时命中不会产生重复条目；
    /// dnsmasq 文件在**后**读，它的主机名因此优先。
    fn loadLeaseFile(self: *Runtime) void {
        const now = util.dnsmasqTime();

        var restored: usize = 0;
        var skipped_expired: usize = 0;
        var skipped_nopool: usize = 0;

        // ---- 1. 状态文件：老式 v4 行 + hosts 行 ----
        // hosts 行必须等两个来源都插完再补名字，所以先缓存内容。
        const S = struct {
            var buf: [64 * 1024]u8 = undefined;
        };
        var state_raw: []const u8 = &[_]u8{};
        var from_dnsmasq: usize = 0;

        if (self.cfg.state_file) |path| {
            if (readWholeFile(path, &S.buf)) |nread| {
                state_raw = S.buf[0..nread];

                var lines = std.mem.splitScalar(u8, state_raw, '\n');
                while (lines.next()) |rawline| {
                    const line = trimEol(rawline);
                    if (line.len == 0 or line[0] != '#') continue;

                    const l = parseStateLine(line, now) orelse continue;

                    // 只恢复「落在我们负责的网段里」的租约。别的文件/别的接口留下的地址
                    // （比如换过 LAN 网段、或别的接口也在写同一个文件）不该被我们认领，
                    // 否则一个陈旧条目就能占住池里的一个地址。
                    if (!self.ipInCharge(l.ip, l.mac[0..l.mac_len])) {
                        skipped_nopool += 1;
                        continue;
                    }
                    if (l.expires <= now) {
                        skipped_expired += 1;
                        continue;
                    }

                    _ = self.leases.insert(l) catch |e| {
                        log.warning("恢复租约失败（表满？）: {s}", .{@errorName(e)});
                        break;
                    };
                    restored += 1;
                }
            } else {
                log.info("状态文件 {s} 不存在或不可读 —— 本次启动没有可从它恢复的租约", .{path});
            }
        }

        // ---- 2. dnsmasq 格式租约文件：v4 的权威来源 ----
        if (self.cfg.dnsmasq_leasefile) |path| {
            const D = struct {
                var buf: [64 * 1024]u8 = undefined;
            };
            if (readWholeFile(path, &D.buf)) |nread| {
                var lines = std.mem.splitScalar(u8, D.buf[0..nread], '\n');
                while (lines.next()) |rawline| {
                    const line = trimEol(rawline);
                    if (line.len == 0) continue;

                    const l = parseDnsmasqLeaseLine(line) orelse continue;
                    if (!self.ipInCharge(l.ip, l.mac[0..l.mac_len])) {
                        skipped_nopool += 1;
                        continue;
                    }
                    if (l.expires <= now) {
                        skipped_expired += 1;
                        continue;
                    }
                    // 已经从这个文件恢复过的地址不再计数（insert 会覆盖，
                    // 但计数翻倍会让人误以为恢复了很多条）
                    const existed = self.leases.find(l.ip) != null;
                    _ = self.leases.insert(l) catch |e| {
                        log.warning("恢复租约失败（表满？）: {s}", .{@errorName(e)});
                        break;
                    };
                    if (!existed) from_dnsmasq += 1;
                }
            } else {
                log.info("dnsmasq 租约文件 {s} 不存在或不可读", .{path});
            }
        }

        // ---- 3. hosts 行：给缺名字的租约补主机名 ----
        // 旧版 odhcpd 的混写文件里，主机名只在 hosts 行上（`#` 行的第 5 字段是 `-`）。
        // 放到最后做，这样不会覆盖 dnsmasq 文件里已经带上的名字。
        if (state_raw.len > 0) {
            var lines2 = std.mem.splitScalar(u8, state_raw, '\n');
            while (lines2.next()) |rawline| {
                const line = trimEol(rawline);
                if (line.len == 0 or line[0] == '#') continue;
                applyHostsLine(self, line);
            }
        }

        log.notice("租约恢复完成：状态文件 {d} 条 + dnsmasq 文件 {d} 条（跳过：已过期 {d} / 不在本网段 {d}）", .{
            restored, from_dnsmasq, skipped_expired, skipped_nopool,
        });
    }

    /// 该地址是否是「我们负责的」：落在任一地址池内，或者是某条静态绑定。
    fn ipInCharge(self: *Runtime, ip: [4]u8, mac: []const u8) bool {
        for (self.cfg.pools.items) |*p| {
            if (p.contains(ip)) return true;
        }
        if (dhcpv4.LeaseDb.findStatic(self.cfg.statics.items, mac)) |s| {
            if (dhcpv4.ipToU32(s.ip) == dhcpv4.ipToU32(ip)) return true;
        }
        return false;
    }

    /// 用一行 hosts 记录（`<ip> <fqdn> [<short>]`）给已恢复的租约补主机名。
    fn applyHostsLine(self: *Runtime, line: []const u8) void {
        var f: [4][]const u8 = undefined;
        var n: usize = 0;
        var it = std.mem.tokenizeAny(u8, line, " \t");
        while (it.next()) |tok| {
            if (n >= f.len) break;
            f[n] = tok;
            n += 1;
        }
        if (n < 2) return;
        const ip = dhcpv4.parseIpv4(f[0]) orelse return;
        const l = self.leases.find(ip) orelse return;
        if (l.hostname() != null) return;

        // 优先用第三个字段（短名），没有就从 FQDN 上截掉域名部分
        var name = if (n >= 3) f[2] else f[1];
        if (n < 3) {
            if (std.mem.indexOfScalar(u8, name, '.')) |d| name = name[0..d];
        }
        if (hostnameValid(name)) l.setHostname(name);
    }

    /// 写 odhcpd 风格的 hosts 文件 + 状态文件。
    ///
    /// hosts 文件：`<dir>/odhcpd.hosts.<ifname>`，内容是标准 hosts 格式
    /// （`ip\thostname.domain\thostname`），dnsmasq 用 `--addn-hosts=<dir>`
    /// 把整个目录读进来 —— 这就是 odhcpd → DNS 的接合点。
    /// **只写 hostname_valid 的租约**（odhcpd 的 statefiles_write_host4 同样如此）。
    fn writeLeaseFiles(self: *Runtime) !void {
        const now = util.dnsmasqTime();
        mkdirIfNeeded(self.cfg.hosts_dir);

        var namebuf: [512]u8 = undefined;
        const ifname = self.cfg.interface orelse "lan";
        const path = std.fmt.bufPrint(&namebuf, "{s}/odhcpd.hosts.{s}", .{ self.cfg.hosts_dir, ifname }) catch return;

        const fd = util.openTruncate(path) orelse {
            log.warning("无法创建 {s}", .{path});
            return;
        };
        var w = FdWriter{ .fd = fd };

        var count: usize = 0;
        var i: usize = 0;
        while (i < self.leases.count) : (i += 1) {
            const l = self.leases.at(i);
            if (l.state != .bound) continue;
            if (l.expires <= now) continue;
            const h = l.hostname() orelse continue;
            if (!hostnameValid(h)) continue;

            var ipb: [16]u8 = undefined;
            const ipt = dhcpv4.ipText(l.ip, &ipb);
            if (self.cfg.domain) |d| {
                w.print("{s}\t{s}.{s}\t{s}\n", .{ ipt, h, d, h });
            } else {
                w.print("{s}\t{s}\n", .{ ipt, h });
            }
            count += 1;
        }
        w.flush();
        _ = system.close(fd);

        if (self.cfg.log_dhcp) log.info("已写出 {d} 条 hosts 记录到 {s}", .{ count, path });

        if (self.cfg.state_file) |sp| {
            try self.writeStateFile(sp, now);
        }
        // LuCI 概览读 dnsmasq 格式的租约文件 —— v4 接管后的补位
        self.writeDnsmasqLeases();
    }

    /// dnsmasq 格式租约文件：`<到期epoch> <mac> <ip> <主机名|*> <clientid|*>`。
    /// LuCI 概览的「DHCP 租约」就是解析这个文件（luci.sys.dhcp_leases）。
    fn writeDnsmasqLeases(self: *Runtime) void {
        const path = self.cfg.dnsmasq_leasefile orelse return;
        const now = util.dnsmasqTime();
        const fd = util.openTruncate(path) orelse {
            log.warning("无法创建 dnsmasq 格式租约文件 {s}（LuCI 概览租约会缺失）", .{path});
            return;
        };
        defer _ = system.close(fd);
        var w = FdWriter{ .fd = fd };
        var count: usize = 0;
        var i: usize = 0;
        while (i < self.leases.count) : (i += 1) {
            const l = self.leases.at(i);
            if (l.state != .bound) continue;
            if (l.expires <= now) continue;
            var ipb: [16]u8 = undefined;
            const mac = macText(l.mac[0..@intCast(l.mac_len)]);
            const h = l.hostname();
            // 主机名必须是无空白的安全文本，否则用 * 占位（dnsmasq 语义）
            const name = if (h != null and h.?.len > 0 and hostnameValid(h.?)) h.? else "*";
            w.print("{d} {s} {s} {s} *\n", .{ l.expires, mac, dhcpv4.ipText(l.ip, &ipb), name });
            count += 1;
        }
        w.flush();
        if (self.cfg.log_dhcp) log.info("已写出 {d} 条 dnsmasq 格式租约到 {s}", .{ count, path });
    }

    /// odhcpd 状态文件 —— **只写 v6 行**。
    ///
    /// ## 为什么不再写 v4 行（2026-09-21 用户报告后定）
    ///
    /// LuCI 的 `luci-rpc getDHCPLeases` 会读**两个**文件并 append 进**同一个**
    /// `dhcp_leases` 数组：
    ///   * `dhcp.@dnsmasq[0].leasefile`（`/tmp/dhcp.leases`）→ 解析出 `macaddr`
    ///   * **硬编码**的 `/tmp/hosts/odhcpd` → 解析出 `duid`
    /// 于是同一条 v4 租约被读两遍：「已分配的 DHCP 租约」表里每台设备出现
    /// 两次，一次带 MAC（来自 dnsmasq 文件）、一次不带（来自本文件的 v4 行
    /// —— 那一行没有 macaddr 字段，MAC 列渲染成空）。实测 .1：6 台设备 →
    /// 该表 12 行。
    ///
    /// 原版 OpenWrt 不暴露这个问题，是因为分工本来就不重叠：系统 dnsmasq 做
    /// v4（只写 `/tmp/dhcp.leases`）、odhcpd 只做 v6（只写本文件的 v6 行）。
    /// 我们让 odhcpd applet 兼做 v4，两个来源就都满了，重复才显形。
    ///
    /// 所以按 OpenWrt 原版分工对齐：**v4 的权威来源是 `/tmp/dhcp.leases`**
    /// （`writeDnsmasqLeases`），v6 才是本文件。回读侧同步调整见 `loadLeaseFile`。
    /// 实测对齐后：`dhcp_leases` 6 条全带 macaddr、零重复；
    /// `dhcp6_leases` 正常显示带 duid 的 v6 行。
    ///
    /// 注意 hosts 文件（`odhcpd.hosts.<ifname>`）不经过本函数，它直接由租约表
    /// 生成，所以不受这个改动影响。
    ///
    /// v6 行格式（odhcpd statefiles.c:539）：
    /// `# <iface> <hexduid> <hexiaid> <hostname> <valid_until> <hex_hostid> 128 <addr>/128`
    ///
    /// v4 行格式（仅供回读兼容，我们不再写）：
    /// `# <iface> <hexhwaddr> ipv4 <hostname> <valid_until> <hexaddr> 32 <addr>/32`
    fn writeStateFile(self: *Runtime, path: []const u8, now: i64) !void {
        const fd = util.openTruncate(path) orelse {
            log.warning("无法创建 {s}", .{path});
            return;
        };
        var w = FdWriter{ .fd = fd };
        const ifname = self.cfg.interface orelse "lan";

        // DHCPv6 分配记录（odhcpd statefiles.c:539 格式）—— LuCI「已分配的
        // DHCPv6 租约」页解析的就是这个文件里的 v6 行
        if (self.v6) |v| {
            var v6buf: std.ArrayListUnmanaged(u8) = .empty;
            defer v6buf.deinit(self.allocator);
            v.appendStateLines(&v6buf, self.allocator, ifname, now);
            if (v6buf.items.len > 0) {
                const iov = [1]posix.iovec_const{.{ .base = v6buf.items.ptr, .len = v6buf.items.len }};
                _ = system.writev(fd, &iov, 1);
            }
        }
        w.flush();
        _ = system.close(fd);
    }

    fn runScript(_: *Runtime, script: []const u8, action: []const u8, mac: []const u8, ip: [4]u8, hostname: ?[]const u8) void {
        var ipb: [16]u8 = undefined;
        const ipt = dhcpv4.ipText(ip, &ipb);
        const macs = macText(mac);
        var macz: [32]u8 = undefined;
        @memcpy(macz[0..macs.len], macs);
        macz[macs.len] = 0;
        var ipz: [24]u8 = undefined;
        @memcpy(ipz[0..ipt.len], ipt);
        ipz[ipt.len] = 0;
        var actz: [8]u8 = undefined;
        @memcpy(actz[0..action.len], action);
        actz[action.len] = 0;
        var hostz: [256]u8 = undefined;
        const h = hostname orelse "";
        const hn = @min(h.len, hostz.len - 1);
        @memcpy(hostz[0..hn], h[0..hn]);
        hostz[hn] = 0;

        var scriptz: [512]u8 = undefined;
        if (script.len + 1 > scriptz.len) return;
        @memcpy(scriptz[0..script.len], script);
        scriptz[script.len] = 0;

        const pid = system.fork();
        if (net.errno(pid) != .SUCCESS) return;
        if (pid != 0) return; // 父进程继续跑事件循环

        // ---- 以下只在子进程里执行 ----
        // fork 与 execve 之间不能有任何分配或加锁，这里的缓冲都在栈上。
        // 监听 socket 建的时候就带了 SOCK_CLOEXEC，execve 会替我关掉，
        // 所以脚本不会替我们占着 67 端口。
        var argv = [_:null]?[*:0]const u8{
            @ptrCast(&scriptz),
            @ptrCast(&actz),
            @ptrCast(&macz),
            @ptrCast(&ipz),
            @ptrCast(&hostz),
        };
        // 空环境：脚本钩子只用来通知 DNS 侧重载，约定用绝对路径。
        // （已知差异：dnsmasq 会把自身环境原样传给脚本。）
        const empty_env = [_:null]?[*:0]const u8{};
        _ = system.execve(@ptrCast(&scriptz), &argv, &empty_env);
        system.exit(127);
    }

    // -----------------------------------------------------------------------
    // 杂项
    // -----------------------------------------------------------------------

    fn installSignals(self: *Runtime) !void {
        _ = self;
        var act = posix.Sigaction{
            .handler = .{ .handler = onSignal },
            .mask = posix.sigemptyset(),
            .flags = 0,
        };
        posix.sigaction(posix.SIG.TERM, &act, null);
        posix.sigaction(posix.SIG.INT, &act, null);
        // HUP 走「重载」而不是退出（对齐上游 signal_reload）
        var hup = posix.Sigaction{
            .handler = .{ .handler = onSignalHup },
            .mask = posix.sigemptyset(),
            .flags = 0,
        };
        posix.sigaction(posix.SIG.HUP, &hup, null);

        // leasetrigger（--dhcp-script / UCI leasetrigger）是 fork+exec 的火后不管：
        // 脚本退出后没人 wait，每条租约变化都会留一个僵尸
        // （真机上表现为 ps 里 `[odhcpd-update] <defunct>` 越积越多）。
        // SIG_IGN 让内核自动回收子进程 —— 对守护进程这是标准做法。
        var ign = posix.Sigaction{
            .handler = .{ .handler = posix.SIG.IGN },
            .mask = posix.sigemptyset(),
            .flags = 0,
        };
        posix.sigaction(posix.SIG.CHLD, &ign, null);
    }

    fn writePidFile(self: *Runtime) void {
        const path = self.cfg.pid_file orelse return;
        const fd = util.openTruncate(path) orelse {
            log.warning("无法写入 PID 文件 {s}", .{path});
            return;
        };
        defer _ = system.close(fd);
        var buf: [32]u8 = undefined;
        const text = std.fmt.bufPrint(&buf, "{d}\n", .{std.os.linux.getpid()}) catch return;
        _ = system.write(fd, text.ptr, text.len);
    }

    fn removePidFile(self: *Runtime) void {
        const path = self.cfg.pid_file orelse return;
        util.removeFile(path);
    }

    /// 启动状态落盘到 `/tmp/odhcpd-boot.txt`（每次 recheck 覆盖重写）。
    ///
    /// ## 为什么必须用文件而不是日志
    /// 开机时 WiFi 驱动会刷**几百行 kern.debug**，把 logd 的环形缓冲塞满，
    /// 我们启动初期的日志被整段丢弃 —— 实测 21:35:51 那次冷启动，从 UCI 解析
    /// 到 logPools 的日志一条都不剩，只有 startV6 之后的还在。文件不受轮转
    /// 影响，冷启动排障只能靠它。
    fn dumpBootState(self: *Runtime) void {
        var buf: [1024]u8 = undefined;
        var len: usize = 0;

        const hdr = "odhcpd 启动/重查状态\n";
        @memcpy(buf[0..hdr.len], hdr);
        len = hdr.len;

        {
            const piece = std.fmt.bufPrint(buf[len..], "单实例锁={s} nl_fd={d} bound_to_device={} 脏标记={}\n", .{
                if (self.instance_lock_fd >= 0) "已持" else "未持",
                self.nl_fd,
                self.bound_to_device,
                self.iface_dirty,
            }) catch "";
            len += piece.len;
        }
        if (self.cfg.interface) |ifname| {
            const piece = std.fmt.bufPrint(buf[len..], "interface={s} ifindex={?d}\n", .{
                ifname, net.ifaceIndex(ifname),
            }) catch "";
            len += piece.len;
        }
        if (self.ifaceIp4ByName(self.cfg.interface orelse "")) |ip| {
            var b: [16]u8 = undefined;
            const piece = std.fmt.bufPrint(buf[len..], "接口当前 IPv4 = {s}\n", .{dhcpv4.ipText(ip, &b)}) catch "";
            len += piece.len;
        } else {
            const piece = "接口当前 IPv4 = （无）\n";
            @memcpy(buf[len..][0..piece.len], piece);
            len += piece.len;
        }
        for (self.cfg.pools.items, 0..) |p, i| {
            var b1: [16]u8 = undefined;
            var b2: [16]u8 = undefined;
            var b3: [16]u8 = undefined;
            const piece = std.fmt.bufPrint(buf[len..], "  池#{d} {s}-{s} 网关={s} (来自配置={}) 接口={s}\n", .{
                i,
                dhcpv4.ipText(p.start, &b1),
                dhcpv4.ipText(p.end, &b2),
                dhcpv4.ipText(p.router, &b3),
                p.router_from_config,
                p.interface orelse "-",
            }) catch "";
            len += piece.len;
        }

        const fd = util.openTruncate("/tmp/odhcpd-boot.txt") orelse return;
        defer _ = system.close(fd);
        _ = system.write(fd, buf[0..len].ptr, len);
    }
};

fn msgName(mt: u8) []const u8 {
    return switch (mt) {
        1 => "DISCOVER",
        2 => "OFFER",
        3 => "REQUEST",
        4 => "DECLINE",
        5 => "ACK",
        6 => "NAK",
        7 => "RELEASE",
        8 => "INFORM",
        else => "?",
    };
}

fn macText(mac: []const u8) []const u8 {
    const S = struct {
        var buf: [64]u8 = undefined;
    };
    var n: usize = 0;
    for (mac, 0..) |b, i| {
        if (i > 0 and n < S.buf.len) {
            S.buf[n] = ':';
            n += 1;
        }
        const hex = "0123456789abcdef";
        if (n + 2 > S.buf.len) break;
        S.buf[n] = hex[b >> 4];
        S.buf[n + 1] = hex[b & 0xf];
        n += 2;
    }
    return S.buf[0..n];
}

fn ipTextTmp(ip: [4]u8) []const u8 {
    const S = struct {
        var buf: [16]u8 = undefined;
    };
    return dhcpv4.ipText(ip, &S.buf);
}

/// RFC1035 §2.3.1 的「preferred name syntax」：字母数字与 `-`，加点分段。
/// 与 odhcpd 的 `odhcpd_hostname_valid()` 同义。
pub fn hostnameValid(h: []const u8) bool {
    if (h.len == 0 or h.len > 253) return false;
    var label_len: usize = 0;
    for (h) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'z') or
            (c >= 'A' and c <= 'Z') or c == '-';
        if (c == '.') {
            if (label_len == 0) return false;
            label_len = 0;
            continue;
        }
        if (!ok) return false;
        label_len += 1;
        if (label_len > 63) return false;
    }
    return label_len > 0;
}

/// 复刻 odhcpd `statefiles_escape_hostname()`（statefiles.c:503-524）。
///
/// 客户端完全控制它上报的主机名（DHCPv4 option 12），而 DNS 标签按 RFC2181 §11
/// 可以携带任意字节 —— 因此未转义地写进「空格分隔、按行解析」的状态文件时，
/// 一个换行就能伪造出一条额外的 `#` 租约记录（GHSA-hhmc-92hw-535f，配合
/// LuCI 未做 HTML 转义构成存储型 XSS）。非 LDH 字节一律写成 `\xNN`。
pub fn escapeHostname(dst: []u8, src: []const u8) []const u8 {
    const hex = "0123456789abcdef";
    var pos: usize = 0;
    for (src) |c| {
        const ldh = (c >= '0' and c <= '9') or (c >= 'A' and c <= 'Z') or
            (c >= 'a' and c <= 'z') or c == '-' or c == '_' or c == '.';
        if (ldh) {
            if (pos + 1 >= dst.len) break;
            dst[pos] = c;
            pos += 1;
        } else {
            if (pos + 4 >= dst.len) break;
            dst[pos] = '\\';
            dst[pos + 1] = 'x';
            dst[pos + 2] = hex[c >> 4];
            dst[pos + 3] = hex[c & 0xf];
            pos += 4;
        }
    }
    dst[pos] = 0;
    return dst[0..pos];
}

/// `escapeHostname()` 的逆运算：`\xNN` -> 原字节，其余原样。
///
/// 读到非法转义序列（`\` 后不是 `x` 或不是两位十六进制）就**停在那里**，
/// 而不是继续往后拼 —— 与其还原出一个半截名字，不如让上层按「无主机名」处理。
pub fn unescapeHostname(dst: []u8, src: []const u8) []const u8 {
    var pos: usize = 0;
    var i: usize = 0;
    while (i < src.len) {
        if (src[i] == '\\' and i + 1 < src.len and src[i + 1] == 'x') {
            if (i + 3 >= src.len) break;
            const hi = hexVal(src[i + 2]) orelse break;
            const lo = hexVal(src[i + 3]) orelse break;
            if (pos >= dst.len) break;
            dst[pos] = @as(u8, hi) << 4 | @as(u8, lo);
            pos += 1;
            i += 4;
            continue;
        }
        if (pos >= dst.len) break;
        dst[pos] = src[i];
        pos += 1;
        i += 1;
    }
    return dst[0..pos];
}

fn hexVal(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => null,
    };
}

/// 解析 MAC 文本。`ether_ntoa()` 的 `aa:bb:cc:dd:ee:ff` 与紧凑的 `aabbccddeeff`
/// 都要认 —— 前者是 odhcpd 的写法，后者常见于自己生成的记录。
fn parseMacText(s: []const u8) ?[6]u8 {
    var out: [6]u8 = [_]u8{0} ** 6;
    var pos: usize = 0;
    var i: usize = 0;
    while (i < s.len and pos < 6) {
        if (s[i] == ':') {
            i += 1;
            continue;
        }
        if (i + 2 > s.len) return null;
        const hi = hexVal(s[i]) orelse return null;
        const lo = hexVal(s[i + 1]) orelse return null;
        out[pos] = @as(u8, hi) << 4 | @as(u8, lo);
        pos += 1;
        i += 2;
    }
    if (pos != 6) return null;
    return out;
}

/// `192.168.0.120/32` -> `192.168.0.120`
fn beforeSlash(s: []const u8) []const u8 {
    return if (std.mem.indexOfScalar(u8, s, '/')) |i| s[0..i] else s;
}

fn trimEol(s: []const u8) []const u8 {
    var e = s;
    while (e.len > 0 and (e[e.len - 1] == '\r' or e[e.len - 1] == ' ' or e[e.len - 1] == '\t')) {
        e = e[0 .. e.len - 1];
    }
    return e;
}

/// applet 入口。返回进程退出码。
pub fn main(allocator: Allocator, args: []const []const u8) u8 {
    var cfg = Config{ .allocator = allocator };
    defer cfg.deinit();

    // 日志先接到 syslog —— 必须早于任何配置解析，否则解析期的告警会被
    // procd 以 daemon.err 的名义上报（假的错误级别）。
    //
    // 逐字对照上游 `ref/odhcpd/src/odhcpd.c:160`：
    //     openlog("odhcpd", LOG_PERROR | LOG_PID, LOG_DAEMON);
    // 即 tag=odhcpd、facility=DAEMON(3)、**并且**镜像一份到 stderr
    // （LOG_PERROR —— 前台手跑时还能在终端上看到）。上游默认
    // `config.log_syslog = true`（config.c:54），所以这里也是默认开。
    //
    // 顺带修掉一个缺口：`/etc/init.d/odhcpd` 没有 `procd_set_param stderr`，
    // 所以在此之前 odhcpd applet 的日志**根本进不了 syslog**（logread 里
    // 一条都搜不到），排查只能靠前台手跑。
    log.enableSyslog("odhcpd", 3, true);

    const ok = parseArgs(&cfg, args) catch true;
    if (!ok) return 0;

    // -----------------------------------------------------------------
    // 配置来源：有配置类参数 -> dnsmasq 风格；没有 -> 读 UCI（odhcpd 风格）
    //
    // 这条分工的依据是 procd 的启动方式：`procd_set_param command
    // /usr/sbin/odhcpd`（ref/openwrt-pkg-odhcpd/files/odhcpd.init），
    // **不带任何参数**，真实 odhcpd 因此只能从 UCI 取配置；而人在命令行
    // 上测试时习惯写 `--dhcp-range=…`。两种场景各走各的，互不干扰。
    //
    // 顺序上必须放在自检**之前** —— 自检会用配置里已有的池（只要它落在
    // 127.0.0.0/8 内），这样 UCI 模式也能端到端验一遍，而不只是验解析。
    // -----------------------------------------------------------------
    if (!cfg.cli_conf_seen and !cfg.no_uci) {
        const st = uci_dhcp.loadFromFiles(&cfg, .{
            .dhcp_path = cfg.uci_path,
            .network_path = cfg.uci_network_path,
            .state_path = cfg.uci_state_path,
        }) catch |e| blk: {
            log.err("读 UCI 配置 {s} 失败：{s}", .{ cfg.uci_path, @errorName(e) });
            break :blk uci_dhcp.Stats{};
        };
        log.notice("配置来源：UCI（{s}）—— 段 {d}，池 {d}，静态 {d}，跳过 {d}，maindhcp={s}", .{
            cfg.uci_path,
            st.sections,
            st.pools,
            st.statics,
            st.skipped,
            if (st.maindhcp) "1" else "0",
        });
    } else if (cfg.cli_conf_seen) {
        log.notice("配置来源：命令行（dnsmasq 风格参数），按要求不读 UCI", .{});
    }

    if (cfg.selftest) {
        return runSelfTest(&cfg);
    }

    // v6-only 模式：maindhcp=0 时池可能是空的，只要还有启用的 v6 接口就能跑
    const v6_any = blk: {
        for (cfg.v6.items) |i| if (i.anyEnabled()) break :blk true;
        break :blk false;
    };
    if (cfg.pools.items.len == 0 and cfg.statics.items.len == 0 and !v6_any) {
        log.err("既没有可用的地址池也没有静态绑定。命令行风格请给 --dhcp-range/--dhcp-host；" ++
            "UCI 风格请检查 {s} 里的 maindhcp 与 dhcpv4 选项", .{cfg.uci_path});
        return 1;
    }
    if (cfg.test_only) {
        log.notice("配置检查通过：{d} 个池，{d} 条静态绑定，{d} 个 v6 接口", .{
            cfg.pools.items.len, cfg.statics.items.len, cfg.v6.items.len,
        });
        return 0;
    }

    var rt = Runtime.init(&cfg);
    log.notice("以 odhcpd applet 身份运行（argv[0] 分派）", .{});

    // ---- 单实例闸门 ----
    // 自检（`--zd-selftest`）与配置检查（`--test-only`）都不长期占用 :67，
    // 而且本地 e2e 会反复起停它们，所以不参与排他。
    if (!cfg.selftest and !cfg.test_only) {
        // v4 租约文件的缺失是「静默丢租约」的高危项，必须在启动时就说清楚。
        if (cfg.dnsmasq_leasefile == null) {
            log.warning("未指定 v4 租约文件（--zd-dnsmasq-leasefile=…，UCI 模式则由 " ++
                "dhcp.@dnsmasq[0].leasefile 提供）：v4 租约会**只存在于内存**，" ++
                "进程重启后无法恢复 —— 客户端续租会被当成新分配，表现为全网换地址。", .{});
        }

        switch (acquireInstanceLockAt(cfg.lock_file orelse INSTANCE_LOCK_PATH)) {
            .acquired => |fd| {
                rt.instance_lock_fd = fd;

                // 第二道闸：锁是空的，但 /proc 里还有别的 odhcpd 在跑。
                // 这种多半是**旧版本二进制**（还没有闸门）或人为手工起的实例 ——
                // 它们不持有 flock，光靠锁挡不住，必须显式拒绝，否则就是
                // 「两个实例各分各的地址」→ 重复 IP。
                var peers: usize = 0;
                const desc = describeOdhcpdPeers(&peers);
                if (peers > 0) {
                    log.err("检测到另有 {d} 个 odhcpd 进程在运行：{s}", .{ peers, desc });
                    log.err("它们未持有单实例锁（多半是旧版本二进制或手工启动的），" ++
                        "光靠 flock 挡不住。为避免两个实例各分各的地址造成重复 IP，" ++
                        "本次拒绝启动 —— 请先停掉它们（如 `kill <pid>` 或 `service odhcpd restart`）。", .{});
                    return 1;
                }
            },
            .already_running => |peer| {
                if (peer) |p| {
                    log.err("已有另一个 odhcpd 实例在运行（pid {d}），本次拒绝启动。", .{p});
                } else {
                    log.err("已有另一个 odhcpd 实例在运行，本次拒绝启动。", .{});
                }
                log.err("多实例会各自维护一份租约表，把同一个地址 ACK 给不同客户端，" ++
                    "表现为「两台设备抢同一个 IP」→ 局域网大面积不通。", .{});
                var peers: usize = 0;
                log.err("现场进程：{s}", .{describeOdhcpdPeers(&peers)});
                return 1;
            },
            .unavailable => {},
        }
    }

    rt.run() catch |e| {
        log.err("odhcpd applet 退出: {s}", .{@errorName(e)});
        return 1;
    };
    return 0;
}

// ---------------------------------------------------------------------------
// 单实例闸门（flock）
// ---------------------------------------------------------------------------
/// 单实例锁的路径。**故意不与 --pid-file 共用**：pid 文件用 open+truncate+close
/// 写，拿它做锁要么改掉 pid 文件的生命周期、要么持有一个随时会被别人截断的文件，
/// 两者都会牵动既有语义。独立一个文件最省心。
const INSTANCE_LOCK_PATH = "/var/run/odhcpd.lock";

const LockOutcome = union(enum) {
    /// 拿到锁。fd 必须**保持打开到进程退出** —— 关闭即释放锁。
    acquired: posix.fd_t,
    /// 已有实例持锁。附带从锁文件里读到的持有者 pid（读不到就是 null）。
    already_running: ?i32,
    /// 锁文件都建不出来（例如 /var/run 只读、或跑在没挂它的沙箱里）。
    /// 这种情况**不阻断启动**，只告警 —— 宁可少一层保护，也不要起不来。
    unavailable,
};

/// 抢单实例锁。对应「odhcpd 全机只能有一个」这条硬约束。
///
/// ## 为什么必须有
/// 2026-09-21 实测（.1）：一次开机后同时存在**两个** odhcpd 实例
/// （PID 2073 与 7206/7935 重叠，前者的启动日志缺失、只在退出时留下一行
/// `收到停止信号，正在退出（收 163 / 发 0）`）。两个实例各有一份独立的租约表，
/// 于是各自把 `192.168.0.102` ACK 给了不同客户端：
///   * `/tmp/dhcp.leases` 说 .102 归 `c4:57:81:42:45:39`（debian）
///   * `ip neigh` 说 .102 实际由 `22:c8:b5:1a:0d:60`（Redmi-Note-11-5G）持有
/// 即**重复 IP** —— 正是用户早先报的「手机 .101 被 PC 抢 → 局域网卡死」同类故障。
///
/// ## 为什么不用「靠 bind :67 失败来排他」
/// 上游 odhcpd **自己就设了 `SO_REUSEADDR`**（`dhcpv4.c:1518`、`dhcpv6.c:88`），
/// 本移植逐条照抄。而 Linux 对 UDP 的规则是「新旧两个 socket 都设了
/// REUSEADDR 就允许重复 bind」—— 所以 bind 根本不会失败，这条路走不通。
/// 去掉 REUSEADDR 虽然能得到内核级排他，但会偏离上游行为、影响逐字节 A/B，
/// 得不偿失。flock 是**纯增量**机制，不触碰任何网络语义。
///
/// ## 语义
/// * `LOCK_EX | LOCK_NB` 拿不到 → 说明已有实例在跑；
/// * 锁随进程消亡（fd 关闭）**自动释放**，不存在陈旧锁文件问题；
/// * 拿到锁后把自己的 pid 写进文件，好让后来者在日志里报出「是谁占着」——
///   这次排查就是因为只有一句模糊的退出码而绕了很久。
///
/// 锁文件路径可注入：生产用 INSTANCE_LOCK_PATH，单测/本地 e2e 用临时路径，
/// 免得几份测试抢同一把全局锁。
fn acquireInstanceLockAt(lock_path: []const u8) LockOutcome {
    var pathz: [128]u8 = undefined;
    if (lock_path.len >= pathz.len) return .unavailable;
    @memcpy(pathz[0..lock_path.len], lock_path);
    pathz[lock_path.len] = 0;
    const path = pathz[0..lock_path.len :0];

    const fd = posix.openat(
        posix.AT.FDCWD,
        path,
        posix.O{ .ACCMODE = .RDWR, .CREAT = true, .CLOEXEC = true },
        0o644,
    ) catch {
        log.warning("无法创建单实例锁 {s}，本次跳过排他检查" ++
            "（若同时跑起两个实例，会出现重复 IP）", .{lock_path});
        return .unavailable;
    };

    const rc = std.os.linux.flock(fd, std.posix.LOCK.EX | std.posix.LOCK.NB);
    if (net.errno(rc) != .SUCCESS) {
        const peer = readPidFromFd(fd);
        _ = system.close(fd);
        return .{ .already_running = peer };
    }

    // 拿到锁：写入自己的 pid（供后来者诊断）。写完 seek 回开头，不留垃圾。
    var buf: [32]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, "{d}\n", .{std.os.linux.getpid()}) catch "";
    if (text.len > 0) {
        _ = system.lseek(fd, 0, 0); // SEEK_SET
        _ = system.ftruncate(fd, 0);
        _ = system.write(fd, text.ptr, text.len);
    }
    return .{ .acquired = fd };
}

/// 从锁文件里读出持有者 pid（内容就是 "<pid>\n"）。
fn readPidFromFd(fd: posix.fd_t) ?i32 {
    _ = system.lseek(fd, 0, 0);
    var buf: [32]u8 = undefined;
    const n = system.read(fd, &buf, buf.len);
    if (net.errno(n) != .SUCCESS or n == 0) return null;
    const text = std.mem.trim(u8, buf[0..@intCast(n)], " \t\r\n");
    return std.fmt.parseInt(i32, text, 10) catch null;
}

/// 扫 /proc 列出所有 odhcpd applet 进程，拼成一行给日志用。
/// `peer_count` 回填**除自己以外**的 odhcpd 进程数（僵尸不算）。
///
/// 之所以不只看锁文件里的 pid：**老版本二进制没有闸门**，也可能有人用
/// `/usr/bin/zig-dnsmasq --applet=odhcpd` 或直接 `/usr/sbin/odhcpd` 起了一个，
/// 这些都不持有我们的锁。列出来才能一眼看清到底有几个、分别是谁。
fn describeOdhcpdPeers(peer_count: *usize) []const u8 {
    peer_count.* = 0;
    const S = struct {
        var buf: [512]u8 = undefined;
    };
    var len: usize = 0;
    const self_pid = std.os.linux.getpid();

    // 用 getdents64 手工扫 /proc，而不是 std.fs —— 与仓库其它地方保持一致
    // （Zig 0.16 移除了 std.fs.cwd()/openDirAbsolute，且本移植坚持不链接 libc）。
    const dfd: posix.fd_t = posix.openat(
        posix.AT.FDCWD,
        "/proc",
        posix.O{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        0,
    ) catch return "（无法打开 /proc）";
    defer _ = system.close(dfd);

    var dent: [16384]u8 = undefined;
    var namebuf: [64]u8 = undefined;
    while (true) {
        const n = std.os.linux.getdents64(@intCast(dfd), &dent, dent.len);
        if (n <= 0) break;
        const total: usize = @intCast(n);

        var off: usize = 0;
        while (off + 19 <= total) {
            const reclen = std.mem.readInt(u16, dent[off + 16 ..][0..2], .little);
            if (reclen == 0 or off + reclen > total) break;
            const nstart = off + 19;
            var nend = nstart;
            while (nend < off + reclen and dent[nend] != 0) nend += 1;
            const entry = dent[nstart..nend];
            off += reclen;

            if (entry.len == 0 or entry[0] == '.') continue;
            const pid = std.fmt.parseInt(i32, entry, 10) catch continue;

            const cpath = std.fmt.bufPrint(&namebuf, "/proc/{s}/cmdline", .{entry}) catch continue;
            const cmd = readWholeFileSmall(cpath) orelse continue;
            if (!isOdhcpdDaemonCmdline(cmd)) continue;

            // 僵尸进程必须排除：它只是等着被回收的空壳，不再持有任何 socket。
            // 不排除的话，一个没被及时 reaped 的 defunct odhcpd 会让我们**永久**
            // 拒绝启动（把「防重复」变成「起不来」，那更糟）。
            if (pidIsZombie(entry)) continue;

            if (pid != self_pid) peer_count.* += 1;

            const piece = std.fmt.bufPrint(S.buf[len..], "{s}{d}{s}", .{
                if (len == 0) "" else ", ",
                pid,
                if (pid == self_pid) "(自己)" else "",
            }) catch break;
            len += piece.len;
        }
    }
    if (len == 0) return "（未在 /proc 里找到 odhcpd 进程）";
    return S.buf[0..len];
}

/// 一条 `/proc/<pid>/cmdline` 是否属于「odhcpd 守护进程本体」。
///
/// ## ★ 为什么不能用 comm
/// `/etc/init.d/odhcpd` 是 `#!` 脚本。内核执行它时会把 `/bin/sh` 的 **comm
/// 设成脚本名 "odhcpd"**（实测：`/bin/sh /etc/rc.common /etc/init.d/odhcpd start`
/// 的 comm 就是 `odhcpd`）。于是**每次 `service odhcpd restart` 都会凭空多出
/// 一个「同名进程」**，闸门误判成「已有实例在跑」→ 拒绝启动 → procd 等 5 秒
/// 重试才起来。本移植第一版就是这么翻的（日志里出现
/// `检测到另有 1 个 odhcpd 进程在运行：…(自己), <init脚本的pid>`）。
///
/// 所以判定必须看 **argv[0] 的 basename**：
///   * `/usr/sbin/odhcpd`                  → "odhcpd" ✓ 是本体
///   * `/bin/sh /etc/rc.common /etc/init.d/odhcpd start` → argv[0] 是 "/bin/sh" ✗
///   * `/usr/bin/zig-dnsmasq -C …`（DNS 实例）→ "zig-dnsmasq" ✗
/// 另外保留显式 `--applet=odhcpd` 的识别（`zig-dnsmasq --applet=odhcpd` 形态）。
fn isOdhcpdDaemonCmdline(cmdline: []const u8) bool {
    if (std.mem.indexOf(u8, cmdline, "--applet=odhcpd") != null) return true;
    const argv0 = std.mem.sliceTo(cmdline, 0);
    if (argv0.len == 0) return false;
    return std.mem.eql(u8, baseNameOf(argv0), "odhcpd");
}

/// 取路径的最后一段。自己写而不用 std.fs.path —— 本移植坚持不依赖 libc，
/// 且这里只需要一个极简实现。
fn baseNameOf(p: []const u8) []const u8 {
    if (std.mem.lastIndexOfScalar(u8, p, '/')) |i| return p[i + 1 ..];
    return p;
}

/// 该 pid 是否处于僵尸态。
fn pidIsZombie(pid_name: []const u8) bool {
    var pbuf: [64]u8 = undefined;
    const spath = std.fmt.bufPrint(&pbuf, "/proc/{s}/stat", .{pid_name}) catch return false;
    const stat = readWholeFileSmall(spath) orelse return false;
    return statStateChar(stat) == 'Z';
}

/// 从 `/proc/<pid>/stat` 的内容里取出状态字符。
///
/// 格式是 `pid (comm) state ...`，而 **comm 里可以含空格甚至右括号**
/// （进程名可被 prctl 改成任意字符串）。所以必须从**最后一个 `)`** 之后取，
/// 用「按空格 split」或「找第一个 `)`」都会在畸形 comm 上取错。
/// 取错方向很危险：把僵尸当成活的 → 我们永久拒绝启动。
fn statStateChar(stat: []const u8) ?u8 {
    const close = std.mem.lastIndexOfScalar(u8, stat, ')') orelse return null;
    const rest = std.mem.trimStart(u8, stat[close + 1 ..], " ");
    return if (rest.len > 0) rest[0] else null;
}

/// 读一个小文件到固定缓冲（/proc 里的 comm/cmdline 都很小）。
fn readWholeFileSmall(path: []const u8) ?[]const u8 {
    const S = struct {
        var buf: [1024]u8 = undefined;
    };
    var pz: [256]u8 = undefined;
    if (path.len >= pz.len) return null;
    @memcpy(pz[0..path.len], path);
    pz[path.len] = 0;

    const fd = posix.openat(posix.AT.FDCWD, pz[0..path.len :0], posix.O{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0) catch return null;
    defer _ = system.close(fd);
    const n = system.read(fd, &S.buf, S.buf.len);
    if (net.errno(n) != .SUCCESS or n == 0) return null;
    return S.buf[0..@intCast(n)];
}

// ---------------------------------------------------------------------------
// 回环自检
// ---------------------------------------------------------------------------

/// 自检用的客户端地址。刻意用 127.0.0.0/8 —— 整段都是本机地址，
/// 内核会把发往它的报文直接交付到回环，不会出现在任何物理网卡上。
const SELF_CLIENT_IP: [4]u8 = .{ 127, 0, 0, 2 };
const SELF_SERVER_IP: [4]u8 = .{ 127, 0, 0, 1 };

/// 是否落在 127.0.0.0/8。自检只在回环段里做，这是安全边界。
fn isLoopback(ip: [4]u8) bool {
    return ip[0] == 127;
}

/// 选项 58 续租时刻 T1 = 0.5 * 租期（RFC2131 §4.4.5）
pub fn t1Of(lease: u32) u32 {
    return lease / 2;
}

/// 选项 59 重绑定时刻 T2 = 0.875 * 租期。写成 `lt - lt/8` 而不是
/// `lt*7/8`，是为了避免 `lt*7` 在大租期上回绕（infinite 那档已经在调用处跳过）。
pub fn t2Of(lease: u32) u32 {
    return lease - (lease / 8);
}

fn outPrint(comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
    writeStdout(s) catch {};
}

/// 跑一次「真实但本机」的 DHCP 握手：
///
///   客户端 socket(0.0.0.0:client_port)   --DISCOVER-->  服务端 socket(:port)
///   客户端 socket  <--OFFER(yiaddr=池内地址)--            服务端 socket
///   客户端 socket  --REQUEST(opt50/opt54)-->              服务端 socket
///   客户端 socket  <--ACK--                                服务端 socket
///
/// 为什么值得做：物理 LAN 上的 67 端口一旦对外服务，就会和上游 DHCP 抢答，
/// 在真实网段里调试 DHCP 本身就是危险的。把地址池换成回环段之后，
/// 整条代码路径（收包 → 解析 → 分配 → 构包 → 选目标 → 发包 → 落盘租约文件）
/// 都能跑到，却一个字节都不上物理网卡。
///
/// 池的两种来源：
///   * 已经配好了池（命令行 `--dhcp-range` 或 UCI）→ **直接用配置里的池**，
///     前提是它整段落在 127.0.0.0/8 里，否则拒绝自检 —— 这样 UCI 模式也能被
///     端到端验证，而不是只验到「配置解析」那一层。
///   * 没配池 → 用内置的 127.0.0.2/32。
pub fn runSelfTest(cfg: *Config) u8 {
    var fails: usize = 0;
    const S = struct {
        var failures: usize = 0;
        fn ck(name: []const u8, cond: bool) void {
            outPrint("  [{s}] {s}\n", .{ if (cond) "OK" else "FAIL", name });
            if (!cond) failures += 1;
        }
    };

    const use_own_pool = cfg.pools.items.len > 0;
    var pool: dhcpv4.Pool = .{
        .start = SELF_CLIENT_IP,
        .end = SELF_CLIENT_IP,
        .netmask = .{ 255, 255, 255, 255 },
        .router = SELF_SERVER_IP,
        .lease_time = 3600,
        .interface = cfg.interface,
    };
    if (use_own_pool) {
        pool = cfg.pools.items[0];
        if (!isLoopback(pool.start) or !isLoopback(pool.end)) {
            outPrint("拒绝自检：池 {d}.{d}.{d}.{d}-{d}.{d}.{d}.{d} 不在 127.0.0.0/8 内。\n" ++
                "在物理网段上跑自检会与上游 DHCP 抢答 —— 请改用回环段内的池。\n", .{
                pool.start[0], pool.start[1], pool.start[2], pool.start[3],
                pool.end[0],   pool.end[1],   pool.end[2],   pool.end[3],
            });
            return 2;
        }
    }
    // 分配器在没有静态绑定命中时，第一个可用地址就是池首
    cfg.server_id = SELF_SERVER_IP;

    var rt = Runtime.init(cfg);
    rt.openSocket() catch |e| {
        outPrint("无法建立服务端 socket: {s}\n", .{@errorName(e)});
        return 1;
    };
    defer if (rt.fd >= 0) net.close(rt.fd);
    rt.leases = dhcpv4.LeaseDb.init(&rt.lease_storage);

    // 没配池时才装临时池（不动 cfg.pools，避免影响后续统计）
    const saved_pools = cfg.pools;
    if (!use_own_pool) {
        cfg.pools = .empty;
        cfg.pools.append(cfg.allocator, pool) catch return 1;
    }
    defer {
        if (!use_own_pool) {
            cfg.pools.deinit(cfg.allocator);
            cfg.pools = saved_pools;
        }
    }

    const cf = net.socketCreate(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP) catch {
        outPrint("无法建立客户端 socket\n", .{});
        return 1;
    };
    defer net.close(cf);
    net.setReuseAddr(cf) catch {};
    net.setBroadcast(cf);
    // 绑 INADDR_ANY 而不是某个 127.x：回环段里任意地址都是本机地址，
    // 绑通配才能收到单播到「池内任意 yiaddr」的 OFFER/ACK
    // （原来绑 127.0.0.2 只在池恰好是 127.0.0.2/32 时才收得到）。
    var csa = addr.SockAddr.fromIp4(0, cfg.client_port);
    net.bind(cf, &csa) catch |e| {
        outPrint("无法绑定客户端 0.0.0.0:{d}: {s}\n", .{ cfg.client_port, @errorName(e) });
        return 1;
    };

    const mac = [_]u8{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x99 };
    const hostname = "zdselftest";

    // 期望值必须按**配置**推出来，而不是写死 —— 否则「配置里有静态绑定」
    // 这种情形会把一个正确的实现判成失败。
    // 分配顺序（dhcpv4.zig 的 LeaseDb.alloc）是 静态 > 已有 > 点名 > 扫描，
    // 且静态地址必须落在池内才生效（odhcpd 同样只认池内静态）。
    var expect_ip: [4]u8 = pool.start;
    var expect_lease: u32 = pool.lease_time;
    // 静态绑定的 name 优先于客户端自报的名字（odhcpd dhcpv4.c:668）
    var expect_name: []const u8 = hostname;
    for (cfg.statics.items) |sh| {
        if (!dhcpv4.macEqual(&sh.mac, &mac)) continue;
        if (!pool.contains(sh.ip)) continue;
        expect_ip = sh.ip;
        if (sh.lease_time != 0) expect_lease = sh.lease_time;
        if (sh.hostname) |nm| {
            if (nm.len > 0) expect_name = nm;
        }
        break;
    }
    outPrint("  期望：yiaddr={d}.{d}.{d}.{d}（{s}），租期 {d}s，租约名 {s}\n", .{
        expect_ip[0],
        expect_ip[1],
        expect_ip[2],
        expect_ip[3],
        if (expect_lease == pool.lease_time) "池默认" else "静态绑定覆盖",
        expect_lease,
        expect_name,
    });

    outPrint("== 回环自检：池 {d}.{d}.{d}.{d}-{d}.{d}.{d}.{d}（掩码 {d}.{d}.{d}.{d}）" ++
        "，来源 {s}，服务端 :{d}，客户端 0.0.0.0:{d} ==\n", .{
        pool.start[0],   pool.start[1],
        pool.start[2],   pool.start[3],
        pool.end[0],     pool.end[1],
        pool.end[2],     pool.end[3],
        pool.netmask[0], pool.netmask[1],
        pool.netmask[2], pool.netmask[3],
        if (use_own_pool) "配置" else "内置",
        cfg.port,        cfg.client_port,
    });

    // ---- 1. DISCOVER -> OFFER ----
    const xid: u32 = 0x5eed0001;
    var pkt: [MAX_PACKET]u8 = undefined;
    const dn = buildClientMsg(&pkt, xid, &mac, .discover, null, null, hostname);
    var rbuf: [MAX_PACKET]u8 = undefined;
    const off_len = exchange(&rt, cf, cfg.port, pkt[0..dn], &rbuf) orelse {
        outPrint("  [FAIL] 没有收到 OFFER（服务端无响应）\n", .{});
        return 1;
    };
    const offer = dhcpv4.parse(rbuf[0..off_len]) orelse {
        outPrint("  [FAIL] OFFER 报文解析失败\n", .{});
        return 1;
    };
    S.ck("收到 OFFER 且 op=BOOTREPLY", offer.op == @intFromEnum(dhcpv4.Op.bootreply));
    S.ck("xid 回显一致", std.mem.readInt(u32, &offer.xid, .big) == xid);
    S.ck("chaddr 回显一致", dhcpv4.macEqual(offer.chaddrSlice(), &mac));
    S.ck("消息类型 = OFFER", offer.msgType() == @intFromEnum(dhcpv4.Msg.offer));
    {
        var b: [96]u8 = undefined;
        const msg = std.fmt.bufPrint(&b, "yiaddr = {d}.{d}.{d}.{d}", .{
            expect_ip[0], expect_ip[1], expect_ip[2], expect_ip[3],
        }) catch "yiaddr";
        S.ck(msg, dhcpv4.ipToU32(offer.yiaddr) == dhcpv4.ipToU32(expect_ip));
    }
    S.ck("option 54 = 服务端标识", blk: {
        const sid = offer.optionIp(dhcpv4.Opt.server_id) orelse break :blk false;
        break :blk dhcpv4.ipToU32(sid) == dhcpv4.ipToU32(SELF_SERVER_IP);
    });
    {
        var b: [64]u8 = undefined;
        const msg = std.fmt.bufPrint(&b, "option 51 租期 = {d}", .{expect_lease}) catch "option 51 租期";
        S.ck(msg, offer.optionU32(dhcpv4.Opt.lease_time) == expect_lease);
    }
    {
        var b: [80]u8 = undefined;
        const msg = std.fmt.bufPrint(&b, "option 58/59 = {d}/{d}", .{
            t1Of(expect_lease), t2Of(expect_lease),
        }) catch "option 58/59";
        S.ck(msg, blk: {
            const a1 = offer.optionU32(dhcpv4.Opt.t1) orelse break :blk false;
            const a2 = offer.optionU32(dhcpv4.Opt.t2) orelse break :blk false;
            break :blk a1 == t1Of(expect_lease) and a2 == t2Of(expect_lease);
        });
    }
    {
        var b: [64]u8 = undefined;
        const msg = std.fmt.bufPrint(&b, "option 1 掩码 = {d}.{d}.{d}.{d}", .{
            pool.netmask[0], pool.netmask[1], pool.netmask[2], pool.netmask[3],
        }) catch "option 1 掩码";
        S.ck(msg, blk: {
            const nm = offer.optionIp(dhcpv4.Opt.netmask) orelse break :blk false;
            break :blk dhcpv4.ipToU32(nm) == dhcpv4.ipToU32(pool.netmask);
        });
    }
    {
        var b: [80]u8 = undefined;
        const msg = std.fmt.bufPrint(&b, "option 3 网关 = {d}.{d}.{d}.{d}", .{
            pool.router[0], pool.router[1], pool.router[2], pool.router[3],
        }) catch "option 3 网关";
        S.ck(msg, blk: {
            const gw = offer.optionIp(dhcpv4.Opt.router) orelse break :blk false;
            break :blk dhcpv4.ipToU32(gw) == dhcpv4.ipToU32(pool.router);
        });
    }

    // ---- 2. REQUEST -> ACK（点 OFFER 给的那个地址，这才是客户端的真实行为） ----
    const got_ip = offer.yiaddr;
    const xid2: u32 = 0x5eed0002;
    const sid = offer.optionIp(dhcpv4.Opt.server_id).?;
    const rn = buildClientMsg(&pkt, xid2, &mac, .request, got_ip, sid, hostname);
    const ack_len = exchange(&rt, cf, cfg.port, pkt[0..rn], &rbuf) orelse {
        outPrint("  [FAIL] 没有收到 ACK\n", .{});
        return 1;
    };
    const ack = dhcpv4.parse(rbuf[0..ack_len]) orelse return 1;
    S.ck("消息类型 = ACK", ack.msgType() == @intFromEnum(dhcpv4.Msg.ack));
    S.ck("ACK 的 yiaddr 与 OFFER 一致", dhcpv4.ipToU32(ack.yiaddr) == dhcpv4.ipToU32(got_ip));

    // ---- 3. 租约必须落到内核记录里 ----
    S.ck("租约状态 = bound", blk: {
        const l = rt.leases.find(got_ip) orelse break :blk false;
        break :blk l.state == .bound;
    });

    // ---- 4. 落盘文件 ----
    rt.writeLeaseFiles() catch |e| outPrint("写租约文件失败: {s}\n", .{@errorName(e)});
    var pathb: [512]u8 = undefined;
    const hosts_path = std.fmt.bufPrint(&pathb, "{s}/odhcpd.hosts.{s}", .{
        cfg.hosts_dir, cfg.interface orelse "lan",
    }) catch "?";
    var fbuf: [512]u8 = undefined;
    var n: usize = 0;
    if (readWholeFile(hosts_path, &fbuf)) |got| {
        n = got;
    }
    const content = fbuf[0..n];
    outPrint("  租约文件: {s} -> {s}\n", .{ hosts_path, if (n > 0) content else "(空/不存在)" });

    var expect_buf: [128]u8 = undefined;
    const expect = std.fmt.bufPrint(&expect_buf, "{d}.{d}.{d}.{d}\t{s}", .{
        got_ip[0], got_ip[1], got_ip[2], got_ip[3], expect_name,
    }) catch "";
    S.ck("hosts 文件含该租约（且名字按静态绑定优先）", n > 0 and std.mem.startsWith(u8, content, expect));

    // ---- 5. 畸形报文不能让服务端崩溃 ----
    const junk = [_]u8{0x01} ** 260;
    if (sendToServer(cf, cfg.port, &junk)) pumpServer(&rt, 500);
    S.ck("畸形报文后进程仍然存活", true);

    fails = S.failures;
    outPrint("\n", .{});
    if (fails == 0) {
        outPrint("自检全部通过\n", .{});
        return 0;
    }
    outPrint("自检失败 {d} 项\n", .{fails});
    return 1;
}

/// 组一个客户端侧报文（DISCOVER / REQUEST）
fn buildClientMsg(
    buf: []u8,
    xid: u32,
    mac: []const u8,
    mt: dhcpv4.Msg,
    requested: ?[4]u8,
    server_id: ?[4]u8,
    hostname: []const u8,
) usize {
    var m = dhcpv4.Message{};
    m.op = @intFromEnum(dhcpv4.Op.bootrequest);
    m.htype = 1;
    m.hlen = @intCast(mac.len);
    m.xid = .{ @truncate(xid >> 24), @truncate(xid >> 16), @truncate(xid >> 8), @truncate(xid) };
    @memcpy(m.chaddr[0..mac.len], mac);

    var b = dhcpv4.Builder.init(buf);
    b.header(&m) catch return 0;
    b.optionU8v(dhcpv4.Opt.message, @intFromEnum(mt)) catch return 0;
    if (requested) |ip| b.optionIpv(dhcpv4.Opt.requested_ip, ip) catch return 0;
    if (server_id) |sid| b.optionIpv(dhcpv4.Opt.server_id, sid) catch return 0;
    b.option(dhcpv4.Opt.hostname, hostname) catch return 0;
    var cid: [7]u8 = undefined;
    cid[0] = 1; // RFC2132：类型 1 = Ethernet
    @memcpy(cid[1..7], mac[0..6]);
    b.option(dhcpv4.Opt.client_id, &cid) catch return 0;
    return b.finish();
}

fn sendToServer(fd: posix.fd_t, port: u16, payload: []const u8) bool {
    var dst = addr.SockAddr.fromIp4(std.mem.nativeToBig(u32, dhcpv4.ipToU32(SELF_SERVER_IP)), port);
    _ = net.sendto(fd, payload, &dst, 0) catch return false;
    return true;
}

/// 自检专用：把服务端的「收包 → 处理 → 回包」跑一轮。
///
/// 正常运行时这一步是 `run()` 里的事件循环在跑；自检没有事件循环，
/// 必须显式泵一次 —— 否则客户端只是在往一个没人读的 socket 里发包
/// （第一版就是这样，表现为「没有收到 OFFER」，很容易误判成协议实现错了）。
fn pumpServer(rt: *Runtime, timeout_ms: i32) void {
    var fds = [_]posix.pollfd{.{ .fd = rt.fd, .events = posix.POLL.IN, .revents = 0 }};
    const n = posix.poll(&fds, timeout_ms) catch return;
    if (n == 0) return;
    if ((fds[0].revents & posix.POLL.IN) == 0) return;

    var buf: [MAX_PACKET]u8 = undefined;
    var control: [128]u8 align(@alignOf(usize)) = undefined;
    const got = rt.recvPacket(&buf, &control) catch return;
    if (got.len > 0) rt.handle(got.buf[0..got.len], got.ifindex, got.src);
}

/// 自检专用：发一个请求并取回应答（中间把服务端泵一轮）。
fn exchange(rt: *Runtime, cf: posix.fd_t, port: u16, payload: []const u8, out: []u8) ?usize {
    if (!sendToServer(cf, port, payload)) return null;
    pumpServer(rt, 1000);
    return recvFromServer(cf, out);
}

fn recvFromServer(fd: posix.fd_t, buf: []u8) ?usize {
    var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.IN, .revents = 0 }};
    _ = posix.poll(&fds, 2000) catch return null;
    if ((fds[0].revents & posix.POLL.IN) == 0) return null;
    return net.recv(fd, buf, 0) catch null;
}

/// 把文件读进调用方的缓冲，返回读到的字节数。
///
/// **必须循环读到 EOF**：一次 `read()` 不保证把整个文件读完（普通文件通常会，
/// 但状态文件在 tmpfs 上被并发重写时可能返回半截）。早期版本只读一次，恢复
/// 租约时会随机少掉后半段记录。
/// 文件超过缓冲则截断 —— 状态文件撑死几十 KB，缓冲远大于此。
fn readWholeFile(path: []const u8, buf: []u8) ?usize {
    const fd = posix.openat(posix.AT.FDCWD, path, posix.O{ .ACCMODE = .RDONLY }, 0) catch return null;
    defer _ = system.close(fd);
    var total: usize = 0;
    while (total < buf.len) {
        const rc = system.read(fd, buf.ptr + total, buf.len - total);
        if (net.errno(rc) != .SUCCESS) return null;
        const n: usize = @intCast(rc);
        if (n == 0) break;
        total += n;
    }
    return total;
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

const t = std.testing;

test "odhcpd：租期文本解析（12h / 30m / 无限）" {
    try t.expectEqual(@as(?u32, 43200), parseLeaseTime("12h"));
    try t.expectEqual(@as(?u32, 1800), parseLeaseTime("30m"));
    try t.expectEqual(@as(?u32, 45), parseLeaseTime("45s"));
    try t.expectEqual(@as(?u32, 3600), parseLeaseTime("3600"));
    try t.expectEqual(@as(?u32, 0xFFFFFFFF), parseLeaseTime("infinite"));
    try t.expectEqual(@as(?u32, null), parseLeaseTime("abc"));
    try t.expectEqual(@as(?u32, null), parseLeaseTime(""));
}

test "odhcpd：hostname_valid 与 odhcpd_hostname_valid 同义" {
    try t.expect(hostnameValid("nas"));
    try t.expect(hostnameValid("my-pc"));
    try t.expect(hostnameValid("a.b.c"));
    try t.expect(hostnameValid("PC01"));
    try t.expect(!hostnameValid(""));
    try t.expect(!hostnameValid("has space"));
    try t.expect(!hostnameValid("bad\nname"));
    try t.expect(!hostnameValid("under_score"));
    try t.expect(!hostnameValid(".leading"));
    try t.expect(!hostnameValid("trailing."));
}

test "odhcpd：主机名转义必须拦住换行与空格（GHSA-hhmc-92hw-535f）" {
    var buf: [256]u8 = undefined;

    // 合法主机名原样写出
    try t.expectEqualStrings("nas-01", escapeHostname(&buf, "nas-01"));

    // 换行 -> \x0a，否则会在状态文件里伪造出一条新记录
    try t.expectEqualStrings("a\\x0ab", escapeHostname(&buf, "a\nb"));
    // 空格 -> \x20，否则会在同一行伪造出额外字段
    try t.expectEqualStrings("a\\x20b", escapeHostname(&buf, "a b"));
    // 冒号、斜杠等同样转义
    try t.expectEqualStrings("a\\x3ab", escapeHostname(&buf, "a:b"));
    // 高字节
    try t.expectEqualStrings("\\x80", escapeHostname(&buf, "\x80"));

    // 转义结果里绝不能出现裸换行
    const evil = "x\n# fake lease line";
    const esc = escapeHostname(&buf, evil);
    try t.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, esc, '\n'));
    try t.expectEqual(@as(?usize, null), std.mem.indexOfScalar(u8, esc, ' '));
}

test "odhcpd：--dhcp-range 解析（含掩码与租期）" {
    var cfg = Config{ .allocator = t.allocator };
    defer cfg.deinit();

    try parseRange(&cfg, "192.168.9.100,192.168.9.200,255.255.255.0,12h");
    try t.expectEqual(@as(usize, 1), cfg.pools.items.len);
    const p = cfg.pools.items[0];
    try t.expectEqual([4]u8{ 192, 168, 9, 100 }, p.start);
    try t.expectEqual([4]u8{ 192, 168, 9, 200 }, p.end);
    try t.expectEqual(@as(u32, 43200), p.lease_time);
    try t.expectEqual(@as(u32, 101), p.size());
    // 网关默认取网络号 +1
    try t.expectEqual([4]u8{ 192, 168, 9, 1 }, p.router);

    // 省略掩码与租期
    try parseRange(&cfg, "10.0.0.10,10.0.0.20");
    try t.expectEqual([4]u8{ 255, 255, 255, 0 }, cfg.pools.items[1].netmask);

    try t.expectError(error.BadRange, parseRange(&cfg, "not-an-ip,10.0.0.20"));
    try t.expectError(error.BadRange, parseRange(&cfg, "10.0.0.10"));
}

test "odhcpd：--dhcp-host 解析出静态绑定" {
    var cfg = Config{ .allocator = t.allocator };
    defer cfg.deinit();

    try parseHost(&cfg, "aa:bb:cc:dd:ee:ff,192.168.9.5,nas,24h");
    try t.expectEqual(@as(usize, 1), cfg.statics.items.len);
    const s = cfg.statics.items[0];
    try t.expectEqual([6]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, s.mac);
    try t.expectEqual([4]u8{ 192, 168, 9, 5 }, s.ip);
    try t.expectEqualStrings("nas", s.hostname.?);
    try t.expectEqual(@as(u32, 86400), s.lease_time);

    // 省略名字与租期
    try parseHost(&cfg, "02:00:00:00:00:01,192.168.9.6");
    try t.expectEqual(@as(?[]const u8, null), cfg.statics.items[1].hostname);
    try t.expectEqual(@as(u32, 0), cfg.statics.items[1].lease_time);

    // 没有 MAC 的条目要忽略而不是崩
    try parseHost(&cfg, "192.168.9.7");
    try t.expectEqual(@as(usize, 2), cfg.statics.items.len);

    // 有 MAC 但没地址 -> 忽略
    try parseHost(&cfg, "aa:bb:cc:dd:ee:99,nas");
    try t.expectEqual(@as(usize, 2), cfg.statics.items.len);
}

test "odhcpd：--dhcp-option 解析（数字号与 option:名 两种写法）" {
    var cfg = Config{ .allocator = t.allocator };
    defer cfg.deinit();

    try parseOption(&cfg, "option:router,192.168.9.1");
    try t.expectEqual(@as(u8, 3), cfg.user_opts.items[0].code);
    try t.expectEqualSlices(u8, &[_]u8{ 192, 168, 9, 1 }, cfg.user_opts.items[0].data[0..4]);

    try parseOption(&cfg, "6,1.1.1.1,8.8.8.8");
    try t.expectEqual(@as(u8, 6), cfg.user_opts.items[1].code);
    try t.expectEqual(@as(u8, 8), cfg.user_opts.items[1].len);
    try t.expectEqualSlices(u8, &[_]u8{ 1, 1, 1, 1, 8, 8, 8, 8 }, cfg.user_opts.items[1].data[0..8]);

    // 字符串型选项（如 option:domain-name）
    try parseOption(&cfg, "option:domain-name,lan");
    try t.expectEqual(@as(u8, 15), cfg.user_opts.items[2].code);
    try t.expectEqualSlices(u8, "lan", cfg.user_opts.items[2].data[0..3]);

    // tag: 形式暂不支持，应当被忽略而不是当成选项号
    const before = cfg.user_opts.items.len;
    try parseOption(&cfg, "tag:voip,option:router,1.2.3.4");
    try t.expectEqual(before, cfg.user_opts.items.len);
}

test "odhcpd：整条命令行解析与不认识的选项报错" {
    var cfg = Config{ .allocator = t.allocator };
    defer cfg.deinit();

    const args = [_][]const u8{
        "--dhcp-range=192.168.9.10,192.168.9.50,255.255.255.0,1h",
        "--dhcp-host=aa:bb:cc:dd:ee:ff,192.168.9.5,nas",
        "--interface=br-lan",
        "--pid-file=/var/run/odhcpd.pid",
        "--domain=lan",
        "--log-dhcp",
        "--dhcp-authoritative",
        "-k",
    };
    try t.expect(try parseArgs(&cfg, &args));
    try t.expectEqual(@as(usize, 1), cfg.pools.items.len);
    try t.expectEqual(@as(usize, 1), cfg.statics.items.len);
    try t.expectEqualStrings("br-lan", cfg.interface.?);
    try t.expectEqualStrings("/var/run/odhcpd.pid", cfg.pid_file.?);
    try t.expectEqualStrings("lan", cfg.domain.?);
    try t.expect(cfg.log_dhcp);
    try t.expect(cfg.authoritative);

    // 不认识的选项必须报错（配置写错了却毫无提示是最糟的情况）
    const bad = [_][]const u8{"--not-a-real-option"};
    try t.expect(!try parseArgs(&cfg, &bad));
}

test "odhcpd：T1/T2 取值（RFC2131 §4.4.5 的 0.5 / 0.875）" {
    try t.expectEqual(@as(u32, 1800), t1Of(3600));
    try t.expectEqual(@as(u32, 3150), t2Of(3600));
    try t.expectEqual(@as(u32, 1350), t1Of(2700));
    try t.expectEqual(@as(u32, 2363), t2Of(2700)); // 2700-337，不是 2700*7/8=2362
    try t.expectEqual(@as(u32, 900), t1Of(1800));
    try t.expectEqual(@as(u32, 1575), t2Of(1800));
    try t.expectEqual(@as(u32, 21600), t1Of(43200));
    try t.expectEqual(@as(u32, 37800), t2Of(43200));
    // 恒有 T1 < T2 < lease（infinite=0xFFFFFFFF 那档调用处已跳过）
    const samples = [_]u32{ 60, 600, 1800, 3600, 43200, 86400 };
    for (samples) |lt| {
        try t.expect(t1Of(lt) < t2Of(lt));
        try t.expect(t2Of(lt) < lt);
        try t.expect(t1Of(lt) > 0);
    }
    // 不能因为 lt*7 回绕而算错：t2Of 用的是减法
    try t.expectEqual(@as(u32, 0xFFFFFFFF - (0xFFFFFFFF / 8)), t2Of(0xFFFFFFFF));
}

test "odhcpd：配置来源的选择 —— 只有配置类参数才算『命令行风格』" {
    // 纯开关（-k / --log-dhcp / --interface / --pid-file）不算配置类参数，
    // 所以 procd 那种「无参数或只有通用开关」的启动方式会走 UCI。
    {
        var cfg = Config{ .allocator = t.allocator };
        defer cfg.deinit();
        const flags_only = [_][]const u8{ "-k", "--log-dhcp", "--interface=br-lan", "--pid-file=/var/run/odhcpd.pid" };
        try t.expect(try parseArgs(&cfg, &flags_only));
        try t.expect(!cfg.cli_conf_seen);
    }
    // 三种配置类参数都要置位
    const cases = [_][]const u8{
        "--dhcp-range=10.9.0.10,10.9.0.20,255.255.255.0,1h",
        "--dhcp-host=aa:bb:cc:dd:ee:ff,10.9.0.5",
        "--dhcp-option=option:mtu,1500",
    };
    for (cases) |c| {
        var cfg = Config{ .allocator = t.allocator };
        defer cfg.deinit();
        const one = [_][]const u8{c};
        try t.expect(try parseArgs(&cfg, &one));
        try t.expect(cfg.cli_conf_seen);
    }
}

test "odhcpd：--no-uci / --uci-file / --uci-network / --uci-state" {
    var cfg = Config{ .allocator = t.allocator };
    defer cfg.deinit();
    // 默认值必须是 odhcpd 的那三条路径
    try t.expect(!cfg.no_uci);
    try t.expectEqualStrings("/etc/config/dhcp", cfg.uci_path);
    try t.expectEqualStrings("/etc/config/network", cfg.uci_network_path);
    try t.expectEqualStrings("/var/state/network", cfg.uci_state_path);

    const args = [_][]const u8{
        "--no-uci",
        "--uci-file=/tmp/t/dhcp",
        "--uci-network=/tmp/t/network",
        "--uci-state=/tmp/t/state",
    };
    try t.expect(try parseArgs(&cfg, &args));
    try t.expect(cfg.no_uci);
    try t.expectEqualStrings("/tmp/t/dhcp", cfg.uci_path);
    try t.expectEqualStrings("/tmp/t/network", cfg.uci_network_path);
    try t.expectEqualStrings("/tmp/t/state", cfg.uci_state_path);
}

test "odhcpd：持久字符串走 arena，deinit 后不泄漏（且不会误 free argv）" {
    var cfg = Config{ .allocator = t.allocator };
    var strs_used = false;
    {
        // 命令行路径给的是 argv 切片，绝不能被 free —— 这里用字面量模拟
        const args = [_][]const u8{"--dhcp-range=10.9.0.10,10.9.0.20,255.255.255.0,1h"};
        try t.expect(try parseArgs(&cfg, &args));
        try t.expectEqual([4]u8{ 10, 9, 0, 10 }, cfg.pools.items[0].start);
        // 再手动往 arena 里塞一个字符串，验证 deinit 会回收
        const s = try cfg.strDup("hello");
        try t.expectEqualStrings("hello", s);
        strs_used = true;
    }
    try t.expect(strs_used);
    cfg.deinit();
}

test "odhcpd：--dhcp-option-force 与 --zd-* 扩展" {
    var cfg = Config{ .allocator = t.allocator };
    defer cfg.deinit();

    const args = [_][]const u8{
        "--dhcp-option-force=option:mtu,1500",
        "--zd-hosts-dir=/tmp/hosts",
        "--zd-server-id=192.168.9.1",
    };
    try t.expect(try parseArgs(&cfg, &args));
    try t.expectEqual(@as(u8, 26), cfg.user_opts.items[0].code);
    try t.expectEqualStrings("/tmp/hosts", cfg.hosts_dir);
    try t.expectEqual([4]u8{ 192, 168, 9, 1 }, cfg.server_id.?);
    const bad = [_][]const u8{"--zd-server-id=999.1.1.1"};
    try t.expect(!try parseArgs(&cfg, &bad));
}

// ---------------------------------------------------------------------------
// 租约恢复（loadLeaseFile）
// ---------------------------------------------------------------------------

fn testLeaseRuntime(cfg: *Config) Runtime {
    var rt = Runtime.init(cfg);
    rt.leases = dhcpv4.LeaseDb.init(&rt.lease_storage);
    return rt;
}

test "odhcpd：MAC 文本解析（odhcpd 的冒号写法与紧凑写法都要认）" {
    const want = [6]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    try t.expectEqual(want, parseMacText("aa:bb:cc:dd:ee:ff").?);
    try t.expectEqual(want, parseMacText("aabbccddeeff").?);
    try t.expectEqual(@as(?[6]u8, null), parseMacText("aa:bb:cc:dd:ee"));
    try t.expectEqual(@as(?[6]u8, null), parseMacText("zz:bb:cc:dd:ee:ff"));
    try t.expectEqual(@as(?[6]u8, null), parseMacText(""));
}

test "odhcpd：主机名转义与反转义必须可逆" {
    var ebuf: [256]u8 = undefined;
    var dbuf: [256]u8 = undefined;
    for ([_][]const u8{ "nas-01", "a\nb", "a b", "a:b", "\x80\xff", "my.host" }) |raw| {
        const esc = escapeHostname(&ebuf, raw);
        try t.expectEqualStrings(raw, unescapeHostname(&dbuf, esc));
    }
    // 非法转义（`\x` 后不是两位十六进制）宁可截断也不能还原出半截名字
    try t.expectEqualStrings("a", unescapeHostname(&dbuf, "a\\xzz"));
    try t.expectEqualStrings("", unescapeHostname(&dbuf, "\\x4"));
}

test "odhcpd：状态行解析 —— 绝对时间 / 相对时间 / 无限 / 已过期" {
    const now: i64 = 1_700_000_000;
    const head = "# br-lan aa:bb:cc:dd:ee:ff ipv4 ";

    var line: [256]u8 = undefined;

    // odhcpd statefiles.c:576 写的是**绝对墙钟秒**
    const abs = parseStateLine(try std.fmt.bufPrint(&line, "{s}nas 1700036000 3232235640 32 192.168.0.120/32", .{head}), now).?;
    try t.expectEqual(@as(i64, 1700036000), abs.expires);
    try t.expectEqualStrings("nas", abs.hostname().?);
    try t.expectEqual([4]u8{ 192, 168, 0, 120 }, abs.ip);
    try t.expectEqual([6]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, abs.mac);
    try t.expectEqual(dhcpv4.LeaseState.bound, abs.state);

    // 本移植早期版本写的「剩余秒数」：仍要能读，不能当 1970 年看
    const rel = parseStateLine(try std.fmt.bufPrint(&line, "{s}nas 3600 3232235640 32 192.168.0.120/32", .{head}), now).?;
    try t.expectEqual(now + 3600, rel.expires);

    // -1 = odhcpd 的 INFINITE_VALID
    const inf = parseStateLine(try std.fmt.bufPrint(&line, "{s}nas -1 3232235640 32 192.168.0.120/32", .{head}), now).?;
    try t.expectEqual(now + LEASE_INFINITE_SECS, inf.expires);

    // 0 = 已过期（解析出来交给上层按 expires<=now 丢弃）
    const gone = parseStateLine(try std.fmt.bufPrint(&line, "{s}nas 0 3232235640 32 192.168.0.120/32", .{head}), now).?;
    try t.expectEqual(now, gone.expires);

    // `broken\x20` 前缀的名字不可用
    const broken = parseStateLine(try std.fmt.bufPrint(&line, "{s}broken\\x20bad\\x20name 1700036000 3232235640 32 192.168.0.120/32", .{head}), now).?;
    try t.expectEqual(@as(?[]const u8, null), broken.hostname());

    // `-` 表示没有主机名
    const none = parseStateLine(try std.fmt.bufPrint(&line, "{s}- 1700036000 3232235640 32 192.168.0.120/32", .{head}), now).?;
    try t.expectEqual(@as(?[]const u8, null), none.hostname());

    // 非 v4 记录（第 4 字段不是字面量 ipv4）必须被排除
    try t.expectEqual(@as(?dhcpv4.Lease, null), parseStateLine("# br-lan 00030001aabb ipv6 nas 1700036000 0 64 2001:db8::1/64", now));
    // 字段数不足
    try t.expectEqual(@as(?dhcpv4.Lease, null), parseStateLine("# br-lan aa:bb:cc:dd:ee:ff ipv4 nas", now));
    // MAC 非法
    try t.expectEqual(@as(?dhcpv4.Lease, null), parseStateLine("# br-lan zz:bb:cc:dd:ee:ff ipv4 nas 1700036000 0 32 192.168.0.120/32", now));
}

test "odhcpd：启动恢复租约 —— 旧版 odhcpd 的混写文件也要能读，且写出后能原样读回" {
    // 用 .zig-cache 下的临时目录（已被 .gitignore 忽略），不污染 /tmp/hosts
    // Zig 0.16 移除了 std.fs.cwd()，直接用 openat/mkdirat（与 util.zig 一致）
    _ = system.mkdir(".zig-cache", 0o755);
    _ = system.mkdir(".zig-cache/zd-test", 0o755);
    const dir = ".zig-cache/zd-test";
    const state_path = dir ++ "/odhcpd";
    const dnsmasq_path = dir ++ "/dhcp.leases";

    // 先清掉上一轮运行留下的文件。不清的话：本轮先按状态文件恢复出
    // `now+3600`，紧接着又被上一轮那份 dnsmasq 文件覆盖成更早的到期时间
    // （实测差 132 秒 = 两次运行的间隔），断言就会莫名其妙地飘。
    _ = system.unlink(state_path);
    _ = system.unlink(dnsmasq_path);

    const now = util.dnsmasqTime();
    var content: [1024]u8 = undefined;
    // 注意：`\\` 行字符串**不处理转义**，制表符必须用普通字符串写出来，
    // 否则文件里会是两个字符 `\` + `t`，hosts 行就退化成单个字段了。
    const hosts_part = "192.168.0.120\tdebian.lan\tdebian\n" ++
        "192.168.0.121\tprinter.lan\n";
    const body = try std.fmt.bufPrint(&content, hosts_part ++
        \\# br-lan aa:bb:cc:dd:ee:ff ipv4 - {d} 3232235640 32 192.168.0.120/32
        \\# br-lan 11:22:33:44:55:66 ipv4 - {d} 3232235641 32 192.168.0.121/32
        \\# br-lan 99:99:99:99:99:99 ipv4 gone 0 0 32 192.168.0.122/32
        \\# br-lan 88:88:88:88:88:88 ipv4 other {d} 0 32 10.0.0.5/32
        \\
    , .{ now + 3600, now + 7200, now + 3600 });
    {
        const fd = try posix.openat(posix.AT.FDCWD, state_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
        defer _ = system.close(fd);
        var off: usize = 0;
        while (off < body.len) {
            const rc = system.write(fd, body[off..].ptr, body.len - off);
            if (net.errno(rc) != .SUCCESS) return error.WriteFailed;
            off += @intCast(rc);
        }
    }

    var cfg = Config{ .allocator = t.allocator };
    defer cfg.deinit();
    try parseRange(&cfg, "192.168.0.100,192.168.0.200,255.255.255.0,12h");
    cfg.state_file = state_path;
    cfg.dnsmasq_leasefile = dnsmasq_path;
    cfg.hosts_dir = dir;

    var rt = testLeaseRuntime(&cfg);
    rt.loadLeaseFile();

    // .122 已过期、10.0.0.5 不在池内 —— 都该被丢掉
    try t.expectEqual(@as(usize, 2), rt.leases.count);

    const l120 = rt.leases.find(.{ 192, 168, 0, 120 }).?;
    try t.expectEqualStrings("debian", l120.hostname().?); // 来自 hosts 行的第 3 字段
    try t.expectEqual(@as(i64, now + 3600), l120.expires);

    const l121 = rt.leases.find(.{ 192, 168, 0, 121 }).?;
    try t.expectEqualStrings("printer", l121.hostname().?); // 只有 FQDN，截掉域名
    try t.expectEqual(@as(i64, now + 7200), l121.expires);

    // 往返：写出去再读回来，条数、名字、到期时间都不能变。
    // 这条锁住的是「valid_until 必须是绝对时间」—— 写相对秒数的话，
    // 第二次读会把 now+剩余 当成绝对时间，到期时间立刻变得离谱。
    //
    // 注意自 2026-09-21 起 v4 往返走的是 **dnsmasq 格式文件**
    // （`cfg.dnsmasq_leasefile`），状态文件只留 v6 行 —— 原因见
    // `writeStateFile` 的注释（LuCI 会把状态文件每一行都塞进 v4 租约表，
    // 两处都写 v4 就重复显示）。所以第二轮的配置同样要给出 dnsmasq 文件路径。
    try rt.writeLeaseFiles();
    var cfg2 = Config{ .allocator = t.allocator };
    defer cfg2.deinit();
    try parseRange(&cfg2, "192.168.0.100,192.168.0.200,255.255.255.0,12h");
    cfg2.state_file = state_path;
    cfg2.dnsmasq_leasefile = dnsmasq_path;
    cfg2.hosts_dir = dir;

    var rt2 = testLeaseRuntime(&cfg2);
    rt2.loadLeaseFile();
    try t.expectEqual(@as(usize, 2), rt2.leases.count);
    const r120 = rt2.leases.find(.{ 192, 168, 0, 120 }).?;
    try t.expectEqualStrings("debian", r120.hostname().?);
    try t.expectEqual(l120.expires, r120.expires);
    const r121 = rt2.leases.find(.{ 192, 168, 0, 121 }).?;
    try t.expectEqualStrings("printer", r121.hostname().?);
    try t.expectEqual(l121.expires, r121.expires);
}

test "odhcpd：v4 状态行不再写出（LuCI 租约去重的前提）" {
    // LuCI 的 luci-rpc 会把 `/tmp/hosts/odhcpd` 的**每一行**都 append 进
    // `dhcp_leases`（标 duid），同时又把 `/tmp/dhcp.leases` 的每一行也 append
    // 进去（标 macaddr）。两处都写 v4 → 同一台设备在概览里出现两次，
    // 一次带 MAC、一次不带。实测 .1：6 台设备 → 12 行。
    //
    // 所以本测试锁死：状态文件里**只有 v6 行**，v4 只出现在 dnsmasq 文件里。
    _ = system.mkdir(".zig-cache", 0o755);
    _ = system.mkdir(".zig-cache/zd-test6", 0o755);
    const dir = ".zig-cache/zd-test6";
    const state_path = dir ++ "/odhcpd";
    const dnsmasq_path = dir ++ "/dhcp.leases";

    var cfg = Config{ .allocator = t.allocator };
    defer cfg.deinit();
    try parseRange(&cfg, "192.168.0.100,192.168.0.200,255.255.255.0,12h");
    cfg.state_file = state_path;
    cfg.dnsmasq_leasefile = dnsmasq_path;
    cfg.hosts_dir = dir;

    var rt = testLeaseRuntime(&cfg);
    const now = util.dnsmasqTime();
    var lease = dhcpv4.Lease{ .ip = .{ 192, 168, 0, 150 }, .mac = .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, .mac_len = 6, .state = .bound, .expires = now + 3600 };
    lease.setHostname("nas");
    _ = try rt.leases.insert(lease);

    try rt.writeLeaseFiles();

    // 状态文件里不该再出现任何 ipv4 行
    var sbuf: [4096]u8 = undefined;
    const sn = readWholeFile(state_path, &sbuf) orelse 0;
    const state_text = sbuf[0..sn];
    try t.expect(std.mem.indexOf(u8, state_text, "ipv4") == null);

    // dnsmasq 文件里必须有这条 v4 租约，且 MAC 带冒号（与 C lease.c:286 一致）
    var dbuf: [4096]u8 = undefined;
    const dn = readWholeFile(dnsmasq_path, &dbuf) orelse 0;
    const dns_text = dbuf[0..dn];
    try t.expect(std.mem.indexOf(u8, dns_text, "192.168.0.150") != null);
    try t.expect(std.mem.indexOf(u8, dns_text, "aa:bb:cc:dd:ee:ff") != null);
    try t.expect(std.mem.indexOf(u8, dns_text, "nas") != null);

    // 解析器要能读回同一份内容（写读闭环）
    var it = std.mem.splitScalar(u8, dns_text, '\n');
    var found = false;
    while (it.next()) |line| {
        const l = parseDnsmasqLeaseLine(trimEol(line)) orelse continue;
        if (dhcpv4.ipToU32(l.ip) != dhcpv4.ipToU32(.{ 192, 168, 0, 150 })) continue;
        found = true;
        try t.expectEqual(@as(i64, now + 3600), l.expires);
        try t.expectEqualStrings("nas", l.hostname().?);
    }
    try t.expect(found);
}

test "odhcpd：parseDnsmasqLeaseLine 的边界（主机名 * / 非以太网硬件类型）" {
    // 主机名 `*` = 客户端没报名，不该被当成名字
    const a = parseDnsmasqLeaseLine("1790032836 f0:c9:d1:cd:ac:2d 192.168.0.238 * *").?;
    try t.expectEqual(@as(?[]const u8, null), a.hostname());
    try t.expectEqual(@as(i64, 1790032836), a.expires);

    // 非以太网硬件类型：C 写 `%.2x-` 前缀（lease.c:312），解析要跳过它
    const b = parseDnsmasqLeaseLine("1790032836 6-aa:bb:cc:dd:ee:ff 192.168.0.9 nas *").?;
    try t.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, b.mac[0..b.mac_len]);

    // 字段不足 / 地址非法 → 丢弃
    try t.expectEqual(@as(?dhcpv4.Lease, null), parseDnsmasqLeaseLine("1790032836 f0:c9:d1:cd:ac:2d"));
    try t.expectEqual(@as(?dhcpv4.Lease, null), parseDnsmasqLeaseLine("1790032836 f0:c9:d1:cd:ac:2d not-an-ip * *"));
    // 注释行不是租约
    try t.expectEqual(@as(?dhcpv4.Lease, null), parseDnsmasqLeaseLine("# 随便写点什么"));
}

test "odhcpd：UCI 模式必须下发 DNS/域名 —— 手机感叹号回归（2026-09-20）" {
    // 真机踩的坑：UCI 把 list dns / list domain 存进 pool.*，emitStandardOptions
    // 却只读 cfg.*，导致 UCI 模式下 option 6/15 一个都不发。
    const txt =
        \\config dhcp 'lan'
        \\    option interface 'lan'
        \\    option start '100'
        \\    option limit '150'
        \\    option leasetime '12h'
        \\    option dhcpv4 'server'
        \\    list domain 'lan'
        \\
        \\config odhcpd 'odhcpd'
        \\    option maindhcp '1'
        \\
    ;
    const uci_mod = @import("uci.zig");
    var r = try uci_mod.parse(t.allocator, txt);
    defer r.package.deinit();
    var cfg = Config{ .allocator = t.allocator };
    defer cfg.deinit();
    const st = try uci_dhcp.apply(&cfg, .{ .dhcp = &r.package, .ifname_override = "lo" });
    try t.expectEqual(@as(usize, 1), st.pools);

    var rt = Runtime.init(&cfg);
    var out: [MAX_PACKET]u8 = undefined;
    var b = dhcpv4.Builder.init(&out);
    const pool = &cfg.pools.items[0];
    const sid: [4]u8 = .{ 127, 0, 0, 1 };
    try rt.emitStandardOptions(&b, pool, sid);
    const end = b.finish();
    _ = &b;

    // 手工扫 TLV
    var saw_dns = false;
    var dns: [4]u8 = undefined;
    var saw_domain = false;
    var i: usize = 0;
    while (i + 2 <= end) {
        const code = out[i];
        if (code == dhcpv4.Opt.end) break;
        const len: usize = out[i + 1];
        if (code == dhcpv4.Opt.dnsserver and len == 4) {
            saw_dns = true;
            dns = .{ out[i + 2], out[i + 3], out[i + 4], out[i + 5] };
        }
        if (code == dhcpv4.Opt.domain) {
            saw_domain = true;
            try t.expectEqualStrings("lan", out[i + 2 ..][0..len]);
        }
        i += 2 + len;
    }
    // UCI 的 list dns 为空时，池里应已兜底成自身地址（plan.own = lo = 127.0.0.1）
    try t.expect(saw_dns);
    try t.expectEqual(sid, dns);
    try t.expect(saw_domain);
}

test "odhcpd：池没配 DNS 时通告自身为 DNS（缺省规则）" {
    var cfg = Config{ .allocator = t.allocator };
    defer cfg.deinit();
    const pool = dhcpv4.Pool{
        .start = .{ 192, 168, 0, 100 },
        .end = .{ 192, 168, 0, 200 },
        .netmask = .{ 255, 255, 255, 0 },
        .router = .{ 192, 168, 0, 1 },
    };
    var rt = Runtime.init(&cfg);
    var out: [MAX_PACKET]u8 = undefined;
    var b = dhcpv4.Builder.init(&out);
    const sid: [4]u8 = .{ 192, 168, 0, 1 };
    try rt.emitStandardOptions(&b, &pool, sid);
    const end = b.finish();
    _ = &b;

    var saw_dns = false;
    var i: usize = 0;
    while (i + 2 <= end) {
        const code = out[i];
        if (code == dhcpv4.Opt.end) break;
        const len: usize = out[i + 1];
        if (code == dhcpv4.Opt.dnsserver) {
            saw_dns = true;
            try t.expectEqualSlices(u8, &sid, out[i + 2 ..][0..len]);
        }
        i += 2 + len;
    }
    try t.expect(saw_dns);
}

test "odhcpd：单实例闸门 —— 第二个实例必须被拒绝（flock 排他）" {
    // 这就是「odhcpd 只能启动一个」这条硬约束的回归测试。
    // 背景（2026-09-21 实测）：一次开机后同时跑了两个实例，两个实例各有一份
    // 独立租约表，把 192.168.0.102 分别 ACK 给了 debian 和 Redmi-Note-11-5G
    // → 重复 IP → 局域网不通。
    const allocator = std.testing.allocator;
    _ = std.os.linux.mkdir(".zig-cache", 0o755);
    _ = std.os.linux.mkdir(".zig-cache/zd-lock", 0o755);
    const lock_path = ".zig-cache/zd-lock/odhcpd.lock";
    _ = std.os.linux.unlink(lock_path);

    // 第一个实例：拿到锁
    const first = acquireInstanceLockAt(lock_path);
    const fd1 = switch (first) {
        .acquired => |fd| fd,
        else => return error.TestUnexpectedResult,
    };

    // 第二个实例：必须被拒绝，且能报出持有者 pid
    const second = acquireInstanceLockAt(lock_path);
    switch (second) {
        .already_running => |peer| {
            try std.testing.expect(peer != null);
            try std.testing.expectEqual(@as(i32, @intCast(std.os.linux.getpid())), peer.?);
        },
        else => return error.TestUnexpectedResult,
    }

    // 释放后应能重新拿到（锁随 fd 关闭自动释放 —— 正是我们依赖的性质：
    // 进程被杀/崩溃都不会留下陈旧锁）
    _ = allocator;
    _ = std.os.linux.close(fd1);
    const third = acquireInstanceLockAt(lock_path);
    switch (third) {
        .acquired => |fd3| _ = std.os.linux.close(fd3),
        else => return error.TestUnexpectedResult,
    }
}

test "odhcpd：单实例闸门 —— 锁文件路径不可用时只降级告警，不阻断启动" {
    // 宁可少一层保护，也不要起不来。这条锁死「unavailable 不等于拒绝启动」。
    const r = acquireInstanceLockAt("/nonexistent-dir-zzz/odhcpd.lock");
    switch (r) {
        .unavailable => {},
        else => return error.TestUnexpectedResult,
    }
}

test "odhcpd：默认锁路径在 /var/run，且与 pid 文件分开" {
    // 故意不与 --pid-file 共用：pid 文件用 open+truncate+close 写，
    // 拿它做锁会牵动既有语义。
    // 注意不能在这里构造 Config 去读 pid_file —— 默认值是在 parseArgs 里设的，
    // 直接 `Config{ .allocator = ... }` 会得到 null（踩过）。
    try std.testing.expectEqualStrings("/var/run/odhcpd.lock", INSTANCE_LOCK_PATH);
    try std.testing.expect(!std.mem.eql(u8, INSTANCE_LOCK_PATH, "/var/run/odhcpd.pid"));
}

test "odhcpd：解析 /proc/<pid>/stat 的状态字符（含畸形 comm）" {
    // 正常行
    try std.testing.expectEqual(@as(?u8, 'S'), statStateChar("1234 (odhcpd) S 1 2 3"));
    // 僵尸
    try std.testing.expectEqual(@as(?u8, 'Z'), statStateChar("1234 (odhcpd) Z 1 2 3"));
    // comm 里含空格
    try std.testing.expectEqual(@as(?u8, 'Z'), statStateChar("1234 (my odhcpd) Z 1"));
    // comm 里含右括号 —— 必须取最后一个 ')' 之后，否则会读到 ')' 后面的垃圾
    try std.testing.expectEqual(@as(?u8, 'Z'), statStateChar("1234 (a)b) Z 1"));
    try std.testing.expectEqual(@as(?u8, 'R'), statStateChar("1234 ((())) R 1"));
    // 畸形/空 → null（宁可当活的不当僵尸，避免永久拒绝启动）
    try std.testing.expectEqual(@as(?u8, null), statStateChar("garbage"));
    try std.testing.expectEqual(@as(?u8, null), statStateChar("1234 (x)"));
}

test "odhcpd：describeOdhcpdPeers 必须把自己排除在 peer 计数外" {
    // 这条保证第二道闸不会因为「看见自己」而拒绝启动。
    var peers: usize = 0;
    const desc = describeOdhcpdPeers(&peers);
    // 测试进程的 comm 是 unit-tests，不是 odhcpd，所以正常应该 0 个 peer；
    // 即便宿主机上恰好跑着我们的 odhcpd，也只应统计**别的**进程。
    try std.testing.expect(desc.len > 0);
    var peers2: usize = 0;
    _ = describeOdhcpdPeers(&peers2);
    try std.testing.expectEqual(peers, peers2); // 两次扫描结果一致（无副作用）
}

test "odhcpd：识别「odhcpd 守护进程本体」—— init 脚本的 comm 会伪装成 odhcpd" {
    // ★ 这是实际翻过车的点：`/etc/init.d/odhcpd` 是 #! 脚本，内核把执行它的
    // /bin/sh 的 comm 设成 "odhcpd"。若按 comm 判定，每次 `service odhcpd restart`
    // 都会多出一个"同名进程"，闸门误判成已有实例 → 拒绝启动。
    // 所以必须按 argv[0] 的 basename 判定。

    // 本体（procd 的真实启动方式：`command /usr/sbin/odhcpd`，无参数）
    try std.testing.expect(isOdhcpdDaemonCmdline("/usr/sbin/odhcpd\x00"));
    // 带参数也算本体
    try std.testing.expect(isOdhcpdDaemonCmdline("/usr/sbin/odhcpd\x00--dhcp-range=a,b,c,1h\x00"));

    // ★ init 脚本（comm 是 odhcpd，但 argv[0] 是 /bin/sh）—— 必须判为「不是本体」
    try std.testing.expect(!isOdhcpdDaemonCmdline(
        "/bin/sh\x00/etc/rc.common\x00/etc/init.d/odhcpd\x00start\x00",
    ));
    try std.testing.expect(!isOdhcpdDaemonCmdline(
        "/bin/sh\x00/etc/rc.common\x00/etc/init.d/odhcpd\x00restart\x00",
    ));

    // DNS 实例（同一个二进制，但身份不同）—— 必须判为「不是本体」，
    // 否则 odhcpd 启动时会把正在跑的 DNS 当成 peer 而拒绝
    try std.testing.expect(!isOdhcpdDaemonCmdline(
        "/usr/bin/zig-dnsmasq\x00-C\x00/var/etc/zig-dnsmasq.conf\x00-k\x00",
    ));

    // 显式 applet 形态
    try std.testing.expect(isOdhcpdDaemonCmdline("/usr/bin/zig-dnsmasq\x00--applet=odhcpd\x00"));

    // 畸形输入
    try std.testing.expect(!isOdhcpdDaemonCmdline(""));
}

test "odhcpd：baseNameOf" {
    try std.testing.expectEqualStrings("odhcpd", baseNameOf("/usr/sbin/odhcpd"));
    try std.testing.expectEqualStrings("sh", baseNameOf("/bin/sh"));
    try std.testing.expectEqualStrings("odhcpd", baseNameOf("odhcpd"));
    try std.testing.expectEqualStrings("", baseNameOf("/usr/sbin/"));
}
