// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! options.zig — 复刻 dnsmasq 配置解析（option.c 的 one_opt / read_opts 部分）
//!
//! 对应 C 源码 src/option.c：
//!   * one_opt()  —— 解析单条选项（命令行或配置文件）
//!   * read_opts() —— 读取配置文件、处理 # 注释与行尾 \ 续行，以及 conf-file / conf-dir
//!
//! 这里把这两段逻辑移植为纯 Zig，所有服务器/地址记录通过 domain.addUpdateServer()
//! 与 d.address_list 落地，最终由 main 调用 domain.buildServerArray() 排序。

const std = @import("std");
const protocol = @import("protocol.zig");
const addr = @import("addr.zig");
const name = @import("name.zig");
const daemon = @import("daemon.zig");
const domain = @import("domain.zig");
const log = @import("log.zig");

/// 本移植新增、protocol 里没有对应常量的选项位（仅占位，遇到只打印 warning）


/// 已知但本移植未实现的 dnsmasq 选项（识别后打 warning 并忽略，不报错）
/// 识别但不做任何处理的选项（需要 DHCP / DNSSEC / TFTP / auth 等未移植子系统，
/// 或需要额外的数据结构）。打 warning 后忽略，不视为错误。
const known_unimplemented = [_][]const u8{
    // DHCP 相关（本阶段不做）
    "dhcp-range", "dhcp-option", "dhcp-host", "dhcp-leasefile", "dhcp-authoritative",
    "dhcp-broadcast", "dhcp-ignore", "dhcp-ignore-names", "dhcp-no-override",
    "dhcp-fqdn", "dhcp-sequential-ip", "dhcp-script", "dhcp-lease-max",
    "enable-tftp", "tftp-root", "tftp-secure", "tftp-lowercase", "pxe-prompt",
    "dhcp-boot", "dhcp-match", "dhcp-vendorclass", "dhcp-userclass", "dhcp-circuitid",
    "dhcp-remoteid", "dhcp-subscrid", "dhcp-name-match", "dhcp-generate-names",
    "dhcp-rapid-commit", "dhcp-alternate-port", "dhcp-leasefile",
    "no-dhcp-interface", "no-dhcp6-interface", "dhcp-option-force",
    "dhcp-reply-delay", "dhcp-proxy", "dhcp-relay", "bootp", "pxe-service",
    "ra-param", "enable-ra", "quiet-dhcp", "quiet-dhcp6", "quiet-ra",
    "leasefile-ro", "leasequery", "dhcp-ttl", "dhcp-duid", "dhcp-client-update",
    // 本地 RR / 静态记录（需要额外数据结构，后续阶段补）
    "mx-host", "txt-record", "srv-host", "cname", "ptr-record", "host-record",
    "naptr-record", "interface-name", "caa-record", "dns-rr", "rev-server",
    "synth-domain", "localmx", "selfmx",
    // auth / DNSSEC / 其它子系统
    "auth-server", "auth-zone", "auth-sec-servers", "auth-peer", "auth-soa",
    "auth-ttl", "dnssec-check-unsigned", "dnssec-no-timecheck", "dnssec-timestamp",
    "dnssec-limits", "trust-anchor", "dnssec-debug", "conf-script",
    "dns-loop-detect", "bogus-nxdomain", "alias",
    // OpenWrt / ImmortalWrt 生成的配置里常见的发行版私有选项。
    // 不加进来的话，直接把发行版生成的 dnsmasq.conf 喂给本移植会**直接退出**
    // （未知选项走的 return error.UnknownOption），在路由器上替换二进制即
    // 整网 DNS 中断 —— 实机验证时踩到过。
    "enable-ubus", "ubus", "read-ethers", "dhcp-script-user",
    "no-ping", "no-ident", "add-mac", "add-subnet", "umbrella", "connmark",
    "conntrack", "ipset", "nftset", "dynamic-host", "log-debug", "log-facility-limit",
    "cache-rr", "no-0x20", "do-0x20", "max-port", "min-port", "query-port",
    "strip-ecs", "strip-mac",
};

/// 取整数（解析失败返回 null 并打 warning）
fn parseIntU(comptime T: type, d: *daemon.Daemon, val: ?[]const u8, what: []const u8) ?T {
    _ = d;
    const v = val orelse {
        log.warning("{s} 缺少参数", .{what});
        return null;
    };
    return std.fmt.parseInt(T, v, 10) catch {
        log.warning("无法解析 {s}: {s}", .{ what, v });
        return null;
    };
}

/// 判断选项是否需要“取值”（用于 --name value 这种分离写法）
fn longTakesValue(nm: []const u8) bool {
    const takes = [_][]const u8{
        "port", "cache-size", "domain", "log-facility", "pid-file", "user", "group",
        "resolv-file", "addn-hosts", "hostsdir", "conf-file", "conf-dir", "local-ttl", "neg-ttl",
        "max-ttl", "max-cache-ttl", "min-cache-ttl", "edns-packet-max", "use-stale-cache",
        "dns-forward-max", "threads", "interface", "listen-address", "local",
        "server", "address", "alias", "rebind-domain-ok",
    };
    for (takes) |t| if (std.mem.eql(u8, nm, t)) return true;
    return false;
}

/// 短选项是否需要取值
fn shortTakesValue(short: u8) bool {
    return switch (short) {
        'p', 'c', 's', '8', 'x', 'u', 'g', 'r', 'H', 'C', '7' => true,
        else => false,
    };
}

/// 把短选项字符映射到长选项名（对应 option.c 的 optmap）
fn longNameForShort(short: u8) ?[]const u8 {
    return switch (short) {
        'p' => "port",
        'c' => "cache-size",
        'E' => "expand-hosts",
        's' => "domain",
        'q' => "log-queries",
        '8' => "log-facility",
        'x' => "pid-file",
        'u' => "user",
        'g' => "group",
        'r' => "resolv-file",
        'H' => "addn-hosts",
        'h' => "no-hosts",
        'C' => "conf-file",
        '7' => "conf-dir",
        'b' => "bogus-priv",
        'o' => "strict-order",
        'd' => "no-daemon",
        'k' => "keep-in-foreground",
        'R' => "no-poll",
        else => null,
    };
}

/// 已知但未实现的选项（识别后 warning + 忽略）
fn isKnownUnimplemented(nm: []const u8) bool {
    for (known_unimplemented) |k| if (std.mem.eql(u8, nm, k)) return true;
    return false;
}

/// 用 POSIX 读取整个文件（绕过 0.16 需要 Io 的 std.fs API）
fn readFileAlloc(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    const fd: std.posix.fd_t = try std.posix.openat(std.posix.AT.FDCWD, path, std.posix.O{ .ACCMODE = .RDONLY }, 0);
    defer _ = std.posix.system.close(fd);
    var buf: std.ArrayList(u8) = .empty;
    var tmp: [8192]u8 = undefined;
    while (true) {
        const n = try std.posix.read(fd, &tmp);
        if (n == 0) break;
        try buf.appendSlice(alloc, tmp[0..n]);
    }
    return buf.toOwnedSlice(alloc);
}

/// 解析命令行（args 不含 argv[0]），返回是否成功
/// 对应 option.c: read_opts() 的 argv 遍历部分
pub fn parseArgs(d: *daemon.Daemon, args: []const []const u8) !void {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (a.len == 0) continue;
        if (a.len >= 2 and a[0] == '-' and a[1] == '-') {
            // 长选项：--name=value 或 --name value
            var nm = a[2..];
            var val: ?[]const u8 = null;
            if (std.mem.indexOfScalar(u8, nm, '=')) |pos| {
                val = nm[pos + 1 ..];
                nm = nm[0..pos];
            } else if (longTakesValue(nm) and i + 1 < args.len and args[i + 1][0] != '-') {
                val = args[i + 1];
                i += 1;
            }
            try parseOption(d, nm, val);
        } else if (a.len >= 2 and a[0] == '-') {
            // 短选项：-p53 或 -p 53
            const short = a[1];
            var val: ?[]const u8 = null;
            if (a.len > 2) {
                val = a[2..];
            } else if (shortTakesValue(short) and i + 1 < args.len and args[i + 1][0] != '-') {
                val = args[i + 1];
                i += 1;
            }
            const ln = longNameForShort(short) orelse {
                log.err("未知短选项: -{c}", .{short});
                return error.UnknownOption;
            };
            try parseOption(d, ln, val);
        } else {
            log.warning("忽略非选项参数: {s}", .{a});
        }
    }
}

/// 解析单条选项：name 不含前导 --，val 为 = 后面的值（可能为 null）
/// 对应 option.c: one_opt()
/// 解析 --balance=<mode> 的策略名。
/// 同时接受几个业界常用别名，方便从其它负载均衡器迁移配置。
fn parseBalanceMode(v: []const u8) ?daemon.BalanceMode {
    if (std.mem.eql(u8, v, "sticky")) return .sticky;
    if (std.mem.eql(u8, v, "dynamic")) return .dynamic;
    if (std.mem.eql(u8, v, "wlc") or std.mem.eql(u8, v, "least-outstanding")) return .dynamic;
    if (std.mem.eql(u8, v, "swrr")) return .swrr;
    if (std.mem.eql(u8, v, "round-robin") or std.mem.eql(u8, v, "rr")) return .round_robin;
    if (std.mem.eql(u8, v, "random")) return .random;
    return null;
}

pub fn parseOption(d: *daemon.Daemon, nm: []const u8, val: ?[]const u8) anyerror!void {
    if (std.mem.eql(u8, nm, "port")) {
        if (parseIntU(u16, d, val, "--port")) |v| d.port = v;
    } else if (std.mem.eql(u8, nm, "cache-size")) {
        if (parseIntU(i32, d, val, "--cache-size")) |v| d.cachesize = v;
    } else if (std.mem.eql(u8, nm, "domain")) {
        if (val) |v| d.domain = try d.allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, nm, "expand-hosts") or std.mem.eql(u8, nm, "E")) {
        d.expand_hosts = true;
        d.setOpt(protocol.OPT_EXPAND);
    } else if (std.mem.eql(u8, nm, "log-queries")) {
        d.setOpt(protocol.OPT_LOG);
    } else if (std.mem.eql(u8, nm, "log-facility")) {
        // 对应 C option.c:2279 的 '8' 分支：值里含 '/' 或等于 "-" 当文件名，
        // 否则当 syslog facility 名（daemon/local0…）；都不匹配则报错退出。
        if (val) |v| {
            switch (log.classifyLogFacility(v) orelse {
                log.err("无效的日志设施（--log-facility={s}）：既不是文件路径，也不是已知的 syslog facility 名", .{v});
                return error.BadOption;
            }) {
                .file => d.log_file = try d.allocator.dupe(u8, v),
                .syslog => |fac| d.log_facility = fac,
            }
        }
    } else if (std.mem.eql(u8, nm, "pid-file")) {
        if (val) |v| d.pid_file = try d.allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, nm, "user")) {
        if (val) |v| d.user = try d.allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, nm, "group")) {
        if (val) |v| d.group = try d.allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, nm, "resolv-file")) {
        if (val) |v| try d.resolv_files.append(d.allocator, try d.allocator.dupe(u8, v));
    } else if (std.mem.eql(u8, nm, "addn-hosts")) {
        if (val) |v| try d.addn_hosts.append(d.allocator, try d.allocator.dupe(u8, v));
    } else if (std.mem.eql(u8, nm, "hostsdir")) {
        // 对应 C option.c:262 的 LOPT_HOST_INOTIFY：目录，读里面每个普通文件。
        // odhcpd 把 odhcpd.hosts.<ifname> 写在 /tmp/hosts 下。
        if (val) |v| try d.hosts_dirs.append(d.allocator, try d.allocator.dupe(u8, v));
    } else if (std.mem.eql(u8, nm, "no-hosts")) {
        // --no-hosts：对应 C 的 reset_option_bool(OPT_NO_HOSTS)
        d.setOpt(protocol.OPT_NO_HOSTS);
    } else if (std.mem.eql(u8, nm, "no-resolv")) {
        d.setOpt(protocol.OPT_NO_RESOLV);
    } else if (std.mem.eql(u8, nm, "no-poll")) {
        d.setOpt(protocol.OPT_NO_POLL);
    } else if (std.mem.eql(u8, nm, "bogus-priv")) {
        d.setOpt(protocol.OPT_BOGUSPRIV);
    } else if (std.mem.eql(u8, nm, "strict-order")) {
        d.setOpt(protocol.OPT_ORDER);
    } else if (std.mem.eql(u8, nm, "no-daemon") or std.mem.eql(u8, nm, "keep-in-foreground")) {
        // 仅设置 OPT_NO_FORK：本移植始终前台运行（不 fork、不 daemonize）
        d.setOpt(protocol.OPT_NO_FORK);
        log.debug("前台运行（不 daemonize）", .{});
    } else if (std.mem.eql(u8, nm, "local-service")) {
        // option.c: set_option_bool(OPT_LOCAL_SERVICE)
        d.setOpt(protocol.OPT_LOCAL_SERVICE);
    } else if (std.mem.eql(u8, nm, "localise-queries")) {
        d.setOpt(protocol.OPT_LOCALISE);
    } else if (std.mem.eql(u8, nm, "domain-needed")) {
        // option.c: 'D' -> OPT_NODOTS_LOCAL，对应 forward.c:357 的「不转发无点名字」
        d.setOpt(protocol.OPT_NODOTS_LOCAL);
    } else if (std.mem.eql(u8, nm, "filterwin2k")) {
        // option.c: 'f' -> OPT_FILTER
        d.setOpt(protocol.OPT_FILTER);
    } else if (std.mem.eql(u8, nm, "all-servers")) {
        // LOPT_NOLAST -> OPT_ALL_SERVERS：每次查询都并发发给组内全部上游
        d.setOpt(protocol.OPT_ALL_SERVERS);
    } else if (std.mem.eql(u8, nm, "balance") or std.mem.eql(u8, nm, "server-balance")) {
        // 本移植扩展：--balance=<sticky|dynamic|swrr|round-robin|random>
        const v = val orelse {
            log.warning("--{s} 需要一个策略名", .{nm});
            return;
        };
        d.balance_mode = parseBalanceMode(v) orelse {
            log.warning("未知的均衡策略: {s}（可用: sticky/dynamic/swrr/round-robin/random）", .{v});
            return;
        };
        log.debug("上游调度策略: {s}", .{@tagName(d.balance_mode)});
    } else if (std.mem.eql(u8, nm, "concurrent-servers")) {
        // 本移植扩展：--concurrent-servers=<n>，0 表示不限制（跟随候选数）
        const v = val orelse {
            log.warning("--concurrent-servers 需要参数", .{});
            return;
        };
        const n = std.fmt.parseInt(usize, v, 10) catch {
            log.warning("--concurrent-servers 参数非法: {s}", .{v});
            return;
        };
        if (n > protocol.MAX_CONCURRENT_OPT) {
            log.warning("--concurrent-servers 超过上限 {d}，已截断", .{protocol.MAX_CONCURRENT_OPT});
        }
        d.concurrent_servers = @min(n, protocol.MAX_CONCURRENT_OPT);
        // 并发 > 1 本身就意味着要「全发」语义，否则单发时这个选项毫无作用
        if (d.concurrent_servers > 1) d.setOpt(protocol.OPT_ALL_SERVERS);
    } else if (std.mem.eql(u8, nm, "sync-forward")) {
        // 本移植扩展：退回同步阻塞转发（用于 A/B 对比与引擎不可用时的兜底）
        d.sync_forward = true;
    } else if (std.mem.eql(u8, nm, "hedge-after")) {
        // 本移植扩展：--hedge-after=<ms> 阶梯式补发（对冲长尾延迟）
        const v = val orelse {
            log.warning("--hedge-after 需要参数（毫秒）", .{});
            return;
        };
        const n = std.fmt.parseInt(i32, v, 10) catch {
            log.warning("--hedge-after 参数非法: {s}", .{v});
            return;
        };
        d.hedge_ms = std.math.clamp(n, 0, protocol.MAX_HEDGE_MS);
        if (d.hedge_ms > 0) d.setOpt(protocol.OPT_ALL_SERVERS);
    } else if (std.mem.eql(u8, nm, "server-cooldown")) {
        // 本移植扩展：连续失败后的熔断基准冷却时长（毫秒）
        const v = val orelse {
            log.warning("--server-cooldown 需要参数（毫秒）", .{});
            return;
        };
        const n = std.fmt.parseInt(i64, v, 10) catch {
            log.warning("--server-cooldown 参数非法: {s}", .{v});
            return;
        };
        d.server_cooldown_ms = std.math.clamp(n, 0, protocol.SERVER_COOLDOWN_OPT_MAX_MS);
    } else if (std.mem.eql(u8, nm, "fast-dns-retry")) {
        // 对应 option.c: LOPT_FAST_RETRY —— 无参数时用 DEFAULT_FAST_RETRY(1000ms)，
        // 有参数时要求 >= 50（对齐 C 版 retry < 50 的检查）。
        // 本移植默认就是 1000ms；显式传 0 可退回 dnsmasq 原生语义
        // （第一台上游吃满整个 TIMEOUT，期间不换台）。
        const v = val orelse {
            d.fast_retry_ms = protocol.DEFAULT_FAST_RETRY_MS;
            return;
        };
        const n = std.fmt.parseInt(i32, v, 10) catch {
            log.warning("--fast-dns-retry 参数非法: {s}", .{v});
            return;
        };
        if (n == 0) {
            d.fast_retry_ms = 0;
        } else {
            if (n < protocol.MIN_FAST_RETRY_MS) {
                log.warning("--fast-dns-retry 的最小值是 {d}ms，已按最小值处理", .{protocol.MIN_FAST_RETRY_MS});
            }
            d.fast_retry_ms = std.math.clamp(n, protocol.MIN_FAST_RETRY_MS, protocol.MAX_FAST_RETRY_MS);
        }
    } else if (std.mem.eql(u8, nm, "no-negcache")) {
        d.setOpt(protocol.OPT_NO_NEG);
    } else if (std.mem.eql(u8, nm, "no-round-robin")) {
        d.setOpt(protocol.OPT_NORR);
    } else if (std.mem.eql(u8, nm, "stop-dns-rebind")) {
        d.setOpt(protocol.OPT_NO_REBIND);
    } else if (std.mem.eql(u8, nm, "rebind-localhost-ok")) {
        d.setOpt(protocol.OPT_LOCAL_REBIND);
    } else if (std.mem.eql(u8, nm, "rebind-domain-ok")) {
        // 对应 C option.c:3037 `case LOPT_NO_REBIND`（ARG_DUP，形如 /dom1/dom2/）。
        // 允许省略首尾斜杠；按 '/' 切分后逐域加入豁免列表。
        // 差异：C 对 `//` 这种写法会插入一个「空域」（其语义是匹配任何单标签名），
        // 实际无人这么配，本移植直接跳过空段。
        if (val) |v| {
            var it = std.mem.splitScalar(u8, v, '/');
            while (it.next()) |part| {
                if (part.len == 0) continue;
                try d.no_rebind.append(d.allocator, try d.allocator.dupe(u8, part));
            }
        }
    } else if (std.mem.eql(u8, nm, "alias")) {
        // 对应 C option.c:4874 `case 'V'`（--alias）：把上游 A 记录按掩码改写
        if (val) |v| applyAlias(d, v);
    } else if (std.mem.eql(u8, nm, "bind-interfaces") or std.mem.eql(u8, nm, "bind-dynamic")) {
        d.setOpt(protocol.OPT_CLEVERBIND);
    } else if (std.mem.eql(u8, nm, "log-async")) {
        // 本移植的日志本身就是「一行一次 write」，无需异步队列
        log.debug("--log-async 已内置（本移植日志同步写整行），忽略参数", .{});
    } else if (std.mem.eql(u8, nm, "dnssec") or std.mem.eql(u8, nm, "dnssec-check-unsigned")) {
        log.warning("--{s} 在本移植中暂未实现，已忽略", .{nm});
    } else if (std.mem.eql(u8, nm, "interface")) {
        if (val) |v| try d.interfaces.append(d.allocator, try d.allocator.dupe(u8, v));
    } else if (std.mem.eql(u8, nm, "except-interface")) {
        if (val) |v| try d.except_interfaces.append(d.allocator, try d.allocator.dupe(u8, v));
    } else if (std.mem.eql(u8, nm, "listen-address")) {
        if (val) |v| {
            var ip4: u32 = 0;
            var ip6: [16]u8 = undefined;
            if (addr.parseIp4(v, &ip4)) {
                try d.listen_addrs.append(d.allocator, addr.SockAddr.fromIp4(ip4, d.port));
            } else if (addr.parseIp6(v, &ip6)) {
                try d.listen_addrs.append(d.allocator, addr.SockAddr.fromIp6(ip6, d.port, 0));
            } else {
                log.warning("无法解析监听地址: {s}", .{v});
            }
        }
    } else if (std.mem.eql(u8, nm, "local-ttl")) {
        if (parseIntU(u32, d, val, "--local-ttl")) |v| d.local_ttl = v;
    } else if (std.mem.eql(u8, nm, "neg-ttl")) {
        if (parseIntU(u32, d, val, "--neg-ttl")) |v| d.neg_ttl = v;
    } else if (std.mem.eql(u8, nm, "max-ttl")) {
        if (parseIntU(u32, d, val, "--max-ttl")) |v| d.max_ttl = v;
    } else if (std.mem.eql(u8, nm, "max-cache-ttl")) {
        if (parseIntU(u32, d, val, "--max-cache-ttl")) |v| {
            d.max_cache_ttl = v;
            d.use_max_cache_ttl = true;
        }
    } else if (std.mem.eql(u8, nm, "min-cache-ttl")) {
        if (parseIntU(u32, d, val, "--min-cache-ttl")) |v| d.min_cache_ttl = v;
    } else if (std.mem.eql(u8, nm, "use-stale-cache")) {
        // 0 = 禁用（默认）；正数 = 过期后该秒数内仍可服务（crec_ttl 返回 0，
        // 让客户端主动重发）。对应 C 的 daemon->cache_max_expiry。
        const v: u32 = if (val) |s| blk: {
            const n = parseIntU(u32, d, s, "--use-stale-cache") orelse 0;
            break :blk n;
        } else 86400; // 无参数：与 C 一致，默认 1 天
        d.stale_cache_ttl = v;
    } else if (std.mem.eql(u8, nm, "edns-packet-max")) {
        if (parseIntU(u16, d, val, "--edns-packet-max")) |v| d.edns_pktsz = v;
    } else if (std.mem.eql(u8, nm, "dns-forward-max")) {
        if (parseIntU(u32, d, val, "--dns-forward-max")) |v| d.dns_forward_max = v;
    } else if (std.mem.eql(u8, nm, "threads")) {
        // 本移植新增：1..64，0 表示按 CPU 数
        if (parseIntU(u32, d, val, "--threads")) |v| {
            if (v == 0 or (v >= 1 and v <= 64)) {
                d.threads = v;
            } else {
                log.warning("--threads 取值应介于 1..64（0=按 CPU），已忽略: {d}", .{v});
            }
        }
    } else if (std.mem.eql(u8, nm, "conf-file") or std.mem.eql(u8, nm, "C")) {
        if (val) |v| {
            // 记下用户显式指定的配置文件。main 里据此决定还要不要读默认的
            // /etc/dnsmasq.conf —— C 版语义是「给了 -C 就只读这一个文件」。
            // 少了这一步会在带 /etc/dnsmasq.conf 的系统上多读一份无关配置，
            // 而 OpenWrt/ImmortalWrt 上那个文件是 UCI 格式，会直接报
            // UnknownOption（实机部署时踩到）。
            if (d.conf_file) |old| d.allocator.free(old);
            d.conf_file = d.allocator.dupe(u8, v) catch null;
            try readConfFile(d, v);
        }
    } else if (std.mem.eql(u8, nm, "conf-dir") or std.mem.eql(u8, nm, "7")) {
        if (val) |v| try readConfDir(d, v);
    } else if (std.mem.eql(u8, nm, "server")) {
        try applyServerLocal(d, val, false, false);
    } else if (std.mem.eql(u8, nm, "local")) {
        // --local=/dom/ 等价于 --server=/dom/#（该域不转发=本地）
        try applyServerLocal(d, val, false, true);
    } else if (std.mem.eql(u8, nm, "address")) {
        try applyAddress(d, val);
    } else if (isKnownUnimplemented(nm)) {
        log.warning("选项 --{s} 在本移植中未实现，已忽略", .{nm});
    } else {
        // 名字可能含非 UTF-8 字节，打印十六进制便于排查
        var dbg: [192]u8 = undefined;
        var dn: usize = 0;
        for (nm) |c| {
            const w = std.fmt.bufPrint(dbg[dn..], "{x:0>2} ", .{c}) catch break;
            dn += w.len;
        }
        log.err("未知选项 len={d} bytes={s}", .{ nm.len, dbg[0..dn] });
        return error.UnknownOption;
    }
}

/// 解析“域名规格”字符串，拆出域名段（不含最后一个）与地址段（最后一个）
/// 对应 option.c: one_opt() 里 server/local/address 的 /domain/ip 拆分
fn splitServerSpec(alloc: std.mem.Allocator, spec: []const u8) !struct {
    domains: std.ArrayList([]const u8),
    addr: []const u8,
    had_slash: bool,
} {
    var domains: std.ArrayList([]const u8) = .empty;
    var addr_str: []const u8 = "";
    var had_slash = false;
    if (spec.len > 0 and spec[0] == '/') {
        had_slash = true;
        const rest = spec[1..];
        var it = std.mem.splitScalar(u8, rest, '/');
        var segs: std.ArrayList([]const u8) = .empty;
        defer segs.deinit(alloc);
        while (it.next()) |s| try segs.append(alloc, s);
        if (segs.items.len == 0) {
            addr_str = "";
        } else {
            addr_str = segs.items[segs.items.len - 1];
            for (segs.items[0 .. segs.items.len - 1]) |s| try domains.append(alloc, s);
        }
    } else {
        addr_str = spec;
    }
    return .{ .domains = domains, .addr = addr_str, .had_slash = had_slash };
}

/// 处理 --server / --local（local 强制为字面地址=本地域）
/// 对应 option.c: one_opt() 的 case 'S' / LOPT_LOCAL
fn applyServerLocal(
    d: *daemon.Daemon,
    val: ?[]const u8,
    from_file: bool,
    force_local: bool,
) !void {
    const spec = val orelse {
        log.warning("--server/--local 缺少参数", .{});
        return;
    };
    var parsed = try splitServerSpec(d.allocator, spec);
    defer parsed.domains.deinit(d.allocator);

    const is_literal = force_local or parsed.addr.len == 0 or std.mem.eql(u8, parsed.addr, "#");

    // 对应 option.c: 地址可以带 `#port` 后缀（例如 server=/dom/1.2.3.4#5353）。
    // 单独的 "#" 已经在上面的 is_literal 里处理掉了。
    var addr_text = parsed.addr;
    var port_num: u16 = protocol.NAMESERVER_PORT;
    if (!is_literal) {
        if (std.mem.lastIndexOfScalar(u8, parsed.addr, '#')) |hi| {
            const tail = parsed.addr[hi + 1 ..];
            if (tail.len != 0) {
                port_num = std.fmt.parseInt(u16, tail, 10) catch {
                    log.warning("上游服务器端口无法解析: {s}", .{parsed.addr});
                    return;
                };
                addr_text = parsed.addr[0..hi];
            }
        }
    }

    var addr_opt: ?addr.SockAddr = null;
    if (!is_literal) {
        var ip4: u32 = 0;
        var ip6: [16]u8 = undefined;
        if (addr.parseIp4(addr_text, &ip4)) {
            addr_opt = addr.SockAddr.fromIp4(ip4, port_num);
        } else if (addr.parseIp6(addr_text, &ip6)) {
            addr_opt = addr.SockAddr.fromIp6(ip6, port_num, 0);
        } else {
            log.warning("无法解析上游服务器地址: {s}", .{addr_text});
            return;
        }
    }

    if (parsed.domains.items.len == 0) {
        // 默认上游（无域名）：domain = null
        var flags: u16 = 0;
        if (from_file) flags |= protocol.SERV_FROM_FILE;
        if (is_literal) flags |= protocol.SERV_LITERAL_ADDRESS;
        try domain.addUpdateServer(d, flags, addr_opt, null, null, null, null);
    } else {
        for (parsed.domains.items) |seg| {
            var flags: u16 = 0;
            if (from_file) flags |= protocol.SERV_FROM_FILE;
            if (is_literal) flags |= protocol.SERV_LITERAL_ADDRESS;
            // "//ip" 形式（空域名段）表示无点域名；"#" 同样视作空域
            const empty = seg.len == 0 or std.mem.eql(u8, seg, "#");
            if (parsed.had_slash and empty) flags |= protocol.SERV_FOR_NODOTS;
            const dom: ?[]const u8 = if (empty) null else seg;
            try domain.addUpdateServer(d, flags, addr_opt, null, null, dom, null);
        }
    }
}

/// 处理 --address=/dom/ip，追加到 d.address_list
/// 对应 option.c: one_opt() 的 case 'A'（本移植改为落 address_list）
/// 对应 C option.c:4874 `case 'V'`（`--alias`）的解析：
///     `--alias=[<旧IP>|<起IP>-<止IP>],<新IP>[,<掩码>]`
/// 至少两段（旧、新）；第三段为可选掩码（默认 /32）；第一段带 `-` 表示区间。
/// 与 C 一致：区间必须与掩码同网段且 起 <= 止，否则整条丢弃并告警。
fn applyAlias(d: *daemon.Daemon, v: []const u8) void {
    var it = std.mem.splitScalar(u8, v, ',');
    const f0 = it.next() orelse "";
    const f1 = it.next() orelse {
        log.warning("--alias 缺少「新地址」参数（应为 [旧IP|起-止],新IP[,掩码]）: {s}", .{v});
        return;
    };
    const f2 = it.next();

    var start_s: []const u8 = f0;
    var end_s: ?[]const u8 = null;
    if (std.mem.indexOfScalar(u8, f0, '-')) |di| {
        start_s = f0[0..di];
        end_s = f0[di + 1 ..];
    }

    var in_net: u32 = 0;
    var out_net: u32 = 0;
    var mask_net: u32 = 0xffffffff;
    if (!addr.parseIp4(start_s, &in_net)) {
        log.warning("--alias 旧地址非法: {s}", .{v});
        return;
    }
    if (!addr.parseIp4(f1, &out_net)) {
        log.warning("--alias 新地址非法: {s}", .{v});
        return;
    }
    if (f2) |m| {
        if (!addr.parseIp4(m, &mask_net)) {
            log.warning("--alias 掩码非法: {s}", .{v});
            return;
        }
    }

    var end_net: u32 = 0;
    if (end_s) |es| {
        if (!addr.parseIp4(es, &end_net)) {
            log.warning("--alias 区间终点非法: {s}", .{v});
            return;
        }
        // is_same_net(in, end, mask) 且 in <= end（主机序比较，与 C 相同）
        if ((in_net & mask_net) != (end_net & mask_net) or
            @byteSwap(in_net) > @byteSwap(end_net))
        {
            log.warning("--alias 区间与掩码不匹配或起止颠倒: {s}", .{v});
            return;
        }
    }

    d.doctors.append(d.allocator, .{
        .in = in_net,
        .end = end_net,
        .out = out_net,
        .mask = mask_net,
    }) catch log.warning("--alias 内存不足，已忽略: {s}", .{v});
}

fn applyAddress(d: *daemon.Daemon, val: ?[]const u8) !void {
    const spec = val orelse {
        log.warning("--address 缺少参数", .{});
        return;
    };
    var parsed = try splitServerSpec(d.allocator, spec);
    defer parsed.domains.deinit(d.allocator);

    var ip4: ?u32 = null;
    var ip6: ?[16]u8 = null;
    if (parsed.addr.len > 0 and !std.mem.eql(u8, parsed.addr, "#")) {
        var v4: u32 = 0;
        var v6: [16]u8 = undefined;
        if (addr.parseIp4(parsed.addr, &v4)) {
            ip4 = v4;
        } else if (addr.parseIp6(parsed.addr, &v6)) {
            ip6 = v6;
        } else {
            log.warning("无法解析 --address 地址: {s}", .{parsed.addr});
            return;
        }
    } else {
        // "#" 表示返回零地址（IPv4 / IPv6 都置 0）
        ip4 = 0;
        ip6 = [_]u8{0} ** 16;
    }

    if (parsed.domains.items.len == 0) {
        log.warning("--address 缺少域名", .{});
        return;
    }

    for (parsed.domains.items) |seg| {
        const is_wild = std.mem.eql(u8, seg, "#") or (seg.len > 0 and seg[0] == '*');
        const is_empty = seg.len == 0 or std.mem.eql(u8, seg, "#");
        const domain_str: ?[]u8 = if (is_empty) null else name.canonicalise(d.allocator, seg);
        if (!is_empty and domain_str == null) {
            log.warning("非法域名: {s}", .{seg});
            continue;
        }
        const rule: daemon.AddressRule = .{
            .domain = if (domain_str) |ds| ds else "",
            .wildcard = is_wild,
            .addr4 = ip4,
            .addr6 = ip6,
            .local = false,
        };
        try d.address_list.append(d.allocator, rule);
    }
}

/// 解析配置文件：每行一条选项（可带 = 值），支持 # 注释、续行（行尾 \ ）、
/// 对应 option.c 顶部注释里的 `meta[]` 表：引号内的元字符映射到 ASCII 控制字符区
/// （0..31），这样后续的「空白归一 / # 注释 / 前后空格裁剪」都不会误伤它们。
const meta_table = "\x00123456 \x08\x09\x0a78\x0d90abcdefABCDE\x1bF:,.";

fn hideMeta(c: u8) u8 {
    for (meta_table, 0..) |m, i| {
        if (c == m) return @intCast(i);
    }
    return c;
}

fn unhideMeta(c: u8) u8 {
    if (c < meta_table.len) return meta_table[c];
    return c;
}

fn unhideMetas(s: []u8) void {
    for (s) |*c| c.* = unhideMeta(c.*);
}

/// 对应 option.c: read_file() 的行内预处理：
///   1. 引号内的 ``\t``/``\n``/``\b``/``\r``/``\e``/``\\``/``\"`` 转义，其余字符原样保留
///      （其中的元字符会被 hide_meta 藏起来，避免被当成空白或注释）
///   2. 所有空白归一为单个空格
///   3. 前置空白的 '#' 起注释作用，其后的内容整行丢弃
///   4. 裁掉首尾空格
///
/// 返回处理后的切片（就地压缩在 buf 内），空行/纯注释行返回 null。
/// 注意：dnsmasq **不支持**行尾 `\` 续行，这里保持一致。
fn normalizeConfLine(buf: []u8) ?[]u8 {
    var n: usize = 0;
    var i: usize = 0;
    var white = true;

    while (i < buf.len) {
        const c = buf[i];

        if (c == '"') {
            i += 1;
            var closed = false;
            while (i < buf.len) : (i += 1) {
                var ch = buf[i];
                if (ch == '"') {
                    closed = true;
                    i += 1;
                    break;
                }
                if (ch == '\\' and i + 1 < buf.len and std.mem.indexOfScalar(u8, "\"tnebr\\", buf[i + 1]) != null) {
                    i += 1;
                    ch = switch (buf[i]) {
                        't' => '\t',
                        'n' => '\n',
                        'b' => 0x08,
                        'r' => '\r',
                        'e' => 0x1b,
                        else => buf[i], // \ 与 "
                    };
                }
                // 引号内字符被「藏起来」：不受后面的空白归一与 # 注释影响
                buf[n] = hideMeta(ch);
                n += 1;
            }
            if (!closed) return null; // 缺少收尾引号，丢弃该行
            continue;
        }

        if (std.ascii.isWhitespace(c)) {
            buf[n] = ' ';
            n += 1;
            i += 1;
            white = true;
            continue;
        }

        if (white and c == '#') break; // 注释开始，忽略其后内容
        buf[n] = c;
        n += 1;
        i += 1;
        white = false;
    }

    // 裁掉首尾空格（被 hide 的空白是控制字符，不会被裁掉，与 C 版一致）
    var s0: usize = 0;
    while (s0 < n and buf[s0] == ' ') s0 += 1;
    var e0: usize = n;
    while (e0 > s0 and buf[e0 - 1] == ' ') e0 -= 1;
    if (e0 == s0) return null;
    return buf[s0..e0];
}

/// 读取并解析配置文件。对应 option.c: read_file() + one_file()。
///
/// 支持的语法：
///   - 每行一条 `name` 或 `name=value`（值中可含空格，无需引号）
///   - `#` 注释：位于行首，或前面有空白
///   - 值可用双引号包裹，引号内支持 `\t \n \b \r \e \\ \"` 转义，
///     且引号内的空格与 `#` 会被保留
pub fn readConfFile(d: *daemon.Daemon, path: []const u8) !void {
    const data = readFileAlloc(d.allocator, path) catch |e| {
        log.err("无法读取配置文件 {s}: {s}", .{ path, @errorName(e) });
        return;
    };
    defer d.allocator.free(data);

    var lineno: usize = 0;
    var lines = std.mem.splitScalar(u8, data, '\n');
    while (lines.next()) |raw| {
        lineno += 1;
        if (raw.len == 0) continue;

        // 复制一份用于就地改写（含 \r 之类都由 normalize 处理）
        const tmp = d.allocator.dupe(u8, raw) catch return;
        defer d.allocator.free(tmp);

        const line = normalizeConfLine(tmp) orelse continue;
        parseConfLine(d, line) catch |e| {
            log.err("配置文件 {s} 第 {d} 行解析失败: {s}", .{ path, lineno, @errorName(e) });
            return e;
        };
    }
}

/// 解析配置文件中的单行（已完成引号/注释预处理）。
/// 对应 option.c: read_file() 里 `strchr(start, '=')` 那段拆分逻辑：
/// 只按第一个 '=' 拆分（不按空白），name 右侧的空白与 '=' 全部裁掉，
/// value 左侧空白裁掉。没有 '=' 时 arg 为 NULL。
fn parseConfLine(d: *daemon.Daemon, line: []u8) !void {
    var opt_name: []u8 = line;
    var val: ?[]u8 = null;

    if (std.mem.indexOfScalar(u8, line, '=')) |eq| {
        var p: usize = eq;
        // 允许 '=' 两侧有空格：把 name 右侧的 ' ' 和 '=' 一起裁掉
        while (p > 0 and (line[p - 1] == ' ' or line[p - 1] == '=')) p -= 1;
        opt_name = line[0..p];
        var a: usize = eq + 1;
        while (a < line.len and line[a] == ' ') a += 1;
        val = if (a < line.len) line[a..] else null;
    }

    if (opt_name.len == 0) return;

    // 还原引号内被隐藏的元字符（对应 C 的 unhide_metas）
    unhideMetas(opt_name);
    if (val) |v| unhideMetas(v);

    try parseOption(d, opt_name, val);
}

/// 读取 conf-dir：按字典序读取目录下所有 *.conf
/// 对应 option.c: read_opts() 对 conf-dir 的处理
pub fn readConfDir(d: *daemon.Daemon, dir_path: []const u8) !void {
    const fd: std.posix.fd_t = try std.posix.openat(
        std.posix.AT.FDCWD,
        dir_path,
        std.posix.O{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        0,
    );
    defer _ = std.posix.system.close(fd);

    var names: std.ArrayList([]u8) = .empty;
    defer {
        for (names.items) |n| d.allocator.free(n);
        names.deinit(d.allocator);
    }

    var buf: [65536]u8 = undefined;
    while (true) {
        const n = std.os.linux.getdents64(@intCast(fd), &buf, buf.len);
        if (n == 0) break;
        var off: usize = 0;
        while (off + 19 <= n) {
            const reclen = std.mem.readInt(u16, buf[off + 16 ..][0..2], .little);
            if (reclen == 0) break;
            const name_start = off + 19;
            var name_end = name_start;
            while (name_end < n and buf[name_end] != 0) name_end += 1;
            const fname = buf[name_start..name_end];
            // 仅选取 *.conf，跳过 . 与 ..
            if (!std.mem.eql(u8, fname, ".") and !std.mem.eql(u8, fname, "..") and
                std.mem.endsWith(u8, fname, ".conf"))
            {
                try names.append(d.allocator, try d.allocator.dupe(u8, fname));
            }
            off += reclen;
        }
    }

    std.mem.sort([]u8, names.items, {}, struct {
        fn lessThan(_: void, a: []u8, b: []u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);

    for (names.items) |fname| {
        const full = try std.fmt.allocPrint(d.allocator, "{s}/{s}", .{ dir_path, fname });
        defer d.allocator.free(full);
        try readConfFile(d, full);
    }
}

/// 生成 --help 文本（对应 dnsmasq 的 --help 输出，精简版）
pub fn usageText(allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        \\用法: dnsmasq [选项]
        \\
        \\通用选项:
        \\  -p, --port=<n>            监听端口（默认 53）
        \\  -c, --cache-size=<n>      缓存条目数
        \\  -C, --conf-file=<file>    指定配置文件
        \\  -7, --conf-dir=<dir>      读取目录下所有 *.conf
        \\  -H, --addn-hosts=<file>   额外 hosts 文件
        \\  -r, --resolv-file=<file>  resolv.conf 路径
        \\  -u, --user=<user>         运行用户
        \\  -g, --group=<group>       运行组
        \\  -x, --pid-file=<file>     PID 文件路径
        \\  -8, --log-facility=<file> 日志文件
        \\
        \\查询/转发:
        \\  -s, --domain=<name>       本地域名
        \\  -E, --expand-hosts        扩展 hosts 名字
        \\  --server=/domain/ip       指定上游服务器（可按域名/无点域/通配）
        \\  --server=ip               默认上游服务器
        \\  --local=/domain/          该域不转发（本地）
        \\  --address=/domain/ip      返回固定地址（含 IPv4/IPv6）
        \\  --interface=<iface>       仅在该接口监听
        \\  --listen-address=<ip>     仅监听该地址
        \\  --no-resolv              不读取 resolv.conf
        \\  --no-poll                不轮询 resolv.conf 变化
        \\  --no-hosts               不读取 /etc/hosts
        \\  -b, --bogus-priv         伪造 RFC1918 反向查询
        \\
        \\多上游调度（本移植扩展）:
        \\  -o, --strict-order        只按配置顺序使用上游（dnsmasq 原生）
        \\  --all-servers             每次查询并发发给全部上游，取最快（dnsmasq 原生）
        \\  --balance=<mode>          均衡策略: sticky(默认)/dynamic/swrr/round-robin/random
        \\  --concurrent-servers=<n>  最多并发 n 台上游（0=不限）
        \\  --hedge-after=<ms>        超过 ms 毫秒未应答再补发下一台（对冲长尾）
        \\  --server-cooldown=<ms>    上游连续失败后的熔断冷却基数
        \\  --fast-dns-retry[=<ms>]   单台上游的等待时间（默认 1000ms，0=退回原生语义）
        \\  --sync-forward            关闭异步转发引擎，退回同步阻塞转发（A/B 对比用）
        \\
        \\TTL/缓存:
        \\  --local-ttl=<n>          本地应答 TTL
        \\  --neg-ttl=<n>            否定应答 TTL
        \\  --max-ttl=<n>            最大 TTL
        \\  --max-cache-ttl=<n>      最大缓存 TTL
        \\  --min-cache-ttl=<n>      最小缓存 TTL
        \\  --use-stale-cache[=<n>]  过期后陈旧记录最多服务 n 秒（默认 86400）
        \\  --edns-packet-max=<n>    EDNS0 报文上限
        \\  --dns-forward-max=<n>    最大并发转发
        \\  --threads=<n>            查询线程数（1..64，0=按 CPU）
        \\
        \\日志/其它:
        \\  -q, --log-queries        记录查询
        \\  -d, --no-daemon          前台运行
        \\  -k, --keep-in-foreground 保持前台
        \\  --local-service          仅接受直连网络查询
        \\
    , .{});
}

// ===========================================================================
// 测试
// ===========================================================================
const testing = std.testing;

test "port 长短选项" {
    {
        var d = daemon.Daemon{ .allocator = testing.allocator };
        defer d.deinit();
        try parseArgs(&d, &.{ "--port=5353" });
        try testing.expectEqual(@as(u16, 5353), d.port);
    }
    {
        var d = daemon.Daemon{ .allocator = testing.allocator };
        defer d.deinit();
        try parseArgs(&d, &.{ "-p", "5354" });
        try testing.expectEqual(@as(u16, 5354), d.port);
    }
    {
        var d = daemon.Daemon{ .allocator = testing.allocator };
        defer d.deinit();
        try parseArgs(&d, &.{ "-p53" });
        try testing.expectEqual(@as(u16, 53), d.port);
    }
}

test "server 带域名生成 Server" {
    var d = daemon.Daemon{ .allocator = testing.allocator };
    defer d.deinit();
    try parseOption(&d, "server", "/example.com/1.2.3.4");
    try testing.expectEqual(@as(usize, 1), d.servers.items.len);
    const s = d.servers.items[0];
    try testing.expectEqualStrings("example.com", s.domain.?);

    var want: u32 = 0;
    _ = addr.parseIp4("1.2.3.4", &want);
    try testing.expectEqual(want, s.addr.toAllAddr().ip4);
    try testing.expectEqual(@as(u16, 53), s.addr.port());
    try testing.expect(!s.isLocal());
}

test "local 生成本地域" {
    var d = daemon.Daemon{ .allocator = testing.allocator };
    defer d.deinit();
    try parseOption(&d, "local", "/internal/");
    try testing.expectEqual(@as(usize, 1), d.servers.items.len);
    const s = d.servers.items[0];
    try testing.expectEqualStrings("internal", s.domain.?);
    try testing.expect(s.isLocal());
}

test "address 进入 address_list" {
    var d = daemon.Daemon{ .allocator = testing.allocator };
    defer d.deinit();
    try parseOption(&d, "address", "/ads.net/0.0.0.0");
    try testing.expectEqual(@as(usize, 1), d.address_list.items.len);
    const r = d.address_list.items[0];
    try testing.expectEqualStrings("ads.net", r.domain);
    try testing.expectEqual(@as(u32, 0), r.addr4.?);
    try testing.expect(r.addr6 == null);
}

test "配置文件解析（注释、引号、= 两侧空格）" {
    const path = "options_test_conf.conf";
    // 注意：dnsmasq 的配置文件不支持行尾反斜杠续行（见 option.c: get_line_alloc），
    // 这里的用例严格对照 option.c: read_file() 的真实语义。
    const content =
        \\# 这是注释行，应被忽略
        \\port=5353
        \\cache-size = 200
        \\server=/example.com/1.2.3.4
        \\address=/ads.net/0.0.0.0
        \\local=/internal/
        \\domain=" padded.example "     # 引号内的空格要保留
        \\dhcp-range=ignored           # 已知但未实现的选项，仅 warning
        \\domain-needed
        \\
    ;
    const fd = try std.posix.openat(
        std.posix.AT.FDCWD,
        path,
        std.posix.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
        0o644,
    );
    var written: usize = 0;
    while (written < content.len) {
        const n = std.posix.system.write(fd, content[written..].ptr, content[written..].len);
        written += n;
    }
    _ = std.posix.system.close(fd);
    defer _ = std.posix.system.unlink(path);

    var d = daemon.Daemon{ .allocator = testing.allocator };
    defer d.deinit();
    try readConfFile(&d, path);

    try testing.expectEqual(@as(u16, 5353), d.port);
    try testing.expectEqual(@as(i32, 200), d.cachesize);

    // server=/example.com/1.2.3.4
    var want: u32 = 0;
    _ = addr.parseIp4("1.2.3.4", &want);
    var found_server = false;
    for (d.servers.items) |s| {
        if (s.domain != null and std.mem.eql(u8, s.domain.?, "example.com")) {
            try testing.expectEqual(want, s.addr.toAllAddr().ip4);
            found_server = true;
        }
    }
    try testing.expect(found_server);

    // address=/ads.net/0.0.0.0
    var found_addr = false;
    for (d.address_list.items) |r| {
        if (std.mem.eql(u8, r.domain, "ads.net")) {
            try testing.expectEqual(@as(u32, 0), r.addr4.?);
            found_addr = true;
        }
    }
    try testing.expect(found_addr);

    // local=/internal/ -> 生成本地域（SERV_LITERAL_ADDRESS）
    var found_local = false;
    for (d.servers.items) |s| {
        if (s.domain != null and std.mem.eql(u8, s.domain.?, "internal")) {
            try testing.expect(s.isLocal());
            found_local = true;
        }
    }
    try testing.expect(found_local);

    // domain=" padded.example "：引号内的前后空格必须保留（对照 hide_meta 语义）
    try testing.expect(d.domain != null);
    try testing.expectEqualStrings(" padded.example ", d.domain.?);
}

test "配置文件：行尾反斜杠不是续行" {
    const path = "options_test_conf2.conf";
    const content =
        \\port=5354
        \\domain=foo.example \
        \\bar.example
        \\
    ;
    const fd = try std.posix.openat(
        std.posix.AT.FDCWD,
        path,
        std.posix.O{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
        0o644,
    );
    var written: usize = 0;
    while (written < content.len) {
        const n = std.posix.system.write(fd, content[written..].ptr, content[written..].len);
        written += n;
    }
    _ = std.posix.system.close(fd);
    defer _ = std.posix.system.unlink(path);

    var d = daemon.Daemon{ .allocator = testing.allocator };
    defer d.deinit();
    // 第 2 行的值就是 "foo.example \"（反斜杠是值的一部分，不与下一行拼接），
    // 第 3 行 `bar.example` 没有 '=' -> 未知选项
    try testing.expectError(error.UnknownOption, readConfFile(&d, path));
    try testing.expect(d.domain != null);
    try testing.expectEqualStrings("foo.example \\", d.domain.?);
}

test "未知选项处理" {
    var d = daemon.Daemon{ .allocator = testing.allocator };
    defer d.deinit();

    // 完全未知的选项 -> 返回 UnknownOption
    try testing.expectError(error.UnknownOption, parseOption(&d, "totally-bogus-xyz", null));

    // 已知但未实现的选项 -> 仅 warning，不报错
    try parseOption(&d, "dhcp-range", "10.0.0.0,12h");
}
