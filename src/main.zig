// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! main.zig — 程序入口，对应 C 源码 src/dnsmasq.c 的 main()
//!
//! 启动顺序（与 dnsmasq 一致）：
//!   1. 解析命令行与配置文件（option.c: read_opts）
//!   2. 初始化日志（log.c）
//!   3. 初始化缓存并加载 /etc/hosts、resolv.conf、--server/--address 配置
//!   4. 构建并排序上游服务器数组（domain-match.c: build_server_array）
//!   5. 建立监听 socket（network.c: create_listeners）
//!   6. 安装信号处理、启动查询线程池
//!   7. 进入事件循环（dnsmasq.c: main 的 poll 循环）
//!
//! 与 C 版的差异：dnsmasq 会 fork 到后台并降权到 --user/--group；
//! 本移植始终前台运行（和 --keep-in-foreground 一样），便于容器与调试。

const std = @import("std");
const protocol = @import("protocol.zig");
const addr = @import("addr.zig");
const util = @import("util.zig");
const log = @import("log.zig");
const daemon_mod = @import("daemon.zig");
const cache_mod = @import("cache.zig");
const options = @import("options.zig");
const hosts = @import("hosts.zig");
const resolv = @import("resolv.zig");
const domain = @import("domain.zig");
const server = @import("server.zig");
const fwdengine = @import("fwdengine.zig");
const applet = @import("applet.zig");
const odhcpd_main = @import("odhcpd_main.zig");

const Daemon = daemon_mod.Daemon;

/// 版本号（对应 VERSION 文件）
const VERSION = "2.93-zig";

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = init.gpa;

    // dnsmasq 里所有日志与锁都依赖一个 Io 实例
    log.io = io;
    log.io_ready = true;
    util.randInitFromIo(io);

    // ---- 0. busybox 式多合一：先按「被调用时的名字」判断自己是哪个 applet ----
    //
    // 安装方式：ln -sf /usr/sbin/zig-dnsmasq /usr/sbin/odhcpd
    // procd 的 /etc/init.d/odhcpd 只写 `command /usr/sbin/odhcpd`，不带任何参数，
    // 所以「靠 argv[0] 认身份」是这套方案能成立的前提。
    var args: std.ArrayListUnmanaged([]const u8) = .empty;
    defer args.deinit(gpa);
    var it = init.minimal.args.iterate();
    const argv0 = it.next() orelse "dnsmasq";
    while (it.next()) |a| try args.append(gpa, a);

    const env_applet = init.environ_map.get("ZIG_APPLET");
    const kind = applet.resolve(argv0, args.items, env_applet);

    // `--applet=` 是给 applet 分派用的，不能留在参数表里让子解析器当成
    // 未知选项报错
    if (applet.explicitApplet(args.items)) |e| {
        var i: usize = 0;
        while (i < e.span) : (i += 1) _ = args.orderedRemove(e.at);
    }

    if (kind == .odhcpd) {
        const code = odhcpd_main.main(gpa, args.items);
        if (code != 0) std.process.exit(code);
        return;
    }

    var d = Daemon{ .allocator = gpa, .io = io };
    d.start_time = util.dnsmasqTime();

    // ---- 1. 先扫一遍是否有 --help / --version ----
    for (args.items) |a| {
        if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-w")) {
            const text = try options.usageText(gpa);
            defer gpa.free(text);
            try writeStdout(io, text);
            return;
        }
        if (std.mem.eql(u8, a, "--version") or std.mem.eql(u8, a, "-v")) {
            try writeStdout(io, "Dnsmasq version " ++ VERSION ++ "\n");
            return;
        }
    }

    // ---- 2. 解析配置 ----
    // 默认配置文件按 dnsmasq 的顺序：CONFFILE 优先，其次 /etc/dnsmasq.conf
    options.parseArgs(&d, args.items) catch |e| {
        log.err("命令行解析失败: {s}", .{@errorName(e)});
        return error.BadConfig;
    };
    if (d.conf_file == null) {
        options.readConfFile(&d, "/etc/dnsmasq.conf") catch {};
    }

    // 日志：--log-queries / --log-facility
    log.log_queries = d.option(protocol.OPT_LOG);
    if (d.log_facility) |fac| {
        // `--log-facility=<facility 名>`：走 syslog，由我们自己带正确 priority。
        // 这修掉「procd 把 stderr 一律按 daemon.err 上报、于是 info 级日志
        // 顶着 err 级别」的假错误观感。
        log.enableSyslog("zig-dnsmasq", fac, false);
    } else if (d.log_file) |p| {
        if (!log.openLogFile(p)) log.warning("无法打开日志文件 {s}，改用 stderr", .{p});
    }

    // ---- 3. 缓存与 hosts / resolv ----
    d.cache = cache_mod.Cache.init(gpa, @intCast(@max(@as(i32, 0), d.cachesize))) catch |e| {
        log.err("初始化缓存失败: {s}", .{@errorName(e)});
        return error.NoMemory;
    };
    d.cache.setStaleTtl(d.stale_cache_ttl);
    d.cache_ready = true;
    defer d.deinit();

    // 本地应答 TTL 默认值（对应 dnsmasq 的 LOCAL_TTL / NEG_TTL 默认）
    if (d.local_ttl == 0) d.local_ttl = 0; // 0 表示用 cachesize 里的默认逻辑

    loadHostsAndResolv(&d);

    // ---- 4. 上游服务器数组 ----
    domain.buildServerArray(&d) catch |e| {
        log.err("构建服务器数组失败: {s}", .{@errorName(e)});
        return error.BadConfig;
    };
    logUpstreams(&d);

    // ---- 5. 监听 ----
    server.createListeners(&d) catch |e| {
        log.err("建立监听 socket 失败: {s}", .{@errorName(e)});
        return error.ListenFailed;
    };
    defer server.closeListeners(&d);

    writePidFile(&d);

    // ---- 6. 信号、异步转发引擎与本地应答线程池 ----
    if (!server.installSignals()) {
        log.warning("无法建立信号自管道，SIGHUP/SIGUSR1 将不可用", .{});
    }
    server.pool.allocator = gpa;
    server.pool.io = io;

    // 引擎必须先于线程池启动：工作线程一旦起来就会往引擎投递查询
    if (d.sync_forward) {
        log.notice("--sync-forward：已禁用异步转发引擎，启用同步阻塞转发", .{});
    } else {
        fwdengine.start(&d) catch |e| {
            log.warning("异步转发引擎启动失败（{s}），退回同步阻塞转发", .{@errorName(e)});
            d.sync_forward = true;
        };
    }
    defer fwdengine.stop();

    try server.startPool(&d);
    defer server.stopPool();

    log.notice("zig-dnsmasq {s} 已启动（缓存 {d} 条）", .{ VERSION, d.cachesize });

    // ---- 7. 事件循环 ----
    server.run(&d) catch |e| {
        log.err("主循环异常退出: {s}", .{@errorName(e)});
    };

    log.notice("正在退出", .{});
    removePidFile(&d);
}

/// 往 stdout 写一段文本（0.16 的 File API 需要 Io 与缓冲）
fn writeStdout(io: std.Io, text: []const u8) !void {
    var buf: [1024]u8 = undefined;
    var out = std.Io.File.stdout().writer(io, &buf);
    try out.interface.writeAll(text);
    try out.interface.flush();
}

/// 加载 /etc/hosts（含 --addn-hosts）与 resolv.conf
fn loadHostsAndResolv(d: *Daemon) void {
    const now = util.dnsmasqTime();
    hosts.cacheReload(&d.cache, d, now);

    // 全局单例指向本地实例（对应 C 的 daemon 全局指针）。
    // 注意必须传指针：Daemon 内含 ArrayList，按值拷贝会让两边状态分叉。
    daemon_mod.instance = d;

    if (!d.option(protocol.OPT_NO_RESOLV)) {
        // 基线必须**先于**读取沉淀：顺序反了会把「读时文件还空、读完才被 netifd
        // 填上」的开机竞态悄悄吸收掉，DNS 会永久停在 0 个上游。
        // 详见 server.snapshotResolvStats 的注释。
        if (!d.option(protocol.OPT_NO_POLL)) server.snapshotResolvStats(d);
        resolv.readResolvFiles(d) catch |e| {
            log.warning("读取 resolv 文件失败: {s}", .{@errorName(e)});
        };
    }

    // 启动就 0 个上游（典型是开机早于 WAN 拨号成功）：必须**强制下轮重试**，
    // 否则用户只能手动重启才恢复。对应 C dnsmasq 的
    // `no servers found in %s, will retry`（dnsmasq.c:1831 + mtime=0）。
    if (d.servers.items.len == 0 and !d.option(protocol.OPT_NO_RESOLV)) {
        if (d.option(protocol.OPT_NO_POLL)) {
            log.warning("resolv.conf 里没有可用的 nameserver，**且 --no-poll 关闭了轮询**" ++
                "，本进程不会自动重试 —— 若要开机自愈请去掉 --no-poll。", .{});
        } else {
            server.forceResolvRetry(d);
            log.warning("resolv.conf 里还没有可用的 nameserver（多半是 WAN 还没拨上），将持续重试。", .{});
        }
    }
}

fn logUpstreams(d: *Daemon) void {
    if (d.serverarray.items.len == 0) {
        if (!d.option(protocol.OPT_NO_RESOLV)) {
            log.warning("没有任何上游服务器（既无 --server 也无 resolv.conf nameserver）", .{});
        }
        return;
    }
    var buf: [4096]u8 = undefined;
    var n: usize = 0;
    for (d.serverarray.items) |s| {
        if (n + 96 >= buf.len) break;
        var tmp: [128]u8 = undefined;
        const at = s.addrText(&tmp);
        const dom = s.domain orelse "<default>";
        const w = std.fmt.bufPrint(buf[n..], "  {s} ({s}){s}\n", .{
            at, dom, if (s.isLocal()) " [local]" else "",
        }) catch break;
        n += w.len;
    }
    log.info("上游服务器列表:\n{s}", .{buf[0..n]});
}

fn writePidFile(d: *Daemon) void {
    const path = d.pid_file orelse return;
    const fd = util.openTruncate(path) orelse {
        log.warning("无法写入 PID 文件 {s}", .{path});
        return;
    };
    defer _ = std.posix.system.close(fd);
    var buf: [32]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, "{d}\n", .{std.os.linux.getpid()}) catch return;
    _ = std.posix.system.write(fd, text.ptr, text.len);
}

fn removePidFile(d: *Daemon) void {
    const path = d.pid_file orelse return;
    util.removeFile(path);
}
