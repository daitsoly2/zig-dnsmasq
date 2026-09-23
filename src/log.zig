// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! log.zig — 对应 C 源码 src/log.c（精简移植）
//!
//! 差异说明：C 版本使用日志队列 + 写线程，这里改为「组装成一行后一次性
//! write(2)」，既保证多线程下的行原子性，也避免额外线程。日志格式与
//! dnsmasq 保持一致，便于对照。

const std = @import("std");
const protocol = @import("protocol.zig");
const addr = @import("addr.zig");

pub const Level = enum(u8) {
    emerg = 0,
    alert = 1,
    crit = 2,
    err = 3,
    warning = 4,
    notice = 5,
    info = 6,
    debug = 7,

    fn tag(self: Level) []const u8 {
        return switch (self) {
            .emerg => "emerg",
            .alert => "alert",
            .crit => "crit",
            .err => "err",
            .warning => "warning",
            .notice => "notice",
            .info => "info",
            .debug => "debug",
        };
    }
};

pub var level: Level = .info;
/// 对应 OPT_QUIET
pub var quiet: bool = false;
/// 对应 OPT_LOG（--log-queries）
pub var log_queries: bool = false;
/// 日志文件描述符（--log-facility=<file>）
pub var log_fd: ?std.posix.fd_t = null;

// ---------------------------------------------------------------------------
// syslog（对应 C 的 --log-facility=<facility>）
//
// C 的语义（option.c:2279 的 '8' 分支、log.c:355 的 openlog/vsyslog）：
//   值里含 '/' 或等于 "-"  → 当**文件路径**（走 log_fd / stderr）
//   否则                  → 当**syslog facility 名**（openlog + vsyslog）
//
// 为什么需要它：我们跑在 procd 下，init 里 `procd_set_param stderr 1`，
// 而 procd 把子进程的 stderr **一律按 daemon.err 上报**，于是日志里
// `zig-dnsmasq: info: ...` 的内容顶着 `daemon.err` 的级别，看着像错误、
// 按级别过滤也不对。走 syslog 由我们自己带正确 priority，这才是正解。
// ---------------------------------------------------------------------------

/// syslog facility（对应 C 的 `daemon->log_fac`）。null = 不走 syslog。
pub var syslog_facility: ?u8 = null;

/// syslog 报文里的 tag（对应 `openlog("dnsmasq", ...)` 的第一个参数）。
/// 单二进制分派两个服务，所以由各 applet 自己设置，日志里才看得出是谁。
pub var syslog_tag: []const u8 = "zig-dnsmasq";

/// 是否在 syslog 之外**再**镜像一份到 stderr（对应 odhcpd 的 `LOG_PERROR`）。
/// 前台手动跑时方便看；被 procd 管着时 stderr 没有接收方，多写一份也无害。
pub var syslog_also_stderr: bool = false;

/// syslog 的 UNIX DGRAM socket（懒打开；失败则永久关闭 syslog 输出）
var syslog_fd: ?std.posix.fd_t = null;
/// 打开失败过就不再重试（避免每条日志都去 socket() 一次）
var syslog_failed: bool = false;

/// `--log-facility` 的分类结果。
/// 对应 C option.c:2284 `strchr(arg, '/') || strcmp(arg, "-") == 0`。
pub const FacilityClass = union(enum) {
    /// 普通文件路径（含 `-`，表示 stderr）
    file,
    /// syslog facility 值（0..23，已按名字查到）
    syslog: u8,
};

/// glibc `syslog.h` 的 `facilitynames`（对应 C option.c:2290 查的那张表）。
/// 名字匹配大小写不敏感 —— C 用的是 `hostname_isequal`。
const FacilityName = struct { name: []const u8, val: u8 };
const facility_names = [_]FacilityName{
    .{ .name = "kern", .val = 0 },
    .{ .name = "user", .val = 1 },
    .{ .name = "mail", .val = 2 },
    .{ .name = "daemon", .val = 3 },
    .{ .name = "auth", .val = 4 },
    .{ .name = "syslog", .val = 5 },
    .{ .name = "lpr", .val = 6 },
    .{ .name = "news", .val = 7 },
    .{ .name = "uucp", .val = 8 },
    .{ .name = "cron", .val = 9 },
    .{ .name = "authpriv", .val = 10 },
    .{ .name = "ftp", .val = 11 },
    .{ .name = "local0", .val = 16 },
    .{ .name = "local1", .val = 17 },
    .{ .name = "local2", .val = 18 },
    .{ .name = "local3", .val = 19 },
    .{ .name = "local4", .val = 20 },
    .{ .name = "local5", .val = 21 },
    .{ .name = "local6", .val = 22 },
    .{ .name = "local7", .val = 23 },
};

/// 按名字查 facility。大小写不敏感（与 C 的 hostname_isequal 一致）。
pub fn facilityValue(name: []const u8) ?u8 {
    for (facility_names) |f| {
        if (f.name.len != name.len) continue;
        var same = true;
        for (f.name, name) |a, b| {
            if (std.ascii.toLower(a) != std.ascii.toLower(b)) {
                same = false;
                break;
            }
        }
        if (same) return f.val;
    }
    return null;
}

/// 分类 `--log-facility` 的值。返回 null 表示「既不是路径、也不是已知
/// facility 名」，调用方应按 C 的行为报 `bad log facility` 并退出。
pub fn classifyLogFacility(arg: []const u8) ?FacilityClass {
    // C: `strchr(arg, '/') || strcmp(arg, "-") == 0` → 当文件名
    if (std.mem.indexOfScalar(u8, arg, '/') != null or std.mem.eql(u8, arg, "-"))
        return .file;
    if (facilityValue(arg)) |v| return .{ .syslog = v };
    return null;
}

/// 打开到 `/dev/log` 的 UNIX DGRAM socket（对应 C log.c:355 的 openlog）。
/// 幂等；失败后不再重试。返回是否可用。
fn ensureSyslogSocket() bool {
    if (syslog_fd != null) return true;
    if (syslog_failed) return false;

    const system = std.posix.system;
    const rc = system.socket(
        std.posix.AF.UNIX,
        system.SOCK.DGRAM | system.SOCK.CLOEXEC,
        0,
    );
    if (std.posix.errno(rc) != .SUCCESS) {
        syslog_failed = true;
        return false;
    }
    syslog_fd = @intCast(rc);
    return true;
}

/// 发一条 syslog 报文。格式 `<PRI>tag[pid]: msg`
/// —— 对应 `openlog(tag, LOG_PID, fac)` + `vsyslog(priority, msg)`。
/// PRI = facility*8 + severity，我们的 `Level` 枚举顺序恰好就是 syslog
/// 的 severity 顺序（emerg=0 … debug=7），可直接用。
fn emitSyslog(fac: u8, lvl: Level, msg: []const u8) void {
    if (!ensureSyslogSocket()) return;
    const fd = syslog_fd.?;

    // syslog 报文里不再重复「zig-dnsmasq: info:」那种自造前缀
    // —— 级别已经在 PRI 里、程序名在 tag 里，logread 会自己排版。
    var buf: [1664]u8 = undefined;
    const text = std.fmt.bufPrint(&buf, "<{d}>{s}[{d}]: {s}\n", .{
        @as(u16, fac) * 8 + @intFromEnum(lvl),
        syslog_tag,
        std.os.linux.getpid(),
        msg,
    }) catch return;

    var log_sa: std.posix.sockaddr.un = .{ .family = std.posix.AF.UNIX, .path = [_]u8{0} ** 108 };
    const dev_log = "/dev/log";
    @memcpy(log_sa.path[0..dev_log.len], dev_log);

    const system = std.posix.system;
    const rc = system.sendto(
        fd,
        text.ptr,
        text.len,
        0,
        @ptrCast(&log_sa),
        @sizeOf(std.posix.sockaddr.un),
    );
    if (std.posix.errno(rc) != .SUCCESS) {
        // 发不出去就关掉 syslog（例如 logd 没起来 / /dev/log 不在沙箱里），
        // 避免每条日志都白跑一次系统调用拖慢 DNS 主路径。
        _ = std.posix.system.close(fd);
        syslog_fd = null;
        syslog_failed = true;
    }
}


/// 安全写：允许部分写与 EINTR
///
/// 注意 `std.posix.system.write` 在链接 libc 时返回 `isize`、走裸 syscall 时返回
/// `usize`；这里用 `@intCast` + `@bitCast` 统一成 `usize` 交给 `std.posix.errno`，
/// 两种模式下都正确（-1/负错误码按补码原样传回）。
fn writeAllFd(fd: std.posix.fd_t, buf: []const u8) void {
    var off: usize = 0;
    while (off < buf.len) {
        const rc_signed: isize = @intCast(std.posix.system.write(fd, buf.ptr + off, buf.len - off));
        const rc: usize = @bitCast(rc_signed);
        if (std.posix.errno(rc) == .SUCCESS) {
            if (rc == 0) return;
            off += rc;
        } else if (std.posix.errno(rc) == .INTR) {
            continue;
        } else return;
    }
}

var log_mutex: std.Io.Mutex = .init;
/// 供 log.zig 使用的 Io 实例（main 启动时注入，用于日志锁与文件写入）
pub var io: std.Io = undefined;
pub var io_ready: bool = false;

/// 日志接收器：非 null 时日志改投到这里（测试断言 / 嵌入式场景用），
/// 不再写 stderr 或日志文件。
pub var sink: ?*const fn (text: []const u8) void = null;

/// 是否真的把日志写出去。测试构建（`zig build test`）默认关闭：
/// 测试运行器的控制通道占用 stderr，直接写会破坏测试协议。
/// 需要断言日志的测试请调用 `enableCapture()`。
pub var enabled: bool = !@import("builtin").is_test;

pub fn shouldEmit(lvl: Level) bool {
    return @intFromEnum(lvl) <= @intFromEnum(level);
}

pub fn emit(lvl: Level, comptime fmt: []const u8, args: anytype) void {
    if (sink == null and !enabled) return;
    if (!shouldEmit(lvl)) return;

    var body: [1536]u8 = undefined;
    const msg = std.fmt.bufPrint(&body, fmt, args) catch body[0..0];

    if (io_ready) {
        log_mutex.lockUncancelable(io);
        defer log_mutex.unlock(io);
        emitLocked(lvl, msg);
    } else {
        emitLocked(lvl, msg);
    }
}

/// 真正把一行日志送出去。调用方必须已持有 log_mutex（或处于 io 未就绪的
/// 单线程启动阶段）。三条互斥的出口，对应 C 的三条分支：
///   * syslog（`--log-facility=<facility>`，或 odhcpd applet 默认）
///   * 日志文件（`--log-facility=<带斜杠的路径>`）
///   * stderr（默认，被 procd 捕获后按 daemon.err 上报）
/// `syslog_also_stderr` 对应 odhcpd 的 `LOG_PERROR`：syslog 之外**再**镜像一份
/// 到 stderr，前台调试时看得见。
fn emitLocked(lvl: Level, msg: []const u8) void {
    if (sink) |s| {
        var line: [1664]u8 = undefined;
        const text = std.fmt.bufPrint(&line, "zig-dnsmasq: {s}: {s}\n", .{ lvl.tag(), msg }) catch return;
        s(text);
        return;
    }

    if (syslog_facility) |fac| {
        emitSyslog(fac, lvl, msg);
        if (!syslog_also_stderr) return;
    }

    if (syslog_facility != null) {
        // LOG_PERROR 分支：只有 syslog 也开着时才走到这里
        var line2: [1664]u8 = undefined;
        const t2 = std.fmt.bufPrint(&line2, "{s}[{d}]: {s}\n", .{ syslog_tag, std.os.linux.getpid(), msg }) catch return;
        writeAllFd(std.posix.STDERR_FILENO, t2);
        return;
    }

    var line: [1664]u8 = undefined;
    const text = std.fmt.bufPrint(&line, "zig-dnsmasq: {s}: {s}\n", .{ lvl.tag(), msg }) catch return;
    if (log_fd) |fd| writeAllFd(fd, text) else writeAllFd(std.posix.STDERR_FILENO, text);
}

// ---------------------------------------------------------------------------
// 日志捕获（仅供测试断言使用）
// ---------------------------------------------------------------------------
var capture_buf: [16384]u8 = undefined;
var capture_len: usize = 0;

fn captureSink(text: []const u8) void {
    const n = @min(text.len, capture_buf.len - capture_len);
    @memcpy(capture_buf[capture_len..][0..n], text[0..n]);
    capture_len += n;
}

/// 打开日志捕获（测试用）
pub fn enableCapture() void {
    capture_len = 0;
    sink = &captureSink;
}

/// 关闭日志捕获（测试用）
pub fn disableCapture() void {
    sink = null;
    capture_len = 0;
}

/// 已捕获的日志文本（测试用）
pub fn capturedText() []const u8 {
    return capture_buf[0..capture_len];
}

pub fn emerg(comptime fmt: []const u8, args: anytype) void {
    emit(.emerg, fmt, args);
}
pub fn err(comptime fmt: []const u8, args: anytype) void {
    emit(.err, fmt, args);
}
pub fn warning(comptime fmt: []const u8, args: anytype) void {
    emit(.warning, fmt, args);
}
pub fn notice(comptime fmt: []const u8, args: anytype) void {
    emit(.notice, fmt, args);
}
pub fn info(comptime fmt: []const u8, args: anytype) void {
    emit(.info, fmt, args);
}
pub fn debug(comptime fmt: []const u8, args: anytype) void {
    emit(.debug, fmt, args);
}

/// 对应 log.c: die()
pub fn die(comptime fmt: []const u8, args: anytype) noreturn {
    emit(.crit, fmt, args);
    std.process.exit(1);
}

/// 打开日志文件（对应 log.c: log_reopen）
pub fn openLogFile(path: []const u8) bool {
    const util = @import("util.zig");
    const fd = util.openAppend(path) orelse return false;
    log_fd = fd;
    return true;
}

/// 启用 syslog 输出。对应 C 的 `openlog(tag, LOG_PID [, LOG_PERROR], facility)`。
/// 单二进制分派两个 applet，各自在启动时按自己的身份调一次 —— 这样
/// `logread` 里 DNS 是 `zig-dnsmasq[...]`、DHCP 是 `odhcpd[...]`，一眼可分。
pub fn enableSyslog(tag: []const u8, facility: u8, also_stderr: bool) void {
    syslog_tag = tag;
    syslog_facility = facility;
    syslog_also_stderr = also_stderr;
}

/// 对应 cache.c: querystr()：把 RR 类型拼成 "A"/"AAAA"/"PTR" 之类的短名
fn queryTypeName(buf: []u8, t: u16) []const u8 {
    if (protocol.rrTypeName(t)) |nm| return nm;
    return std.fmt.bufPrint(buf, "type={d}", .{t}) catch "type=?";
}

/// 对应 dnsmasq 的 log_query()（cache.c）。
///
/// 输出格式（无 OPT_EXTRALOG 时）为：`%s %s%s%s %s%s` →
///     <source> <name> <verb> <dest>
/// 例：
///     query[A] example.com from 192.168.1.5
///     forwarded example.com to 8.8.8.8
///     cached example.com is 1.2.3.4
///     /etc/hosts host.local is 10.0.0.1
///     config bad.example is NXDOMAIN
///
/// flags 用 protocol.F_* 组合；a 为地址（查询日志里是客户端源地址，
/// 应答日志里是记录地址）；arg 是 F_HOSTS 的 hosts 文件名 / F_UPSTREAM 的
/// 上游服务器名 / F_RRNAME 的资源记录名；qtype 为查询的 RR 类型。
pub fn logQuery(flags: u32, name_s: []const u8, a: ?addr.AllAddr, arg: ?[]const u8, qtype: u16) void {
    if (!log_queries) return;

    const arg_text = arg orelse "";

    var destbuf: [64]u8 = undefined;
    var typebuf: [16]u8 = undefined;

    // ---- dest：应答内容 ----
    var dest: []const u8 = arg_text;
    if (a) |x| {
        switch (x) {
            .ip4 => |v| {
                var nb: [16]u8 = undefined;
                dest = addr.writeIp4(&nb, v);
                // writeIp4 返回的是入参缓冲的切片，需要拷到 destbuf 保证生命周期
                const n = @min(dest.len, destbuf.len);
                @memcpy(destbuf[0..n], dest[0..n]);
                dest = destbuf[0..n];
            },
            .ip6 => |v| {
                var nb: [64]u8 = undefined;
                const t = addr.writeIp6(&nb, &v);
                const n = @min(t.len, destbuf.len);
                @memcpy(destbuf[0..n], t[0..n]);
                dest = destbuf[0..n];
            },
            .log => |l| {
                dest = switch (l.rcode) {
                    protocol.SERVFAIL => "SERVFAIL",
                    protocol.REFUSED => "REFUSED",
                    protocol.FORMERR => "FORMERR",
                    protocol.NOTIMP => "not implemented",
                    else => std.fmt.bufPrint(&destbuf, "{d}", .{l.rcode}) catch "?",
                };
            },
            else => dest = arg_text,
        }
    }

    if ((flags & protocol.F_NEG) != 0) {
        if ((flags & protocol.F_NXDOMAIN) != 0) {
            dest = "NXDOMAIN";
        } else if ((flags & protocol.F_IPV4) != 0) {
            dest = "NODATA-IPv4";
        } else if ((flags & protocol.F_IPV6) != 0) {
            dest = "NODATA-IPv6";
        } else {
            dest = "NODATA";
        }
    } else if ((flags & protocol.F_CNAME) != 0) {
        dest = "<CNAME>";
    } else if ((flags & protocol.F_RRNAME) != 0) {
        dest = arg_text;
    }

    // 反查：把地址放到前面的 name 槽，名字放到 dest 槽
    var nm = name_s;
    if ((flags & protocol.F_REVERSE) != 0) {
        const tmp = nm;
        nm = dest;
        dest = tmp;
    }

    // ---- source：谁给出的答案 ----
    var source: []const u8 = "cached";
    var verb: []const u8 = "is";
    if ((flags & protocol.F_CONFIG) != 0) {
        source = "config";
    } else if ((flags & protocol.F_DHCP) != 0) {
        source = "DHCP";
    } else if ((flags & protocol.F_HOSTS) != 0) {
        source = arg_text;
    } else if ((flags & protocol.F_UPSTREAM) != 0) {
        source = "reply";
    } else if ((flags & protocol.F_AUTH) != 0) {
        source = "auth";
    } else if ((flags & protocol.F_QUERY) != 0) {
        source = "query";
    } else if ((flags & protocol.F_SERVER) != 0) {
        source = "forwarded";
        verb = "to";
    }

    if ((flags & protocol.F_QUERY) != 0) {
        verb = "from";
        if (qtype > 0) {
            var sbuf: [32]u8 = undefined;
            const tn = queryTypeName(&typebuf, qtype);
            source = std.fmt.bufPrint(&sbuf, "{s}[{s}]", .{ source, tn }) catch source;
        }
    }

    if (nm.len == 0) nm = ".";
    emit(.info, "{s} {s} {s} {s}", .{ source, nm, verb, dest });
}

const testing = std.testing;

test "log level filtering" {
    level = .warning;
    try testing.expect(!shouldEmit(.info));
    try testing.expect(!shouldEmit(.notice));
    try testing.expect(shouldEmit(.warning));
    try testing.expect(shouldEmit(.err));

    // 捕获模式下验证行格式
    enableCapture();
    defer disableCapture();

    info("should be suppressed {d}", .{1});
    try testing.expectEqualStrings("", capturedText());

    err("visible {s}", .{"yes"});
    try testing.expectEqualStrings("zig-dnsmasq: err: visible yes\n", capturedText());

    level = .info;
}

test "log_query 格式与 dnsmasq 一致" {
    log_queries = true;
    defer log_queries = false;
    level = .info;

    const client = addr.SockAddr.fromIp4(@bitCast([4]u8{ 192, 168, 1, 5 }), 54321);
    const client_addr = client.toAllAddr();
    const rec4 = addr.AllAddr{ .ip4 = @bitCast([4]u8{ 1, 2, 3, 4 }) };

    // query[A] example.com from 192.168.1.5
    enableCapture();
    logQuery(protocol.F_QUERY | protocol.F_IPV4, "example.com", client_addr, null, protocol.T_A);
    try testing.expectEqualStrings("zig-dnsmasq: info: query[A] example.com from 192.168.1.5\n", capturedText());

    // forwarded example.com to 8.8.8.8（F_SERVER + arg 为上游名）
    disableCapture();
    enableCapture();
    logQuery(protocol.F_SERVER | protocol.F_IPV6, "example.com", null, "8.8.8.8", protocol.T_A);
    try testing.expectEqualStrings("zig-dnsmasq: info: forwarded example.com to 8.8.8.8\n", capturedText());

    // cached example.com is 1.2.3.4
    disableCapture();
    enableCapture();
    logQuery(protocol.F_FORWARD | protocol.F_IPV4, "example.com", rec4, null, protocol.T_A);
    try testing.expectEqualStrings("zig-dnsmasq: info: cached example.com is 1.2.3.4\n", capturedText());

    // /etc/hosts host.local is 10.0.0.1（F_HOSTS 时 arg 是 hosts 文件名）
    disableCapture();
    enableCapture();
    logQuery(protocol.F_HOSTS | protocol.F_FORWARD | protocol.F_IPV4, "host.local", addr.AllAddr{ .ip4 = @bitCast([4]u8{ 10, 0, 0, 1 }) }, "/etc/hosts", protocol.T_A);
    try testing.expectEqualStrings("zig-dnsmasq: info: /etc/hosts host.local is 10.0.0.1\n", capturedText());

    // config bad.example is NXDOMAIN
    disableCapture();
    enableCapture();
    logQuery(protocol.F_CONFIG | protocol.F_NEG | protocol.F_NXDOMAIN, "bad.example", null, null, protocol.T_A);
    try testing.expectEqualStrings("zig-dnsmasq: info: config bad.example is NXDOMAIN\n", capturedText());

    // 反查（如 rfc1035.c:1918 的 PTR 缓存命中）：
    // 传入的是「记录名」，F_REVERSE 会让 name/dest 互换，
    // 于是地址出现在前面 -> cached 192.168.1.5 is host.local
    disableCapture();
    enableCapture();
    logQuery(protocol.F_REVERSE | protocol.F_IPV4, "host.local", addr.AllAddr{ .ip4 = @bitCast([4]u8{ 192, 168, 1, 5 }) }, null, protocol.T_PTR);
    try testing.expectEqualStrings("zig-dnsmasq: info: cached 192.168.1.5 is host.local\n", capturedText());

    // hosts 提供反查时 source 取 arg（hosts 文件名）
    disableCapture();
    enableCapture();
    logQuery(protocol.F_REVERSE | protocol.F_IPV4 | protocol.F_HOSTS, "host.local", addr.AllAddr{ .ip4 = @bitCast([4]u8{ 192, 168, 1, 5 }) }, "/etc/hosts", protocol.T_PTR);
    try testing.expectEqualStrings("zig-dnsmasq: info: /etc/hosts 192.168.1.5 is host.local\n", capturedText());

    // 关闭 log-queries 时不应输出
    log_queries = false;
    disableCapture();
    enableCapture();
    logQuery(protocol.F_QUERY | protocol.F_IPV4, "example.com", client_addr, null, protocol.T_A);
    try testing.expectEqualStrings("", capturedText());
    log_queries = true;
}
