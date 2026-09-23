// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! applet.zig —— busybox 式「多合一二进制」（multi-call binary）分派层。
//!
//! ## 为什么要有这一层
//!
//! 路由器上 dnsmasq 与 odhcpd 是两个各自独立的守护进程。但我们的目标是
//! **一个二进制同时充当两者**，于是采用 busybox 的做法：程序启动时看
//!   * 自己被用什么名字调用（argv[0] 的 basename），
//!   * 或者命令行里有没有显式的 `--applet=<名字>`，
//! 然后分派到对应的「applet」（功能分支）。
//!
//! 这样安装只需两条软链接，不需要第二份可执行文件：
//!
//!     /usr/sbin/zig-dnsmasq            （本体，DNS 解析/转发）
//!     /usr/sbin/dnsmasq      -> zig-dnsmasq   （可选：伪装成 dnsmasq）
//!     /usr/sbin/odhcpd       -> zig-dnsmasq   （DHCPv4/v6 + RA）
//!
//! procd 的 `/etc/init.d/odhcpd` 里写的是 `procd_set_param command /usr/sbin/odhcpd`
//! **不带任何参数**，所以「靠 argv[0] 判断身份」这件事不只是省事，而是必需。
//!
//! ## 与 busybox 的差异
//!
//! busybox 把 applet 表编译进二进制并支持 `busybox <applet> args` 形式；
//! 这里同样保留了这条路径（`--applet=`），但**默认不解析裸子命令**，
//! 避免把 dnsmasq 的第一个位置参数误当成 applet 名（dnsmasq 允许
//! `dnsmasq /etc/dnsmasq.conf` 这种写法，位置参数是配置文件）。
//!
//! 判定顺序（先命中先赢）：
//!   1. 命令行里的 `--applet=<名字>` / `--applet <名字>`
//!   2. 环境变量 ZIG_APPLET（用于不方便造软链接的场景，如容器/测试）
//!   3. argv[0] 的 basename 里是否含 "odhcpd" → odhcpd；含 "dnsmasq" → dnsmasq
//!   4. 都认不出来 → 默认 dnsmasq（保证老部署改名后行为不变）

const std = @import("std");

/// 本二进制支持的身份。
pub const Kind = enum {
    /// DNS 解析 / 转发（对应 dnsmasq 的主功能）
    dnsmasq,
    /// DHCPv4 / DHCPv6 / RA（对应 odhcpd）
    odhcpd,

    /// 用于日志与 --version 输出的名字。
    pub fn name(self: Kind) []const u8 {
        return switch (self) {
            .dnsmasq => "dnsmasq",
            .odhcpd => "odhcpd",
        };
    }
};

/// 取路径的最后一段。`/usr/sbin/odhcpd` -> `odhcpd`；`odhcpd` -> `odhcpd`。
/// 末尾的 '/' 会被跳过（`/usr/sbin/` -> `sbin`）。
pub fn basename(path: []const u8) []const u8 {
    var end = path.len;
    while (end > 0 and path[end - 1] == '/') end -= 1;
    var start = end;
    while (start > 0 and path[start - 1] != '/') start -= 1;
    return path[start..end];
}

/// 大小写不敏感的子串包含。用于兼容 `ODHCPD`、`Odhcpd` 之类的大小写写法。
fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (haystack.len < needle.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

/// 仅根据「被调用时的名字」判定身份。认不出返回 null。
///
/// 匹配的是**子串**而不是全等，这样 `zig-dnsmasq`、`dnsmasq-2.93`、
/// `dnsmasq.exe` 都能归到 dnsmasq；`odhcpd-2025.10`、`zig-odhcpd` 归到 odhcpd。
/// 先判 odhcpd：因为 "dnsmasq" 不可能是 "odhcpd" 的子串，顺序其实不影响结果，
/// 但显式写出来可以避免以后有人给 dnsmasq 变体起名时踩坑。
pub fn classify(name_raw: []const u8) ?Kind {
    const b = basename(name_raw);
    if (b.len == 0) return null;
    if (containsIgnoreCase(b, "odhcpd")) return .odhcpd;
    if (containsIgnoreCase(b, "dnsmasq")) return .dnsmasq;
    return null;
}

/// 从命令行参数里找 `--applet=X` 或 `--applet X`。
/// 返回 (身份, 需要从参数表里剔除的下标区间)。
///
/// 之所以也剔除，是因为这些参数对 applet 本身没有意义，留着会让
/// dnsmasq 的参数解析器报「无法识别的选项」。
pub const Explicit = struct {
    kind: Kind,
    /// 命中的参数个数（1 或 2），调用方据此删除
    span: usize,
    /// 命中位置在 args 里的下标
    at: usize,
};

pub fn explicitApplet(args: []const []const u8) ?Explicit {
    const prefix = "--applet=";
    for (args, 0..) |a, i| {
        if (std.mem.startsWith(u8, a, prefix)) {
            const v = a[prefix.len..];
            const k = classify(v) orelse continue;
            return .{ .kind = k, .span = 1, .at = i };
        }
        if (std.mem.eql(u8, a, "--applet")) {
            if (i + 1 >= args.len) continue;
            const k = classify(args[i + 1]) orelse continue;
            return .{ .kind = k, .span = 2, .at = i };
        }
    }
    return null;
}

/// 完整判定：显式参数 > 环境变量 > argv[0] > 默认 dnsmasq。
/// `env_applet` 传 `std.posix.getenv("ZIG_APPLET")` 的结果（或 null）。
pub fn resolve(argv0: []const u8, args: []const []const u8, env_applet: ?[]const u8) Kind {
    if (explicitApplet(args)) |e| return e.kind;
    if (env_applet) |v| {
        if (classify(v)) |k| return k;
    }
    if (classify(argv0)) |k| return k;
    return .dnsmasq;
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

test "applet：basename 处理各种写法" {
    try std.testing.expectEqualStrings("odhcpd", basename("/usr/sbin/odhcpd"));
    try std.testing.expectEqualStrings("odhcpd", basename("odhcpd"));
    try std.testing.expectEqualStrings("odhcpd", basename("./odhcpd"));
    try std.testing.expectEqualStrings("zig-dnsmasq", basename("/tmp/zd/zig-dnsmasq"));
    try std.testing.expectEqualStrings("sbin", basename("/usr/sbin/"));
    try std.testing.expectEqualStrings("", basename(""));
}

test "applet：classify 认得出软链接名与各种变体" {
    try std.testing.expectEqual(Kind.odhcpd, classify("/usr/sbin/odhcpd").?);
    try std.testing.expectEqual(Kind.odhcpd, classify("odhcpd").?);
    try std.testing.expectEqual(Kind.odhcpd, classify("odhcpd-2025.10").?);
    try std.testing.expectEqual(Kind.odhcpd, classify("zig-odhcpd").?);
    try std.testing.expectEqual(Kind.odhcpd, classify("ODHCPD").?);

    try std.testing.expectEqual(Kind.dnsmasq, classify("/usr/sbin/dnsmasq").?);
    try std.testing.expectEqual(Kind.dnsmasq, classify("dnsmasq").?);
    try std.testing.expectEqual(Kind.dnsmasq, classify("dnsmasq-2.93").?);
    try std.testing.expectEqual(Kind.dnsmasq, classify("zig-dnsmasq").?);
    try std.testing.expectEqual(Kind.dnsmasq, classify("dnsmasq.exe").?);

    try std.testing.expectEqual(@as(?Kind, null), classify("busybox"));
    try std.testing.expectEqual(@as(?Kind, null), classify(""));
}

test "applet：--applet= 显式指定优先级最高" {
    const a1 = [_][]const u8{"--applet=odhcpd"};
    try std.testing.expectEqual(Kind.odhcpd, resolve("zig-dnsmasq", &a1, null));

    const a2 = [_][]const u8{ "--applet", "odhcpd", "-C", "/x.conf" };
    const e = explicitApplet(&a2).?;
    try std.testing.expectEqual(Kind.odhcpd, e.kind);
    try std.testing.expectEqual(@as(usize, 0), e.at); // 命中的是 `--applet` 这个 token
    try std.testing.expectEqual(@as(usize, 2), e.span);

    // 认不出 applet 名的 --applet 值不应劫持分派，继续看 argv[0]
    const a3 = [_][]const u8{"--applet=nonsense"};
    try std.testing.expectEqual(Kind.dnsmasq, resolve("/usr/sbin/dnsmasq", &a3, null));
}

test "applet：环境变量次优先，argv[0] 最后" {
    try std.testing.expectEqual(Kind.odhcpd, resolve("zig-dnsmasq", &.{}, "odhcpd"));
    try std.testing.expectEqual(Kind.dnsmasq, resolve("odhcpd", &.{}, "dnsmasq"));

    // 位置参数不能被误当成 applet 名（dnsmasq 允许 `dnsmasq <conf>`）
    const a = [_][]const u8{"/etc/dnsmasq.conf", "-d"};
    try std.testing.expectEqual(Kind.dnsmasq, resolve("zig-dnsmasq", &a, null));
}

test "applet：认不出一律回退 dnsmasq，保证老部署改名后不变" {
    try std.testing.expectEqual(Kind.dnsmasq, resolve("/opt/weird-name", &.{}, null));
    try std.testing.expectEqual(Kind.dnsmasq, resolve("", &.{}, null));
}
