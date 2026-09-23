// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! uci.zig —— OpenWrt UCI 配置文件的**只读**解析器。
//!
//! ## 为什么自己写而不用 libuci
//!
//! odhcpd 通过 libuci 读 `/etc/config/dhcp`（`ref/odhcpd/src/config.c:2064`
//! 的 `odhcpd_reload()`）。本移植是**静态链接的 musl 单二进制**，不链接
//! libuci/libubox，也不想为了读一个纯文本文件去调外部 `uci` 命令
//! （那会引入对 shell 与 PATH 的依赖，在 ujail 沙箱里还要额外放行）。
//!
//! UCI 的文件语法很小，实现它的成本远低于引入依赖：
//!
//! ```text
//! # 注释
//! config <type> ['<名字>']
//!     option <键> '<值>'
//!     option <键> <值>
//!     list   <键> '<值>'
//! ```
//!
//! 引号规则照 libuci：单引号内原样保留；双引号内 `\"` 与 `\\` 是转义；
//! 不加引号时取到行尾（去尾部空白）。
//!
//! ## 容错策略
//!
//! 真实 UCI 解析失败会让整个包加载失败。路由器上的配置文件是人手改的，
//! 一个手抖不该让 DHCP 整个不工作 —— 所以这里**逐行容错**：坏行记一条
//! 警告后跳过，能读出的部分照常生效。是否真的「配置为空」由调用方判断
//! （见 `uci_dhcp.zig`）。

const std = @import("std");
const posix = std.posix;
const system = std.os.linux;

const Allocator = std.mem.Allocator;
const log = @import("log.zig");

pub const Option = struct {
    key: []const u8,
    value: []const u8,
    /// `list` 产生的是列表项（同一键可以出现多次）
    is_list: bool,
};

pub const Section = struct {
    /// 段类型，例如 `dhcp` / `host` / `odhcpd`
    typ: []const u8,
    /// 段名（`config dhcp 'lan'` 里的 `lan`）；未命名段为 null
    name: ?[]const u8,
    opts: []Option = &.{},
    /// 段头所在行号（1 起），用于报错定位
    line: u32 = 0,

    /// 取一个标量选项（同键出现多次时取**第一个**，与 libuci 的
    /// `uci_lookup_option()` 一致）。
    pub fn get(self: *const Section, key: []const u8) ?[]const u8 {
        for (self.opts) |o| {
            if (std.mem.eql(u8, o.key, key)) return o.value;
        }
        return null;
    }

    /// 收集一个选项的全部取值（`list` 与 `option` 都算，顺序保持文件顺序）。
    pub fn collect(self: *const Section, allocator: Allocator, key: []const u8) ![]const []const u8 {
        var out: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer out.deinit(allocator);
        for (self.opts) |o| {
            if (std.mem.eql(u8, o.key, key)) try out.append(allocator, o.value);
        }
        return out.toOwnedSlice(allocator);
    }

    /// UCI 的布尔语义：`1`/`true`/`yes`/`on`/`enabled` 为真。
    /// 与 libuci 的 `uci_to_bool` 一致（其余字面量一律为假）。
    pub fn getBool(self: *const Section, key: []const u8) ?bool {
        const v = self.get(key) orelse return null;
        return boolOf(v);
    }

    pub fn getInt(self: *const Section, key: []const u8) ?i64 {
        const v = self.get(key) orelse return null;
        return std.fmt.parseInt(i64, std.mem.trim(u8, v, " \t"), 10) catch null;
    }
};

pub fn boolOf(v: []const u8) bool {
    const t = [_][]const u8{ "1", "true", "yes", "on", "enabled" };
    for (t) |x| {
        if (std.ascii.eqlIgnoreCase(v, x)) return true;
    }
    return false;
}

pub const Package = struct {
    arena: std.heap.ArenaAllocator,
    sections: []Section,

    pub fn deinit(self: *Package) void {
        self.arena.deinit();
    }

    /// 按类型找第一个段
    pub fn first(self: *const Package, typ: []const u8) ?*const Section {
        for (self.sections) |*s| {
            if (std.mem.eql(u8, s.typ, typ)) return s;
        }
        return null;
    }

    /// 按类型 + 段名找段（`name == null` 表示「未命名段」）
    pub fn byName(self: *const Package, typ: []const u8, name: ?[]const u8) ?*const Section {
        for (self.sections) |*s| {
            if (!std.mem.eql(u8, s.typ, typ)) continue;
            if (s.name == null and name == null) return s;
            if (s.name != null and name != null and std.mem.eql(u8, s.name.?, name.?)) return s;
        }
        return null;
    }

    /// 统计某类型的段数
    pub fn count(self: *const Package, typ: []const u8) usize {
        var n: usize = 0;
        for (self.sections) |s| {
            if (std.mem.eql(u8, s.typ, typ)) n += 1;
        }
        return n;
    }
};

pub const ParseResult = struct {
    package: Package,
    /// 跳过的坏行数（已打警告）
    bad_lines: usize,
};

pub fn parse(allocator: Allocator, text: []const u8) !ParseResult {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    var sections: std.ArrayListUnmanaged(Section) = .empty;
    var cur: ?usize = null;
    var bad: usize = 0;
    var lineno: u32 = 0;

    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw| {
        lineno += 1;
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (line[0] == '#') continue;

        const kw = keyword(line);
        const rest = std.mem.trim(u8, line[kw.len..], " \t");

        if (std.mem.eql(u8, kw, "config")) {
            const ty = takeToken(rest, 0) orelse {
                log.warning("uci: 第 {d} 行 config 缺段类型，已跳过", .{lineno});
                bad += 1;
                continue;
            };
            var nm: ?[]const u8 = null;
            if (takeToken(rest, ty.end)) |n| {
                if (n.raw.len > 0) nm = try a.dupe(u8, n.raw);
            }
            try sections.append(a, .{
                .typ = try a.dupe(u8, ty.raw),
                .name = nm,
                .line = lineno,
            });
            cur = sections.items.len - 1;
            continue;
        }
        if (std.mem.eql(u8, kw, "package")) continue; // 只出现在 /var/state 里
        if (std.mem.eql(u8, kw, "option") or std.mem.eql(u8, kw, "list")) {
            const ci = cur orelse {
                log.warning("uci: 第 {d} 行 {s} 出现在任何 config 段之前，已跳过", .{ lineno, kw });
                bad += 1;
                continue;
            };
            const key = takeToken(rest, 0) orelse {
                log.warning("uci: 第 {d} 行 {s} 缺键名，已跳过", .{ lineno, kw });
                bad += 1;
                continue;
            };
            const val = takeValue(std.mem.trim(u8, rest[key.end..], " \t"));
            const seg = &sections.items[ci];
            const old = seg.opts;
            const nw = try a.alloc(Option, old.len + 1);
            @memcpy(nw[0..old.len], old);
            nw[old.len] = .{
                .key = try a.dupe(u8, key.raw),
                .value = try decode(a, val),
                .is_list = std.mem.eql(u8, kw, "list"),
            };
            seg.opts = nw;
            continue;
        }
        // 其它关键字：libuci 会报错，这里只警告，保证坏行不拖垮整份配置
        log.warning("uci: 第 {d} 行以未知关键字 '{s}' 开头，已跳过", .{ lineno, kw });
        bad += 1;
    }

    return .{
        .package = .{
            .arena = arena,
            .sections = try sections.toOwnedSlice(a),
        },
        .bad_lines = bad,
    };
}

fn isSpace(c: u8) bool {
    return c == ' ' or c == '\t';
}

fn keyword(line: []const u8) []const u8 {
    var i: usize = 0;
    while (i < line.len and !isSpace(line[i])) i += 1;
    return line[0..i];
}

/// 一个从 `off` 开始扫出来的 token。`raw` 已去掉引号（单引号还原文，
/// 双引号标记 `dq = true` 待调用方解转义）；`end` 是它在入参里的右边界。
const Token = struct {
    raw: []const u8,
    dq: bool = false,
    end: usize = 0,
};

fn takeToken(s: []const u8, off: usize) ?Token {
    var i = off;
    while (i < s.len and isSpace(s[i])) i += 1;
    if (i >= s.len) return null;
    if (s[i] == '\'' or s[i] == '"') {
        const q = s[i];
        var j = i + 1;
        while (j < s.len and s[j] != q) {
            // 双引号内 `\` 转义下一个字符，扫结尾时不能把 \" 当结束符；
            // 单引号内没有转义（libuci 语义）。
            j += if (q == '"' and s[j] == '\\' and j + 1 < s.len) 2 else 1;
        }
        const end = if (j < s.len) j + 1 else s.len; // 引号没闭合就吃到行尾
        return .{ .raw = s[i + 1 .. @min(j, s.len)], .dq = q == '"', .end = end };
    }
    var j = i;
    while (j < s.len and !isSpace(s[j])) j += 1;
    return .{ .raw = s[i..j], .end = j };
}

/// 「值」：带引号时按引号规则取出，否则取到行尾（去尾部空白）。
fn takeValue(s: []const u8) Token {
    var i: usize = 0;
    while (i < s.len and isSpace(s[i])) i += 1;
    if (i >= s.len) return .{ .raw = "", .end = s.len };
    if (s[i] == '\'' or s[i] == '"') return takeToken(s, i).?;
    return .{ .raw = std.mem.trimEnd(u8, s[i..], " \t"), .end = s.len };
}

/// 把 token 落成最终字符串：双引号内容需要折叠 `\"` 与 `\\`。
/// `unescape` 的输出**只会变短**，所以按原长开一块即可，不需要栈缓冲。
fn decode(a: Allocator, t: Token) ![]const u8 {
    if (!t.dq) return a.dupe(u8, t.raw);
    const buf = try a.alloc(u8, t.raw.len);
    return a.dupe(u8, unescape(t.raw, buf));
}

/// 折叠双引号内的 `\"` 与 `\\`（libuci 只认可这两个转义，其余原样保留）。
/// `buf` 长度必须 >= `src.len`。
pub fn unescape(src: []const u8, buf: []u8) []const u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < src.len) : (i += 1) {
        if (src[i] == '\\' and i + 1 < src.len and (src[i + 1] == '"' or src[i + 1] == '\\')) {
            buf[n] = src[i + 1];
            i += 1;
        } else {
            buf[n] = src[i];
        }
        n += 1;
    }
    return buf[0..n];
}

/// 从文件读入并解析
pub fn load(allocator: Allocator, path: []const u8) !ParseResult {
    const fd = try posix.openat(posix.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    defer _ = system.close(fd);
    const txt = try readAll(allocator, fd, 1 << 20);
    defer allocator.free(txt);
    return parse(allocator, txt);
}

fn readAll(allocator: Allocator, fd: i32, max: usize) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);
    var buf: [4096]u8 = undefined;
    while (out.items.len < max) {
        const n = try posix.read(fd, &buf);
        if (n == 0) break;
        try out.appendSlice(allocator, buf[0..n]);
    }
    return out.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

const testing = std.testing;

const sample =
    \\# 注释行
    \\config dnsmasq
    \\    option domain 'HOME'
    \\    list interface 'lan'
    \\
    \\config dhcp 'lan'
    \\    option interface 'lan'
    \\    option start '100'
    \\    option limit '150'
    \\    option leasetime '12h'
    \\    option dhcpv4 'server'
    \\    option force '1'
    \\    list domain 'lan'
    \\    list dhcp_option '6,1.1.1.1'
    \\
    \\config odhcpd 'odhcpd'
    \\    option maindhcp '1'
    \\    option leasefile '/tmp/hosts/odhcpd'
    \\
    \\config host 'nas'
    \\    option name 'nas'
    \\    option mac 'aa:bb:cc:dd:ee:ff'
    \\    option ip '192.168.0.5'
    \\
;

test "uci：段/段名/选项计数" {
    var r = try parse(testing.allocator, sample);
    defer r.package.deinit();
    try testing.expectEqual(@as(usize, 0), r.bad_lines);
    try testing.expectEqual(@as(usize, 4), r.package.sections.len);
    try testing.expectEqual(@as(usize, 1), r.package.count("dhcp"));
    try testing.expectEqual(@as(usize, 1), r.package.count("host"));
    try testing.expectEqualStrings("dnsmasq", r.package.sections[0].typ);
    try testing.expectEqual(@as(?[]const u8, null), r.package.sections[0].name);
}

test "uci：get / byName / 列表收集" {
    var r = try parse(testing.allocator, sample);
    defer r.package.deinit();

    const lan = r.package.byName("dhcp", "lan").?;
    try testing.expectEqualStrings("lan", lan.get("interface").?);
    try testing.expectEqualStrings("100", lan.get("start").?);
    try testing.expectEqual(@as(?i64, 100), lan.getInt("start"));
    try testing.expectEqual(@as(?i64, 150), lan.getInt("limit"));
    try testing.expectEqualStrings("server", lan.get("dhcpv4").?);
    try testing.expectEqual(@as(?bool, false), lan.getBool("dhcpv4")); // 模式串不是布尔
    try testing.expectEqual(@as(?bool, true), lan.getBool("force"));
    try testing.expectEqual(@as(?bool, null), lan.getBool("nope"));

    const domains = try lan.collect(testing.allocator, "domain");
    defer testing.allocator.free(domains);
    try testing.expectEqual(@as(usize, 1), domains.len);
    try testing.expectEqualStrings("lan", domains[0]);

    const opts = try lan.collect(testing.allocator, "dhcp_option");
    defer testing.allocator.free(opts);
    try testing.expectEqual(@as(usize, 1), opts.len);
    try testing.expectEqualStrings("6,1.1.1.1", opts[0]);

    const od = r.package.byName("odhcpd", "odhcpd").?;
    try testing.expectEqual(@as(?bool, true), od.getBool("maindhcp"));
    try testing.expectEqualStrings("/tmp/hosts/odhcpd", od.get("leasefile").?);
}

test "uci：无段名与有段名互不串门" {
    var r = try parse(testing.allocator, "config device\n\toption name 'br-lan'\n");
    defer r.package.deinit();
    try testing.expect(r.package.byName("device", null) != null);
    try testing.expect(r.package.byName("device", "br-lan") == null);
}

test "uci：引号规则（单引号原样 / 双引号解转义 / 无引号取到行尾）" {
    var r = try parse(testing.allocator,
        \\config x 'a'
        \\    option s 'raw \n keep'
        \\    option d "say \"hi\" and \\ end"
        \\    option bare hello world   
        \\    option empty ''
        \\    option unclosed 'oops
        \\
    );
    defer r.package.deinit();
    const s = r.package.sections[0];
    // 单引号内不做任何转义处理（libuci 同）
    try testing.expectEqualStrings("raw \\n keep", s.get("s").?);
    // 双引号内 \" -> " 、 \\ -> \
    try testing.expectEqualStrings("say \"hi\" and \\ end", s.get("d").?);
    try testing.expectEqualStrings("hello world", s.get("bare").?);
    try testing.expectEqualStrings("", s.get("empty").?);
    // 引号未闭合：吃到行尾（不报错、不吞掉后面的段）
    try testing.expectEqualStrings("oops", s.get("unclosed").?);
}

test "uci：坏行不致命，只计数，好行照常生效" {
    var r = try parse(testing.allocator,
        \\    option orphan 'x'
        \\config
        \\config dhcp 'lan'
        \\    option start '100'
        \\nonsense keyword here
        \\
    );
    defer r.package.deinit();
    try testing.expectEqual(@as(usize, 3), r.bad_lines);
    try testing.expectEqual(@as(usize, 1), r.package.sections.len);
    try testing.expectEqualStrings("100", r.package.byName("dhcp", "lan").?.get("start").?);
}

test "uci：注释与空行" {
    var r = try parse(testing.allocator,
        \\# 头注释
        \\
        \\   # 缩进的注释
        \\config a
        \\    option k 'v'
        \\
    );
    defer r.package.deinit();
    try testing.expectEqual(@as(usize, 0), r.bad_lines);
    try testing.expectEqualStrings("v", r.package.sections[0].get("k").?);
}

test "uci：boolOf 与 libuci 的布尔字面量一致" {
    try testing.expect(boolOf("1"));
    try testing.expect(boolOf("true"));
    try testing.expect(boolOf("YES"));
    try testing.expect(boolOf("on"));
    try testing.expect(boolOf("enabled"));
    try testing.expect(!boolOf("0"));
    try testing.expect(!boolOf("off"));
    try testing.expect(!boolOf("disabled"));
    try testing.expect(!boolOf(""));
}

test "uci：unescape 只折叠 \\\" 与 \\\\，长度只减不增" {
    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("a\"b", unescape("a\\\"b", &buf));
    try testing.expectEqualStrings("a\\b", unescape("a\\\\b", &buf));
    try testing.expectEqualStrings("a\\nb", unescape("a\\nb", &buf));
    try testing.expectEqualStrings("", unescape("", &buf));
    // 尾部孤立反斜杠原样保留
    try testing.expectEqualStrings("a\\", unescape("a\\", &buf));
}

test "uci：空文本得到空包而不是错误" {
    var r = try parse(testing.allocator, "");
    defer r.package.deinit();
    try testing.expectEqual(@as(usize, 0), r.package.sections.len);
}

test "uci：解析真实 OpenWrt /etc/config/dhcp 的骨架（192.168.0.1 实测内容）" {
    var r = try parse(testing.allocator,
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
        \\    option loglevel '4'
        \\
    );
    defer r.package.deinit();
    const lan = r.package.byName("dhcp", "lan").?;
    try testing.expectEqualStrings("server", lan.get("dhcpv4").?);
    try testing.expectEqual(@as(?i64, 100), lan.getInt("start"));
    try testing.expectEqual(@as(?i64, 150), lan.getInt("limit"));
    try testing.expectEqualStrings("12h", lan.get("leasetime").?);
    const od = r.package.byName("odhcpd", "odhcpd").?;
    try testing.expectEqual(true, od.getBool("maindhcp").?);
    try testing.expectEqual(@as(?i64, 4), od.getInt("loglevel"));
}

test "uci：以真实 TAB 缩进的文件（OpenWrt 生成的就是 TAB）也能解析" {
    // 多行字符串字面量里不能放 TAB（Zig 直接报 invalid byte），
    // 但真实 /etc/config/dhcp 全是 TAB 缩进 —— 所以必须单独用转义写一遍。
    var r = try parse(testing.allocator,
        "config dhcp 'lan'\n" ++
            "\toption interface 'lan'\n" ++
            "\toption start '100'\n" ++
            "\toption limit '150'\n" ++
            "\toption leasetime '12h'\n");
    defer r.package.deinit();
    try testing.expectEqual(@as(usize, 0), r.bad_lines);
    const lan = r.package.byName("dhcp", "lan").?;
    try testing.expectEqual(@as(?i64, 100), lan.getInt("start"));
    try testing.expectEqual(@as(?i64, 150), lan.getInt("limit"));
    try testing.expectEqualStrings("12h", lan.get("leasetime").?);
}

test "uci：文件不存在时返回错误而不是空包（由调用方决定降级）" {
    try testing.expectError(error.FileNotFound, load(testing.allocator, "/nonexistent/uci/dhcp"));
}
