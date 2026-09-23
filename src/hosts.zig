// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! hosts.zig — 复刻 C 源码 src/cache.c 中 read_hostsfile / add_hosts_entry 的功能，
//! 以及 cache_reload 中关于 hosts 文件的部分。
//!
//! 与 C 版本的对应：
//!   * read_hostsfile()  -> readHostsFile()
//!   * add_hosts_entry()  -> addHostEntry()
//!   * cache_reload()     中清除并重新加载 F_HOSTS 记录的部分 -> cacheReload()
//! 名称规范化、正查/反查标记、expand-hosts、注释与别名处理均与 C 保持一致。
//!
//! 注意反查的实现方式：与 C 版一样，hosts 记录**只有一条**，名字即主机名，
//! 同一 cRec 上同时带 F_FORWARD 与 F_REVERSE；并不存在单独的
//! `<nibbles>.in-addr.arpa` 记录。PTR 查询通过按地址扫描缓存命中
//! （`Cache.findByAddr()`，对应 C 的 `cache_find_by_addr()`）。
//! 下面的 buildArpaName() 只用于测试里核对 ip6.arpa 的半字节顺序。

const std = @import("std");
const protocol = @import("protocol.zig");
const addr = @import("addr.zig");
const name = @import("name.zig");
const cache = @import("cache.zig");
const daemon = @import("daemon.zig");
const log = @import("log.zig");

/// --no-hosts 选项标志位。对应 dnsmasq.h 的 OPT_NO_HOSTS（位序号 4）。
/// 注意必须使用 protocol.zig 里与 C 版本编号一致的常量，不要另起一套位。
const OPT_NO_HOSTS: u32 = protocol.OPT_NO_HOSTS;

/// 把单个十六进制半字节（0..15）转为小写字符
fn hexChar(nibble: u8) u8 {
    const chars = "0123456789abcdef";
    const i: usize = @intCast(nibble & 0xf);
    return chars[i];
}

/// 由地址生成反查名字（in-addr.arpa / ip6.arpa）。
/// 对应 C 的 get_domain() / get_domain6() 的逆过程；生产路径上反查不靠这个名字
/// （见文件头说明），这里主要用于测试校验 nibble 顺序，以及调试输出。
/// 结果写入 buf，返回构造出的切片（不含终止符）。
fn buildArpaName(buf: []u8, a: addr.AllAddr) []const u8 {
    var n: usize = 0;

    if (a == .ip4) {
        // 网络字节序的 4 字节，按逆序每个字节写成十进制，再追加 in-addr.arpa
        const b: [4]u8 = @bitCast(a.ip4);
        var i: usize = 3;
        while (true) : (i -= 1) {
            var tmp: [4]u8 = undefined;
            const s = std.fmt.bufPrint(&tmp, "{d}", .{b[i]}) catch "";
            for (s) |ch| {
                buf[n] = ch;
                n += 1;
            }
            if (i == 0) break;
            buf[n] = '.';
            n += 1;
        }
        const suffix = ".in-addr.arpa";
        @memcpy(buf[n..][0..suffix.len], suffix);
        n += suffix.len;
    } else {
        // IPv6：字节逆序，每个字节拆成低/高两个半字节，再追加 ip6.arpa
        const bytes = a.ip6;
        var i: usize = 15;
        while (true) : (i -= 1) {
            const lo: u8 = bytes[i] & 0xf;
            const hi: u8 = bytes[i] >> 4;
            buf[n] = hexChar(lo);
            n += 1;
            buf[n] = '.';
            n += 1;
            buf[n] = hexChar(hi);
            n += 1;
            if (i == 0) break;
            buf[n] = '.';
            n += 1;
        }
        const suffix = ".ip6.arpa";
        @memcpy(buf[n..][0..suffix.len], suffix);
        n += suffix.len;
    }

    return buf[0..n];
}

// ---------------------------------------------------------------------------
// addHostsEntry（对应 C: cache.c: add_hosts_entry）
// ---------------------------------------------------------------------------
/// 往缓存里加一条 hosts 记录，返回新记录（重复则返回已存在的那条）。
///
/// 与 C 版一致的要点（`cache.c: add_hosts_entry()` + `read_hostsfile()`）：
///   * **只**创建一条记录，名字是主机名本身，标志同时带 F_FORWARD 与 F_REVERSE；
///     反查并不存在单独的 `<nibble>.in-addr.arpa` 记录，而是靠按地址扫描
///     （C 的 `cache_find_by_addr()` / 本移植的 `Cache.findByAddr()`）命中。
///   * 因此 PTR 应答里写出的名字就是主机名，而不是 arpa 形式的名字。
///   * 「一个地址只对应一个名字」（first one trumps）：同一地址再有新名字时，
///     新记录不再带 F_REVERSE。
///   * 同一「名字 + 地址」重复出现时直接跳过（C 里会 free 掉新 crec）。
pub fn addHostEntry(c: *cache.Cache, nm: []const u8, a: addr.AllAddr, ttl: u32, now: i64) ?*cache.CRec {
    const addr_flags: u32 = switch (a) {
        .ip4 => protocol.F_IPV4,
        .ip6 => protocol.F_IPV6,
        else => return null,
    };

    // 去重：同名同地址已存在则不再插入（对应 C 的 cache_find_by_name 循环）
    if (c.findByName(nm, now, protocol.F_IPV4 | protocol.F_IPV6 | protocol.F_FORWARD)) |old| {
        if ((old.flags & protocol.F_HOSTS) != 0 and old.addr.eql(a)) return old;
    }

    // 反查唯一性：该地址已有反查记录时，本条不再承担反查（C 里清掉 F_REVERSE）
    var flags = protocol.F_HOSTS | protocol.F_IMMORTAL | protocol.F_FORWARD | addr_flags;
    if (c.findByAddr(a, now, addr_flags) == null) {
        flags |= protocol.F_REVERSE;
    }

    return c.insert(nm, a, protocol.C_IN, now, ttl, flags);
}

// ---------------------------------------------------------------------------
// 文件读取辅助（对应 C: fopen / get_line_alloc）
// ---------------------------------------------------------------------------
/// 用同步 posix 调用把整个文件读入内存；文件不存在或读取失败时返回 null。
fn readTextFile(allocator: std.mem.Allocator, path: []const u8) ?[]u8 {
    const fd = std.posix.openat(std.posix.AT.FDCWD, path, std.posix.O{ .ACCMODE = .RDONLY }, 0) catch {
        log.info("无法读取 hosts/resolv 文件 {s}", .{path});
        return null;
    };
    defer _ = std.posix.system.close(fd);

    var buf: std.ArrayList(u8) = .empty;
    var tmp: [8192]u8 = undefined;
    while (true) {
        const n = std.posix.read(fd, &tmp) catch {
            buf.deinit(allocator);
            return null;
        };
        if (n == 0) break;
        buf.appendSlice(allocator, tmp[0..n]) catch {
            buf.deinit(allocator);
            return null;
        };
    }

    return buf.toOwnedSlice(allocator) catch null;
}

// ---------------------------------------------------------------------------
// read_hostsfile（对应 C: cache.c: read_hostsfile）
// ---------------------------------------------------------------------------
/// 读取一个 hosts 文件并加入缓存，返回加入的名字条数（含 expand-hosts 补的名字）。
/// 文件无法打开时返回 null。
pub fn readHostsFile(
    allocator: std.mem.Allocator,
    path: []const u8,
    c: *cache.Cache,
    d: *daemon.Daemon,
    ttl: u32,
    now: i64,
) ?usize {
    const content = readTextFile(allocator, path) orelse return null;
    defer allocator.free(content);

    var names_done: usize = 0;

    var lines = std.mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        // '#' 起为注释，截断到行尾（对应 C 的 eatspace/gettok 处理）
        const hidx = std.mem.indexOfScalar(u8, line, '#');
        const l = if (hidx) |i| line[0..i] else line;

        var it = std.mem.tokenizeAny(u8, l, " \t");
        const addr_tok = it.next() orelse continue;

        var ip4: u32 = 0;
        var ip6: [16]u8 = undefined;
        var a: addr.AllAddr = undefined;

        if (addr.parseIp4(addr_tok, &ip4)) {
            a = .{ .ip4 = ip4 };
        } else if (addr.parseIp6(addr_tok, &ip6)) {
            a = .{ .ip6 = ip6 };
        } else {
            // 地址非法，跳过整行（对应 C 的“bad address”分支）
            continue;
        }

        while (it.next()) |name_tok| {
            const canon = name.canonicalise(allocator, name_tok) orelse continue;
            defer allocator.free(canon);

            if (addHostEntry(c, canon, a, ttl, now) != null) {
                names_done += 1;
            }

            // --expand-hosts：对不含 '.' 的名字再补一条 名字.domain
            if (d.expand_hosts and d.domain != null and
                std.mem.indexOfScalar(u8, canon, '.') == null)
            {
                const full = std.fmt.allocPrint(
                    allocator,
                    "{s}.{s}",
                    .{ canon, d.domain.? },
                ) catch continue;
                if (addHostEntry(c, full, a, ttl, now) != null) {
                    names_done += 1;
                }
                allocator.free(full);
            }
        }
    }

    return names_done;
}

// ---------------------------------------------------------------------------
// 清除所有 F_HOSTS 记录（cache_reload 的第一步）
// ---------------------------------------------------------------------------
/// 遍历哈希表，释放所有带 F_HOSTS 标志的缓存记录（对应 C cache_reload 开头
/// 的“移除旧的 hosts 记录”逻辑）。
fn clearHosts(c: *cache.Cache) void {
    var bi: usize = 0;
    while (bi < c.hash_table.len) : (bi += 1) {
        var crecp = c.hash_table[bi];
        while (crecp) |cr| {
            const next = cr.hash_next;
            if ((cr.flags & protocol.F_HOSTS) != 0) {
                c.cacheFree(cr);
            }
            crecp = next;
        }
    }
}

// ---------------------------------------------------------------------------
// cache_reload 中关于 hosts 的部分（对应 C: cache.c: cache_reload）
// ---------------------------------------------------------------------------
/// 按 dnsmasq 逻辑加载 /etc/hosts（除非设置了 OPT_NO_HOSTS）以及
/// --addn-hosts 与 --hostsdir 里的文件；会先清掉所有 F_HOSTS 记录再重新加载。
pub fn cacheReload(c: *cache.Cache, d: *daemon.Daemon, now: i64) void {
    clearHosts(c);

    const ttl = d.local_ttl;

    if (!d.option(OPT_NO_HOSTS)) {
        // 默认系统 hosts 文件
        _ = readHostsFile(d.allocator, "/etc/hosts", c, d, ttl, now);
    }

    for (d.addn_hosts.items) |p| {
        _ = readHostsFile(d.allocator, p, c, d, ttl, now);
    }

    // --hostsdir：目录里**每个普通文件**都当 hosts 文件读。
    // 这是 odhcpd → DNS 的接合点（odhcpd 把 `odhcpd.hosts.<ifname>` 写在
    // `/tmp/hosts` 下），也是 `<host>.lan` 能解析的前提。
    for (d.hosts_dirs.items) |dir| {
        scanHostsDir(d.allocator, dir, c, d, ttl, now);
    }
}

/// 扫描一个 `--hostsdir` 目录，逐个读里面的 hosts 文件。
///
/// 跳过规则逐条对照 C `inotify.c:set_dynamic_inotify()`：
///   * 名字为空、以 `~` 结尾（编辑器备份）、`#...#`（Emacs 自动保存）、
///     以 `.` 开头（含 `.` 与 `..`）→ 跳过；
///   * **非普通文件**（目录/FIFO/设备/套接字）→ 跳过。
///
/// `d_type` 由 getdents64 直接给出（偏移 18），所以不必 stat —— 本移植是
/// 静态 musl 不链接 libc，Zig 0.16 的 linux std 里也没有 fstatat。
/// 与 C 的细微差别：C 是 `stat()` 后判 `S_ISREG`，会**跟随符号链接**；
/// 这里 DT_LNK 与 DT_UNKNOWN 都放行（DT_UNKNOWN 的文件系统上只能靠读失败
/// 兜底），行为在 odhcpd 实际写普通文件的场景下等价。
pub fn scanHostsDir(
    allocator: std.mem.Allocator,
    dir_path: []const u8,
    c: *cache.Cache,
    d: *daemon.Daemon,
    ttl: u32,
    now: i64,
) void {
    const fd: std.posix.fd_t = std.posix.openat(
        std.posix.AT.FDCWD,
        dir_path,
        std.posix.O{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true },
        0,
    ) catch {
        // 对应 C 的 "bad dynamic directory"：目录不存在/不是目录只告警不致命
        log.warning("--hostsdir={s} 无法打开（不存在或不是目录），该目录的 hosts 不会生效", .{dir_path});
        return;
    };
    defer _ = std.posix.system.close(fd);

    var buf: [32768]u8 = undefined;
    var pathbuf: [512]u8 = undefined;

    while (true) {
        const n = std.os.linux.getdents64(@intCast(fd), &buf, buf.len);
        if (n <= 0) break;
        const total: usize = @intCast(n);

        var off: usize = 0;
        while (off + 19 <= total) {
            const reclen = std.mem.readInt(u16, buf[off + 16 ..][0..2], .little);
            if (reclen == 0 or off + reclen > total) break;
            const dtype = buf[off + 18];
            const name_start = off + 19;
            var name_end = name_start;
            while (name_end < off + reclen and buf[name_end] != 0) name_end += 1;
            const fname = buf[name_start..name_end];

            if (hostsDirNameWanted(fname) and hostsDirTypeWanted(dtype)) {
                const full = std.fmt.bufPrint(&pathbuf, "{s}/{s}", .{ dir_path, fname }) catch {
                    off += reclen;
                    continue;
                };
                _ = readHostsFile(allocator, full, c, d, ttl, now);
            }
            off += reclen;
        }
    }
}

/// `--hostsdir` 里的文件名是否要读（对照 C: 空名 / `~` 结尾 / `#…#` / `.` 开头都跳过）
fn hostsDirNameWanted(fname: []const u8) bool {
    if (fname.len == 0) return false;
    if (fname[fname.len - 1] == '~') return false; // 编辑器备份 foo~
    if (fname[0] == '.') return false; // 含 "." 与 ".."
    if (fname[0] == '#' and fname[fname.len - 1] == '#') return false; // Emacs 自动保存
    return true;
}

/// `--hostsdir` 里的目录项类型是否要读（对照 C 的 `S_ISREG`）
fn hostsDirTypeWanted(dtype: u8) bool {
    return switch (dtype) {
        DT_REG => true,
        DT_LNK, DT_UNKNOWN => true, // C 的 stat() 会跟随链接；UNKNOWN 交给读失败兜底
        else => false, // DT_DIR / DT_FIFO / DT_CHR / DT_BLK / DT_SOCK
    };
}

/// `struct linux_dirent64` 的 d_type 取值（linux/dirent.h）
const DT_UNKNOWN: u8 = 0;
const DT_REG: u8 = 8;
const DT_LNK: u8 = 10;

// ---------------------------------------------------------------------------
// --hostsdir 的 inotify 监视（对应 C inotify.c 里 AH_HOSTS 那部分）
// ---------------------------------------------------------------------------
/// 监视所有 `--hostsdir` 目录，变了就触发一次 hosts 重载。
///
/// 为什么需要它：odhcpd 每有租约变化就重写 `odhcpd.hosts.<ifname>`，
/// 而 DNS 侧如果不重新读，`<host>.lan` 要等进程重启才出现。
/// C 的做法是 `inotify_add_watch(dir, IN_CLOSE_WRITE|IN_MOVED_TO|IN_DELETE)`
/// （inotify.c:193 `set_dynamic_inotify`），这里照抄同一组掩码。
///
/// 注意 odhcpd 用 `O_TRUNC` 打开再写再关，所以命中的是 **IN_CLOSE_WRITE**；
/// 监视的是**目录**，目录 watch 会把目录内文件的事件报上来。
pub const DirWatcher = struct {
    fd: std.posix.fd_t = -1,
    /// 成功挂上 watch 的目录数；0 表示没有可监视的目录
    n_watched: usize = 0,

    pub fn init(self: *DirWatcher, d: *daemon.Daemon) bool {
        if (d.hosts_dirs.items.len == 0) return false;

        const rc = std.os.linux.inotify_init1(
            std.os.linux.IN.CLOEXEC | std.os.linux.IN.NONBLOCK,
        );
        if (std.posix.errno(rc) != .SUCCESS) {
            log.warning("inotify_init1 失败，--hostsdir 变化不会自动重载（重启才生效）", .{});
            return false;
        }
        self.fd = @intCast(rc);

        var pathz: [512]u8 = undefined;
        for (d.hosts_dirs.items) |dir| {
            if (dir.len + 1 > pathz.len) continue;
            @memcpy(pathz[0..dir.len], dir);
            pathz[dir.len] = 0;
            const wd = std.os.linux.inotify_add_watch(
                @intCast(self.fd),
                pathz[0..dir.len :0],
                std.os.linux.IN.CLOSE_WRITE | std.os.linux.IN.MOVED_TO | std.os.linux.IN.DELETE,
            );
            if (std.posix.errno(wd) == .SUCCESS) {
                self.n_watched += 1;
            } else {
                log.warning("inotify 监视 {s} 失败（该目录变化不会自动重载）", .{dir});
            }
        }

        if (self.n_watched == 0) {
            _ = std.posix.system.close(self.fd);
            self.fd = -1;
            return false;
        }
        return true;
    }

    pub fn deinit(self: *DirWatcher) void {
        if (self.fd >= 0) _ = std.posix.system.close(self.fd);
        self.fd = -1;
    }

    /// 排空挂起的事件。返回 true 表示「有变化，调用方该重载 hosts 了」。
    /// 一次排空会把整个队列读干净，所以同一批写入只会触发一次重载。
    pub fn drain(self: *DirWatcher) bool {
        if (self.fd < 0) return false;
        var buf: [4096]u8 = undefined;
        var got = false;
        while (true) {
            const n = std.posix.system.read(self.fd, &buf, buf.len);
            if (std.posix.errno(n) != .SUCCESS) break;
            if (n == 0) break;
            got = true;
            // 只关心「有没有变」，事件内容（名字/掩码）不需要解析
            if (@as(usize, @intCast(n)) < buf.len) break;
        }
        return got;
    }
};

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------
const testing = std.testing;

fn makeCache(allocator: std.mem.Allocator) !cache.Cache {
    return try cache.Cache.init(allocator, 256);
}

/// 测试辅助：dnsmasq 的反查记录（F_REVERSE）是按地址查找的
/// （C 版本对应 cache_find_by_addr），不是按名字查找。
fn findReverse(c: *cache.Cache, arpa_name: []const u8, now: i64, prot: u32) ?*cache.CRec {
    var a: addr.AllAddr = .{ .none = {} };
    if (name.inArpaName2Addr(arpa_name, &a) == 0) return null;
    return c.findByAddr(a, now, prot);
}

test "addHostEntry 建立正查与反查记录（IPv4）" {
    const allocator = testing.allocator;
    var c = try makeCache(allocator);
    defer c.deinit();

    var a: addr.AllAddr = .{ .ip4 = 0 };
    _ = addr.parseIp4("192.168.1.5", &a.ip4);

    const now: i64 = 1000;
    const fwd = addHostEntry(&c, "host1.example", a, 0, now);
    try testing.expect(fwd != null);

    // 正查记录存在且标志正确
    const found = c.findByName("host1.example", now, protocol.F_FORWARD | protocol.F_HOSTS);
    try testing.expect(found != null);
    try testing.expect((found.?.flags & protocol.F_HOSTS) != 0);
    try testing.expect((found.?.flags & protocol.F_IMMORTAL) != 0);
    try testing.expect((found.?.flags & protocol.F_IPV4) != 0);
    try testing.expect((found.?.flags & protocol.F_FORWARD) != 0);

    // 反查记录：4.3.2.1.in-addr.arpa
    const rev = findReverse(&c, "5.1.168.192.in-addr.arpa", now, protocol.F_REVERSE | protocol.F_IPV4);
    try testing.expect(rev != null);
    try testing.expect((rev.?.flags & protocol.F_REVERSE) != 0);
    // 关键：反查记录的名字是**主机名**（PTR 应答就写它），不是 arpa 形式
    try testing.expectEqualStrings("host1.example", c.getName(rev.?));
    try testing.expect((rev.?.flags & protocol.F_FORWARD) != 0);

    // 按地址反查也能命中
    try testing.expect(c.findByAddr(a, now, protocol.F_REVERSE | protocol.F_IPV4) != null);
    // 同一个 cRec 既是正查也是反查（C 版语义）
    try testing.expectEqual(rev.?, found.?);

    // 同一地址再加一个名字：新记录不再承担反查（first one trumps）
    _ = addHostEntry(&c, "alias1.example", a, 0, now);
    try testing.expectEqualStrings("host1.example", c.getName(c.findByAddr(a, now, protocol.F_REVERSE | protocol.F_IPV4).?));

    // 同名同地址重复插入：直接返回已有记录
    const again = addHostEntry(&c, "host1.example", a, 0, now);
    try testing.expectEqual(found.?, again.?);
}

test "ipv6 反查名生成正确（与 name.inArpaName2Addr 互逆）" {
    const allocator = testing.allocator;
    var c = try makeCache(allocator);
    defer c.deinit();

    var a: addr.AllAddr = .{ .ip6 = [_]u8{0} ** 16 };
    _ = addr.parseIp6("2001:db8::1", &a.ip6);

    var buf: [protocol.MAXDNAME]u8 = undefined;
    const arpa = buildArpaName(&buf, a);

    // 标准 ip6.arpa 形式：以小写十六进制逐位（nibble）逆序排列，后缀 .ip6.arpa
    try testing.expect(std.mem.endsWith(u8, arpa, ".ip6.arpa"));
    // ::1 的最低位 nibble 为 1，故 arpa 以 "1.0" 开头
    try testing.expect(std.mem.startsWith(u8, arpa, "1.0."));
    // 高位字节 20 01 0d b8 逆序对应 "8.b.d.0.1.0.0.2"
    try testing.expect(std.mem.indexOf(u8, arpa, "8.b.d.0.1.0.0.2") != null);

    // 互逆：arpa -> 地址
    var back: addr.AllAddr = .{ .none = {} };
    const kind = name.inArpaName2Addr(arpa, &back);
    try testing.expectEqual(protocol.F_IPV6, kind);
    try testing.expect(std.mem.eql(u8, &a.ip6, &back.ip6));

    // 真插入一条，验证反查命中
    const now: i64 = 1000;
    _ = addHostEntry(&c, "v6host", a, 0, now);
    try testing.expect(findReverse(&c, arpa, now, protocol.F_REVERSE | protocol.F_IPV6) != null);
}

test "readHostsFile 解析含注释/别名/IPv4/IPv6" {
    const allocator = testing.allocator;
    var c = try makeCache(allocator);
    defer c.deinit();

    // 写临时 hosts 文件
    const path = "/tmp/zz_hosts_test.txt";
    const fd = std.posix.openat(std.posix.AT.FDCWD, path, std.posix.O{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
    }, 0o644) catch unreachable;
    defer _ = std.posix.system.close(fd);
    const text =
        "# 这是注释行\n" ++
        "127.0.0.1 localhost localhost2\n" ++
        "192.168.1.10 myhost alias1 # 行尾注释\n" ++
        "::1 v6host\n" ++
        "not.an.ipv4 badname   # 地址非法，整行跳过\n";
    _ = std.posix.system.write(fd, text.ptr, text.len);

    var d: daemon.Daemon = .{ .allocator = allocator };
    const now: i64 = 1000;
    const count = readHostsFile(allocator, path, &c, &d, 0, now);
    // localhost, localhost2, myhost, alias1, v6host = 5
    try testing.expectEqual(@as(?usize, 5), count);

    try testing.expect(c.findByName("localhost", now, protocol.F_FORWARD | protocol.F_HOSTS) != null);
    try testing.expect(c.findByName("alias1", now, protocol.F_FORWARD | protocol.F_HOSTS) != null);
    try testing.expect(c.findByName("v6host", now, protocol.F_FORWARD | protocol.F_HOSTS) != null);
    try testing.expect(c.findByName("myhost", now, protocol.F_FORWARD | protocol.F_HOSTS) != null);

    // IPv4 反查
    try testing.expect(findReverse(&c, "10.1.168.192.in-addr.arpa", now, protocol.F_REVERSE | protocol.F_IPV4) != null);
    // IPv6 反查（::1）：用 buildArpaName 生成，避免手写字面量长度出错
    var r6: addr.AllAddr = .{ .ip6 = [_]u8{0} ** 16 };
    _ = addr.parseIp6("::1", &r6.ip6);
    var rbuf: [protocol.MAXDNAME]u8 = undefined;
    const rarpa = buildArpaName(&rbuf, r6);
    try testing.expect(findReverse(&c, rarpa, now, protocol.F_REVERSE | protocol.F_IPV6) != null);
}

test "cacheReload 先清除 F_HOSTS 再重载" {
    const allocator = testing.allocator;
    var c = try makeCache(allocator);
    defer c.deinit();

    var d: daemon.Daemon = .{ .allocator = allocator };
    defer d.deinit();

    // 额外 hosts 文件
    const path = "/tmp/zz_hosts_reload.txt";
    const fd = std.posix.openat(std.posix.AT.FDCWD, path, std.posix.O{
        .ACCMODE = .WRONLY,
        .CREAT = true,
        .TRUNC = true,
    }, 0o644) catch unreachable;
    defer _ = std.posix.system.close(fd);
    _ = std.posix.system.write(fd, "10.0.0.1 reloadedhost\n".ptr, "10.0.0.1 reloadedhost\n".len);
    const p = try allocator.dupe(u8, path);
    try d.addn_hosts.append(allocator, p);

    const now: i64 = 1000;
    var old: addr.AllAddr = .{ .ip4 = 0 };
    _ = addr.parseIp4("172.16.0.9", &old.ip4);
    _ = addHostEntry(&c, "manual.example", old, 0, now);
    try testing.expect(c.findByName("manual.example", now, protocol.F_FORWARD | protocol.F_HOSTS) != null);

    // 设 OPT_NO_HOSTS，避免去读系统 /etc/hosts
    d.setOpt(OPT_NO_HOSTS);
    cacheReload(&c, &d, now);

    // 旧的手动记录应被清除
    try testing.expect(c.findByName("manual.example", now, protocol.F_FORWARD | protocol.F_HOSTS) == null);
    // 新加载的记录应存在
    try testing.expect(c.findByName("reloadedhost", now, protocol.F_FORWARD | protocol.F_HOSTS) != null);
    try testing.expect(findReverse(&c, "1.0.0.10.in-addr.arpa", now, protocol.F_REVERSE | protocol.F_IPV4) != null);
}

test "--hostsdir：读目录里的每个普通文件，且按 C 的规则跳过备份/隐藏/子目录" {
    // 这就是 odhcpd → DNS 的接合点：odhcpd 把 `odhcpd.hosts.<ifname>`
    // 写进这个目录，DNS 用 --hostsdir 把它读进来，`<host>.lan` 才能解析。
    const allocator = testing.allocator;

    _ = std.os.linux.mkdir(".zig-cache", 0o755);
    _ = std.os.linux.mkdir(".zig-cache/zd-hostsdir", 0o755);
    const dir = ".zig-cache/zd-hostsdir";

    const S = struct {
        fn write(path: []const u8, text: []const u8) void {
            const fd = std.posix.openat(std.posix.AT.FDCWD, path, std.posix.O{
                .ACCMODE = .WRONLY,
                .CREAT = true,
                .TRUNC = true,
            }, 0o644) catch return;
            defer _ = std.posix.system.close(fd);
            _ = std.posix.system.write(fd, text.ptr, text.len);
        }
    };

    // 应被读入
    S.write(dir ++ "/odhcpd.hosts.br-lan", "192.168.0.244\tdebian\n192.168.0.101\tRedmi-phone\n");
    // 应被跳过（对照 C set_dynamic_inotify 的过滤规则）
    S.write(dir ++ "/.hidden", "10.0.0.1 hiddenhost\n");
    S.write(dir ++ "/odhcpd.hosts.bak~", "10.0.0.2 backuphost\n");
    S.write(dir ++ "/#auto#", "10.0.0.3 autohost\n");
    // 子目录：DT_DIR，必须跳过
    _ = std.os.linux.mkdir(dir ++ "/sub", 0o755);
    S.write(dir ++ "/sub/odhcpd.hosts.x", "10.0.0.4 subhost\n");

    var c = try makeCache(allocator);
    defer c.deinit();
    var d: daemon.Daemon = .{ .allocator = allocator };
    defer d.deinit();

    try d.hosts_dirs.append(allocator, try allocator.dupe(u8, dir));
    d.setOpt(OPT_NO_HOSTS);
    // --expand-hosts + domain=lan：裸名 `debian` 要同时得到 `debian.lan`。
    // domain 必须 dupe —— Daemon.deinit 会 `allocator.free(self.domain)`，
    // 直接塞字面量会在 deinit 时踩 debug allocator 的 Invalid free。
    d.expand_hosts = true;
    d.domain = try allocator.dupe(u8, "lan");

    const now: i64 = 1000;
    cacheReload(&c, &d, now);

    const F = protocol.F_FORWARD | protocol.F_HOSTS;
    // 目录里的正常文件读到了
    try testing.expect(c.findByName("debian", now, F) != null);
    try testing.expect(c.findByName("Redmi-phone", now, F) != null);
    // expand-hosts：`debian.lan` 也能解析（≤ 用不带域名去查同一个地址）
    try testing.expect(c.findByName("debian.lan", now, F) != null);
    // 跳过规则生效
    try testing.expect(c.findByName("hiddenhost", now, F) == null);
    try testing.expect(c.findByName("backuphost", now, F) == null);
    try testing.expect(c.findByName("autohost", now, F) == null);
    // 子目录里的文件不能被读（否则会沿着目录树到处读）
    try testing.expect(c.findByName("subhost", now, F) == null);
}

test "--hostsdir：跳过规则与文件类型判定" {
    // 名字规则（对照 C：空名 / ~ 结尾 / #…# / . 开头）
    try testing.expect(!hostsDirNameWanted(""));
    try testing.expect(!hostsDirNameWanted(".hidden"));
    try testing.expect(!hostsDirNameWanted("."));
    try testing.expect(!hostsDirNameWanted(".."));
    try testing.expect(!hostsDirNameWanted("odhcpd.hosts.br-lan~"));
    try testing.expect(!hostsDirNameWanted("#auto#"));
    try testing.expect(hostsDirNameWanted("odhcpd.hosts.br-lan"));
    try testing.expect(hostsDirNameWanted("hosts"));
    // 名字里含 # 但不是首尾包裹的，不该被误杀
    try testing.expect(hostsDirNameWanted("a#b"));

    // 类型规则（对照 C 的 S_ISREG）
    try testing.expect(hostsDirTypeWanted(DT_REG));
    try testing.expect(hostsDirTypeWanted(DT_UNKNOWN)); // 交给读失败兜底
    try testing.expect(hostsDirTypeWanted(DT_LNK)); // C 的 stat() 会跟随链接
    try testing.expect(!hostsDirTypeWanted(4)); // DT_DIR
    try testing.expect(!hostsDirTypeWanted(1)); // DT_FIFO
    try testing.expect(!hostsDirTypeWanted(6)); // DT_BLK
    try testing.expect(!hostsDirTypeWanted(12)); // DT_SOCK
}

test "--hostsdir：目录不存在时只告警不崩" {
    const allocator = testing.allocator;
    var c = try makeCache(allocator);
    defer c.deinit();
    var d: daemon.Daemon = .{ .allocator = allocator };
    defer d.deinit();

    try d.hosts_dirs.append(allocator, try allocator.dupe(u8, "/nonexistent/zd-hostsdir-xyz"));
    d.setOpt(OPT_NO_HOSTS);

    // 不该 panic / 不该有任何记录
    cacheReload(&c, &d, 1000);
    try testing.expect(c.findByName("anything", 1000, protocol.F_FORWARD | protocol.F_HOSTS) == null);
}
