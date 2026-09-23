// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! addr.zig — 地址类型与转换（对应 C 源码 dnsmasq.h 中的 union all_addr / union mysockaddr
//! 以及 util.c 里的 sockaddr_isequal、prettyprint_addr、is_same_net* 等）

const std = @import("std");
const protocol = @import("protocol.zig");

pub const sockaddr = std.posix.sockaddr;
pub const socklen_t = std.posix.socklen_t;
pub const AF = std.posix.AF;

pub const Af = enum { ip4, ip6 };

/// 对应 union all_addr：既能放地址，也能放 CNAME / 日志等缓存负载
pub const AllAddr = union(enum) {
    ip4: u32, // 网络字节序的 struct in_addr
    ip6: [16]u8,
    /// CNAME 目标：可能是另一条缓存记录（uid），也可能是名字
    cname: CnameRef,
    /// 用于缓存 DNSSEC 日志/统计类记录
    log: LogRec,
    /// 任意 RR 的原始内容（去压缩后的 wire RDATA）—— 对应 C 的 addr.rrdata / addr.rrblock。
    /// 本移植用于 SRV / PTR 的正向缓存（F_RR）。
    rr: RrData,
    none: void,

    pub fn eql(a: AllAddr, b: AllAddr) bool {
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
        return switch (a) {
            .ip4 => |v| v == b.ip4,
            .ip6 => |v| std.mem.eql(u8, &v, &b.ip6),
            else => false,
        };
    }
};

/// CNAME 目标名的两种保存方式（对应 C 版 union 里的 target.name / target.cache）：
///
///   is_name_ptr = true  → 用 target_name：目标名**自有**保存，读取时直接返回。
///                         内存由 cacheFree() 负责释放。
///   is_name_ptr = false → 用 target_crec：目标名取自它指向的另一条缓存记录
///                         （C 版正是靠这条链把相邻的 CNAME 串起来）。
pub const CnameRef = struct {
    /// 指向 cache 记录的指针（cache.zig 里的 CRec），未设置时为 null
    target_crec: ?*anyopaque = null,
    /// 自有保存的目标名（is_name_ptr 为 true 时有效，生命周期由 cache 管理）
    target_name: ?[]const u8 = null,
    uid: u32 = 0,
    /// true 表示走 target_name 这条路（对应 C 版的 addr.cname.is_name_ptr）
    is_name_ptr: bool = false,
};

pub const LogRec = struct {
    keytag: u16 = 0,
    algo: u8 = 0,
    digest: u8 = 0,
    rcode: u8 = 0,
    ede: i32 = -1,
};

/// 缓存的任意 RR 内容（对应 C dnsmasq.h 的
/// `struct { unsigned short rrtype, datalen; struct blockdata *rrdata; } rrblock` /
/// `struct datablock { rrtype, datalen, data[] } rrdata`）。
///
/// 差异：C 对「不含域名且 ≤ RR_IMDATALEN」的记录把数据内联在 addr 里、其余走 blockdata，
/// 两者靠 F_KEYTAG 区分；本移植一律堆分配，用 `owned` 标记，淘汰时统一释放。
pub const RrData = struct {
    rrtype: u16 = 0,
    /// wire 格式 RDATA（其中的域名已去压缩、重新编码，可安全拷进别的报文）
    data: []const u8 = &.{},
    /// data 是否为堆分配（cacheFree 时需释放）
    owned: bool = false,
};

/// 对应 union mysockaddr（这里用 sockaddr_storage + 长度）
pub const SockAddr = struct {
    store: sockaddr.storage = undefined,
    len: socklen_t = 0,

    pub fn fromIp4(addr_net: u32, port_num: u16) SockAddr {
        var s = SockAddr{ .len = @sizeOf(sockaddr.in) };
        const p: *sockaddr.in = @ptrCast(&s.store);
        p.* = .{
            .family = AF.INET,
            .port = std.mem.nativeToBig(u16, port_num),
            .addr = addr_net,
            .zero = .{0} ** 8,
        };
        return s;
    }

    pub fn fromIp6(addr: [16]u8, port_num: u16, scope_id: u32) SockAddr {
        var s = SockAddr{ .len = @sizeOf(sockaddr.in6) };
        const p: *sockaddr.in6 = @ptrCast(&s.store);
        p.* = .{
            .family = AF.INET6,
            .port = std.mem.nativeToBig(u16, port_num),
            .flowinfo = 0,
            .addr = addr,
            .scope_id = scope_id,
        };
        return s;
    }

    pub inline fn family(self: *const SockAddr) u16 {
        return self.store.family;
    }

    pub inline fn isIp4(self: *const SockAddr) bool {
        return self.store.family == AF.INET;
    }

    pub inline fn isIp6(self: *const SockAddr) bool {
        return self.store.family == AF.INET6;
    }

    pub fn port(self: *const SockAddr) u16 {
        return switch (self.store.family) {
            AF.INET => std.mem.bigToNative(u16, self.asIn().port),
            AF.INET6 => std.mem.bigToNative(u16, self.asIn6().port),
            else => 0,
        };
    }

    pub fn setPort(self: *SockAddr, port_num: u16) void {
        switch (self.store.family) {
            AF.INET => self.asInMut().port = std.mem.nativeToBig(u16, port_num),
            AF.INET6 => self.asIn6Mut().port = std.mem.nativeToBig(u16, port_num),
            else => {},
        }
    }

    pub inline fn asIn(self: *const SockAddr) *const sockaddr.in {
        return @ptrCast(&self.store);
    }

    pub inline fn asInMut(self: *SockAddr) *sockaddr.in {
        return @ptrCast(&self.store);
    }

    pub inline fn asIn6(self: *const SockAddr) *const sockaddr.in6 {
        return @ptrCast(&self.store);
    }

    pub inline fn asIn6Mut(self: *SockAddr) *sockaddr.in6 {
        return @ptrCast(&self.store);
    }

    pub inline fn ptr(self: *const SockAddr) *const sockaddr {
        return @ptrCast(&self.store);
    }

    pub inline fn mutPtr(self: *SockAddr) *sockaddr {
        return @ptrCast(&self.store);
    }

    /// 取出地址部分（不含端口），IPv4 为网络字节序 u32
    pub fn toAllAddr(self: *const SockAddr) AllAddr {
        return switch (self.store.family) {
            AF.INET => .{ .ip4 = self.asIn().addr },
            AF.INET6 => .{ .ip6 = self.asIn6().addr },
            else => .{ .none = {} },
        };
    }

    /// 对应 util.c: sockaddr_isequal()
    pub fn eql(a: *const SockAddr, b: *const SockAddr) bool {
        if (a.store.family != b.store.family) return false;
        return switch (a.store.family) {
            AF.INET => a.asIn().port == b.asIn().port and a.asIn().addr == b.asIn().addr,
            AF.INET6 => a.asIn6().port == b.asIn6().port and
                std.mem.eql(u8, &a.asIn6().addr, &b.asIn6().addr) and
                a.asIn6().scope_id == b.asIn6().scope_id,
            else => false,
        };
    }

    /// 对应 util.c: sockaddr_isnull()
    pub fn isNull(self: *const SockAddr) bool {
        return switch (self.store.family) {
            AF.INET => self.asIn().addr == 0,
            AF.INET6 => std.mem.allEqual(u8, &self.asIn6().addr, 0),
            else => true,
        };
    }

    /// 对应 util.c: prettyprint_addr()：输出 "1.2.3.4" 或 "1.2.3.4#5353"
    pub fn writeTo(self: *const SockAddr, buf: []u8) []const u8 {
        var n: usize = 0;
        switch (self.store.family) {
            AF.INET => n = writeIp4(buf, self.asIn().addr).len,
            AF.INET6 => n = writeIp6(buf, &self.asIn6().addr).len,
            else => {},
        }
        const p = self.port();
        if (p != 0 and n + 7 < buf.len) {
            buf[n] = '#';
            n += 1;
            n += writeUnsigned(buf[n..], p);
        }
        return buf[0..n];
    }
};

/// 把网络字节序 IPv4 写为点分十进制
pub fn writeIp4(buf: []u8, addr_net: u32) []const u8 {
    const b: [4]u8 = @bitCast(addr_net);
    var n: usize = 0;
    for (b, 0..) |octet, i| {
        n += writeUnsigned(buf[n..], octet);
        if (i != 3) {
            buf[n] = '.';
            n += 1;
        }
    }
    return buf[0..n];
}

/// 把 16 字节 IPv6 写为压缩形式
pub fn writeIp6(buf: []u8, addr: *const [16]u8) []const u8 {
    // 对应 inet_ntop(AF_INET6)：把最长的连续 0 字（>=2 个）压成 "::"
    var words: [8]u16 = undefined;
    for (0..8) |k| words[k] = (@as(u16, addr[k * 2]) << 8) | @as(u16, addr[k * 2 + 1]);

    var best_start: usize = 8;
    var best_len: usize = 0;
    var cur_start: usize = 8;
    var cur_len: usize = 0;
    for (words, 0..) |w, k| {
        if (w == 0) {
            if (cur_len == 0) cur_start = k;
            cur_len += 1;
            if (cur_len > best_len) {
                best_len = cur_len;
                best_start = cur_start;
            }
        } else {
            cur_len = 0;
        }
    }
    // inet_ntop 只在零串长度 >= 2 时才压缩
    if (best_len < 2) {
        best_start = 8;
        best_len = 0;
    }

    var n: usize = 0;
    var k: usize = 0;
    while (k < 8) {
        if (k == best_start) {
            buf[n] = ':';
            n += 1;
            buf[n] = ':';
            n += 1;
            k += best_len;
            if (k >= 8) break;
            continue;
        }
        if (n != 0 and buf[n - 1] != ':') {
            buf[n] = ':';
            n += 1;
        }
        n += writeHexWord(buf[n..], words[k]);
        k += 1;
    }
    return buf[0..n];
}

fn writeHexWord(buf: []u8, word: u16) usize {
    const hex = "0123456789abcdef";
    var n: usize = 0;
    var started = false;
    var shift: i32 = 12;
    while (shift >= 0) : (shift -= 4) {
        const d: u4 = @truncate(@as(u32, word) >> @intCast(shift));
        if (d != 0 or started or shift == 0) {
            buf[n] = hex[d];
            n += 1;
            started = true;
        }
    }
    return n;
}

pub fn writeUnsigned(buf: []u8, value: anytype) usize {
    var tmp: [24]u8 = undefined;
    var v: u64 = @intCast(value);
    var i: usize = tmp.len;
    if (v == 0) {
        buf[0] = '0';
        return 1;
    }
    while (v != 0) {
        i -= 1;
        tmp[i] = '0' + @as(u8, @truncate(v % 10));
        v /= 10;
    }
    const len = tmp.len - i;
    @memcpy(buf[0..len], tmp[i..]);
    return len;
}

// ---------------------------------------------------------------------------
// 地址字符串解析（对应 inet_pton 的用法，自带实现避免依赖 libc）
// ---------------------------------------------------------------------------
pub fn parseIp4(text: []const u8, out: *u32) bool {
    var buf: [4]u8 = undefined;
    var count: usize = 0;

    if (text.len == 0) return false;

    var i: usize = 0;
    while (count < 4) {
        const start = i;
        var part: u32 = 0;
        while (i < text.len and std.ascii.isDigit(text[i])) : (i += 1) {
            if (i - start >= 3) return false;
            part = part * 10 + (text[i] - '0');
            if (part > 255) return false;
        }
        if (i == start) return false;

        buf[count] = @truncate(part);
        count += 1;

        if (i == text.len) break;
        if (text[i] != '.') return false;
        i += 1;
        if (i == text.len) return false;
    }

    if (count != 4 or i != text.len) return false;
    // AllAddr.ip4 采用「地址字节在内存中的原样表示」，与 struct in_addr 一致
    out.* = @bitCast(buf);
    return true;
}

pub fn parseIp6(text: []const u8, out: *[16]u8) bool {
    var head: [16]u8 = [_]u8{0} ** 16;
    var tail: [16]u8 = [_]u8{0} ** 16;
    var head_len: usize = 0;
    var tail_len: usize = 0;
    var seen_double = false;
    var i: usize = 0;

    if (text.len == 0) return false;

    if (text[0] == ':') {
        if (text.len < 2 or text[1] != ':') return false;
        seen_double = true;
        i = 2;
    }

    while (i < text.len) {
        // 读取一个 16 位组
        const group_start = i;
        var digits: usize = 0;
        var value: u16 = 0;
        while (i < text.len and std.ascii.isHex(text[i])) {
            value = (value << 4) | hexVal(text[i]);
            digits += 1;
            if (digits > 4) return false;
            i += 1;
        }

        if (i < text.len and text[i] == '.') {
            // 内嵌 IPv4（如 ::ffff:1.2.3.4）：从本组开头整体按 IPv4 解析
            var v4: u32 = 0;
            if (!parseIp4(text[group_start..], &v4)) return false;
            const bytes: [4]u8 = @bitCast(v4);
            if (seen_double) {
                if (tail_len + 4 > 16) return false;
                @memcpy(tail[tail_len..][0..4], &bytes);
                tail_len += 4;
            } else {
                if (head_len + 4 > 16) return false;
                @memcpy(head[head_len..][0..4], &bytes);
                head_len += 4;
            }
            i = text.len;
            break;
        }
        if (digits == 0) return false;

        if (seen_double) {
            if (tail_len + 2 > 16) return false;
            tail[tail_len] = @truncate(value >> 8);
            tail[tail_len + 1] = @truncate(value);
            tail_len += 2;
        } else {
            if (head_len + 2 > 16) return false;
            head[head_len] = @truncate(value >> 8);
            head[head_len + 1] = @truncate(value);
            head_len += 2;
        }

        if (i == text.len) break;
        if (text[i] != ':') return false;
        i += 1;
        if (i < text.len and text[i] == ':') {
            if (seen_double) return false;
            seen_double = true;
            i += 1;
        } else if (i == text.len) return false;
    }

    if (!seen_double and head_len != 16) return false;
    if (seen_double and head_len + tail_len > 16) return false;

    var result: [16]u8 = [_]u8{0} ** 16;
    @memcpy(result[0..head_len], head[0..head_len]);
    if (seen_double) {
        const off = 16 - tail_len;
        @memcpy(result[off..][0..tail_len], tail[0..tail_len]);
    }
    out.* = result;
    return true;
}

fn hexVal(c: u8) u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => 0,
    };
}

// ---------------------------------------------------------------------------
// 网段判断（对应 util.c: is_same_net / is_same_net6 / netmask_length）
// ---------------------------------------------------------------------------
pub fn netmaskLength(mask_raw: u32) i32 {
    var m = mask_raw;
    var zero_count: i32 = 0;
    while ((m & 1) == 0 and zero_count < 32) {
        m >>= 1;
        zero_count += 1;
    }
    return 32 - zero_count;
}

pub fn isSameNet(a_raw: u32, b_raw: u32, mask_raw: u32) bool {
    return (a_raw & mask_raw) == (b_raw & mask_raw);
}

pub fn isSameNetPrefix(a_net: u32, b_net: u32, prefix: i32) bool {
    if (prefix <= 0) return true;
    if (prefix > 32) return false;
    // 生成掩码后按字节原样比较，避免字节序歧义
    const ab: [4]u8 = @bitCast(a_net);
    const bb: [4]u8 = @bitCast(b_net);
    var bits: i32 = 0;
    while (bits < prefix) : (bits += 8) {
        const idx: usize = @intCast(@divTrunc(bits, 8));
        const remain = prefix - bits;
        if (remain >= 8) {
            if (ab[idx] != bb[idx]) return false;
        } else {
            const shift: u3 = @intCast(8 - remain);
            const m: u8 = @truncate(@as(u16, 0xff) << shift);
            if ((ab[idx] & m) != (bb[idx] & m)) return false;
        }
    }
    return true;
}

pub fn isSameNet6(a: *const [16]u8, b: *const [16]u8, prefixlen: i32) bool {
    if (prefixlen <= 0) return true;
    const bits: i32 = if (prefixlen > 128) 128 else prefixlen;
    var n: i32 = 0;
    while (n < bits) : (n += 8) {
        const remain = bits - n;
        if (remain >= 8) {
            if (a[@intCast(@divTrunc(n, 8))] != b[@intCast(@divTrunc(n, 8))]) return false;
        } else {
            const shift: u3 = @intCast(8 - remain);
            const mask: u8 = @truncate(@as(u16, 0xff) << shift);
            const idx: usize = @intCast(@divTrunc(n, 8));
            if ((a[idx] & mask) != (b[idx] & mask)) return false;
        }
    }
    return true;
}

pub fn addr6Part(addr: *const [16]u8) u64 {
    return std.mem.readInt(u64, addr[8..16], .big);
}

pub fn setAddr6Part(addr: *[16]u8, host: u64) void {
    std.mem.writeInt(u64, addr[8..16], host, .big);
}

/// 判定私网地址（对应 util.c/cache.c 中 private_net 的用法，用于 --bogus-priv 与 rebind 防护）
pub fn privateNet(addr_net: u32, ban_localhost: bool) bool {
    const b: [4]u8 = @bitCast(addr_net);
    const ip = std.mem.readInt(u32, &b, .big); // 对应 ntohl(addr.s_addr)
    return ((ip & 0xFF000000) == 0x7F000000 and ban_localhost) or
        ((ip & 0xFF000000) == 0x00000000 and ban_localhost) or
        ((ip & 0xFF000000) == 0x0A000000) or
        ((ip & 0xFFC00000) == 0x64400000) or
        ((ip & 0xFFF00000) == 0xAC100000) or
        ((ip & 0xFFFF0000) == 0xC0A80000) or
        ((ip & 0xFFFF0000) == 0xA9FE0000) or
        ((ip & 0xFFFFFF00) == 0xC0000200) or
        ((ip & 0xFFFFFF00) == 0xC6336400) or
        ((ip & 0xFFFFFF00) == 0xCB007100) or
        (ip == 0xFFFFFFFF);
}

pub fn privateNet6(a: *const [16]u8, ban_localhost: bool) bool {
    // v4-mapped
    if (isV4Mapped(a)) {
        const v4 = std.mem.readInt(u32, a[12..16], .big);
        return privateNet(v4, ban_localhost);
    }
    const unspecified = std.mem.allEqual(u8, a, 0);
    const link_local = a[0] == 0xFE and (a[1] & 0xC0) == 0x80; // fe80::/10
    const site_local = a[0] == 0xFE and (a[1] & 0xC0) == 0xC0; // fec0::/10
    return (unspecified and ban_localhost) or
        (isLoopback(a) and ban_localhost) or
        link_local or
        site_local or
        ((a[0] & 0xFE) == 0xFC) or // unique local fc00::/7
        (std.mem.readInt(u32, a[0..4], .big) == 0x20010DB8); // 2001:db8::/32
}

pub fn isV4Mapped(a: *const [16]u8) bool {
    return std.mem.allEqual(u8, a[0..10], 0) and a[10] == 0xFF and a[11] == 0xFF;
}

pub fn isLoopback(a: *const [16]u8) bool {
    return std.mem.allEqual(u8, a[0..15], 0) and a[15] == 1;
}

// ---------------------------------------------------------------------------
// 便捷构造
// ---------------------------------------------------------------------------
pub const ANY_IP4: u32 = 0;
pub const ANY_IP6: [16]u8 = [_]u8{0} ** 16;
/// 127.0.0.1（按 struct in_addr 的内存表示）
pub const LOOPBACK_IP4: u32 = @bitCast([4]u8{ 127, 0, 0, 1 });

test "parse and format ipv4" {
    var v: u32 = 0;
    try std.testing.expect(parseIp4("192.168.1.1", &v));
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("192.168.1.1", writeIp4(&buf, v));
    try std.testing.expect(!parseIp4("192.168.1.256", &v));
    try std.testing.expect(!parseIp4("1.2.3", &v));
    var s = SockAddr.fromIp4(v, 5353);
    try std.testing.expectEqual(@as(u16, 5353), s.port());
    try std.testing.expectEqualStrings("192.168.1.1#5353", s.writeTo(&buf));
}

test "parse and format ipv6" {
    var v: [16]u8 = undefined;
    var buf: [64]u8 = undefined;
    // writeIp6 对应 inet_ntop(AF_INET6)：最长零串压缩为 "::"
    try std.testing.expect(parseIp6("2001:db8::1", &v));
    try std.testing.expectEqualStrings("2001:db8::1", writeIp6(&buf, &v));

    try std.testing.expect(parseIp6("::1", &v));
    try std.testing.expect(isLoopback(&v));
    try std.testing.expectEqualStrings("::1", writeIp6(&buf, &v));

    // 没有任何零字 -> 不压缩
    try std.testing.expect(parseIp6("2001:db8:1:2:3:4:5:6", &v));
    try std.testing.expectEqualStrings("2001:db8:1:2:3:4:5:6", writeIp6(&buf, &v));

    // 单个零字不压缩（inet_ntop 只在连续零 >= 2 时压缩）
    try std.testing.expect(parseIp6("2001:db8:0:2:3:4:5:6", &v));
    try std.testing.expectEqualStrings("2001:db8:0:2:3:4:5:6", writeIp6(&buf, &v));

    // 全零
    try std.testing.expect(parseIp6("::", &v));
    try std.testing.expectEqualStrings("::", writeIp6(&buf, &v));

    // 末尾零串压缩（避免出现单个结尾冒号）
    try std.testing.expect(parseIp6("2001:db8::", &v));
    try std.testing.expectEqualStrings("2001:db8::", writeIp6(&buf, &v));

    // 取最长零串（这段有两个候选：一个 2 个 0、一个 3 个 0）
    try std.testing.expect(parseIp6("1:0:0:2:0:0:0:3", &v));
    try std.testing.expectEqualStrings("1:0:0:2::3", writeIp6(&buf, &v));

    // 多个零串等长时取靠前的（inet_ntop 用 > 比较，即首个最长者）
    try std.testing.expect(parseIp6("1:0:0:2:0:0:3:4", &v));
    try std.testing.expectEqualStrings("1::2:0:0:3:4", writeIp6(&buf, &v));
}
