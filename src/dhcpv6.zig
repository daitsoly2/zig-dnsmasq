// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! dhcpv6.zig —— DHCPv6 报文编解码（RFC 8415）。
//!
//! ## 定位
//!
//! 与 `dhcpv4.zig` 同样的分工：这里**只有纯函数**（字节进出 + 纯逻辑），
//! socket 与事件循环在 `odhcpd_main.zig` 的 v6 运行时里。每个字段都能指回
//! RFC 8415 的节号，测试逐字节断言。
//!
//! ## 报文骨架
//!
//! ```text
//! 0        8        16       24        32
//! +--------+--------+--------+--------+
//! | type   |   transaction-id (24bit) |   固定 4 字节头（无 checksum，UDP 547/548）
//! +--------+--------------------------+
//! | options ...                       |   每个 option = code(16) len(16) data
//! +-----------------------------------+
//! ```
//!
//! 与 DHCPv4 的最大分野：**没有广播**，客户端永远从链路本地地址发包；
//! 服务器应答也发回客户端的链路本地地址 —— 所以不需要 ARP 那套把戏，
//! 但 socket 必须 `IPV6_RECVPKTINFO`（要知道从哪块网卡进的，v6 里这是
//! scope_id 的一部分）。

const std = @import("std");

pub const SERVER_PORT: u16 = 547;
pub const CLIENT_PORT: u16 = 546;

/// RFC 8415 §Table 3 的报文类型
pub const MsgType = enum(u8) {
    solicit = 1,
    advertise = 2,
    request = 3,
    confirm = 4,
    renew = 5,
    rebind = 6,
    reply = 7,
    release = 8,
    decline = 9,
    reconfigure = 10,
    info_request = 11,
    relay_forw = 12,
    relay_repl = 13,
};

/// RFC 8415 §24.3 的 option 码（本移植用到的）
pub const Opt = struct {
    pub const client_id: u16 = 1;
    pub const server_id: u16 = 2;
    pub const ia_na: u16 = 3;
    pub const ia_ta: u16 = 4;
    pub const iaaddr: u16 = 5;
    pub const oro: u16 = 6;
    pub const preference: u16 = 7;
    pub const elapsed_time: u16 = 8;
    pub const status_code: u16 = 13;
    pub const rapid_commit: u16 = 14;
    pub const dns_servers: u16 = 23;
    pub const domain_search: u16 = 24;
    pub const ia_pd: u16 = 25;
    pub const iaprefix: u16 = 26;
    pub const ntp_server: u16 = 56;
};

/// Status Code（RFC 8415 §24.4）的 code 值
pub const Status = struct {
    pub const success: u16 = 0;
    pub const no_addrs_avail: u16 = 2;
    pub const not_on_link: u16 = 4;
    pub const use_multicast: u16 = 5;
    pub const no_binding: u16 = 3;
};

/// 一个 option 的解析结果（data 指向原缓冲，零拷贝）
pub const RawOpt = struct {
    code: u16,
    data: []const u8,
};

pub const ParsedMsg = struct {
    msg_type: MsgType,
    /// 3 字节事务号，应答时原样回显
    tid: [3]u8,
    opts: []RawOpt,

    pub fn find(self: *const ParsedMsg, code: u16) ?[]const u8 {
        for (self.opts) |o| {
            if (o.code == code) return o.data;
        }
        return null;
    }

    /// ORO（option request option）里客户端点名要的 option 码
    pub fn wants(self: *const ParsedMsg, code: u16) bool {
        const oro = self.find(Opt.oro) orelse return false;
        var i: usize = 0;
        while (i + 2 <= oro.len) : (i += 2) {
            if (std.mem.readInt(u16, oro[i..][0..2], .big) == code) return true;
        }
        return false;
    }

    pub fn hasRapidCommit(self: *const ParsedMsg) bool {
        return self.find(Opt.rapid_commit) != null;
    }
};

pub const ParseError = error{ TooShort, BadTid };

/// 解析 4 字节头 + option TLV 链。`opts_out` 由调用方提供（栈上数组即可）。
/// 截断/畸形的 option 直接截断在该处（与 odhcpd 一样宽容），头不全才算错。
pub fn parse(buf: []const u8, opts_out: []RawOpt) ParseError!ParsedMsg {
    if (buf.len < 4) return error.TooShort;
    const mt: ?MsgType = if (buf[0] >= 1 and buf[0] <= 13) @enumFromInt(buf[0]) else null;
    if (mt == null) return error.TooShort; // 不认识的类型整体丢弃
    var tid: [3]u8 = undefined;
    @memcpy(&tid, buf[1..4]);

    var n: usize = 0;
    var off: usize = 4;
    while (off + 4 <= buf.len and n < opts_out.len) {
        const code = std.mem.readInt(u16, buf[off..][0..2], .big);
        const len = std.mem.readInt(u16, buf[off + 2 ..][0..2], .big);
        off += 4;
        if (off + len > buf.len) break; // 截断，丢弃残包
        opts_out[n] = .{ .code = code, .data = buf[off..][0..len] };
        n += 1;
        off += len;
    }
    return .{ .msg_type = mt.?, .tid = tid, .opts = opts_out[0..n] };
}

// ---------------------------------------------------------------------------
// IA_NA / IAADDR 的拆装
// ---------------------------------------------------------------------------

pub const IaNa = struct {
    iaid: u32,
    t1: u32,
    t2: u32,
};

/// IA_NA option 数据 = iaid(4) t1(4) t2(4) + 子 option（IAADDR...）
pub fn parseIaNa(data: []const u8) ?IaNa {
    if (data.len < 12) return null;
    return .{
        .iaid = std.mem.readInt(u32, data[0..4], .big),
        .t1 = std.mem.readInt(u32, data[4..8], .big),
        .t2 = std.mem.readInt(u32, data[8..12], .big),
    };
}

/// IAADDR 数据 = addr(16) preferred(4) valid(4)。子 option 忽略。
pub const IaAddr = struct {
    addr: [16]u8,
    preferred: u32,
    valid: u32,
};

pub fn parseIaAddr(data: []const u8) ?IaAddr {
    if (data.len < 24) return null;
    var out: IaAddr = undefined;
    @memcpy(&out.addr, data[0..16]);
    out.preferred = std.mem.readInt(u32, data[16..20], .big);
    out.valid = std.mem.readInt(u32, data[20..24], .big);
    return out;
}

pub fn iaAddrBytes(addr: [16]u8, preferred: u32, valid: u32) [24]u8 {
    var b: [24]u8 = undefined;
    @memcpy(b[0..16], &addr);
    std.mem.writeInt(u32, b[16..20], preferred, .big);
    std.mem.writeInt(u32, b[20..24], valid, .big);
    return b;
}

// ---------------------------------------------------------------------------
// 写出
// ---------------------------------------------------------------------------

/// 往 buf 里追加 option。返回写入的 option 起始偏移没意义，调用方只关心
/// 总长度，所以直接返回 void；写不下就丢弃（与 v4 的 builder 行为一致）。
pub fn appendOpt(buf: []u8, off: *usize, code: u16, data: []const u8) void {
    if (off.* + 4 + data.len > buf.len) return;
    std.mem.writeInt(u16, buf[off.*..][0..2], code, .big);
    std.mem.writeInt(u16, buf[off.* + 2 ..][0..2], @intCast(data.len), .big);
    @memcpy(buf[off.* + 4 ..][0..data.len], data);
    off.* += 4 + data.len;
}

pub fn appendU16Opt(buf: []u8, off: *usize, code: u16, v: u16) void {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, v, .big);
    appendOpt(buf, off, code, &b);
}

pub fn appendU32Opt(buf: []u8, off: *usize, code: u16, v: u32) void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .big);
    appendOpt(buf, off, code, &b);
}

/// 报文头（type + tid）
pub fn appendHeader(buf: []u8, off: *usize, mt: MsgType, tid: [3]u8) void {
    buf[off.*] = @intFromEnum(mt);
    @memcpy(buf[off.* + 1 ..][0..3], &tid);
    off.* += 4;
}

/// DUID-LL（type 3）: kind(2)=3 htype(2)=1(ethernet) mac(6)
pub fn duidLL(out: *[10]u8, mac: [6]u8) []const u8 {
    std.mem.writeInt(u16, out[0..2], 3, .big);
    std.mem.writeInt(u16, out[2..4], 1, .big);
    @memcpy(out[4..10], &mac);
    return out[0..10];
}

/// DNS 搜索域（option 24）的编码：每个域名的标签序列 + 0 结尾。
/// 多个域名直接顺序拼接（RFC 1035 格式，无压缩）。
pub fn encodeDomainList(buf: []u8, domains: []const []const u8) []const u8 {
    var n: usize = 0;
    for (domains) |d| {
        var it = std.mem.splitScalar(u8, d, '.');
        while (it.next()) |label| {
            if (label.len == 0 or label.len > 63) continue;
            if (n + 1 + label.len > buf.len) return buf[0..n];
            buf[n] = @intCast(label.len);
            n += 1;
            @memcpy(buf[n..][0..label.len], label);
            n += label.len;
        }
        if (n < buf.len) {
            buf[n] = 0;
            n += 1;
        }
    }
    return buf[0..n];
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

const t = std.testing;

test "dhcpv6：解析 Solicit（client-id + IA_NA + rapid commit）" {
    var buf: [128]u8 = undefined;
    var off: usize = 0;
    appendHeader(&buf, &off, .solicit, .{ 0x12, 0x34, 0x56 });
    const duid = [_]u8{ 0, 1, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    appendOpt(&buf, &off, Opt.client_id, &duid);
    const iana = [_]u8{ 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0 } ++ (iaAddrBytes(
        .{ 0x20, 0x01 } ++ [_]u8{0} ** 14,
        0,
        0,
    ));
    appendOpt(&buf, &off, Opt.ia_na, iana[0..12]);
    appendOpt(&buf, &off, Opt.rapid_commit, "");
    var oro: [2]u8 = undefined;
    std.mem.writeInt(u16, &oro, Opt.dns_servers, .big);
    appendOpt(&buf, &off, Opt.oro, &oro);

    var opts: [16]RawOpt = undefined;
    const m = try parse(buf[0..off], &opts);
    try t.expectEqual(MsgType.solicit, m.msg_type);
    try t.expectEqualSlices(u8, &.{ 0x12, 0x34, 0x56 }, &m.tid);
    try t.expectEqualSlices(u8, &duid, m.find(Opt.client_id).?);
    try t.expect(m.hasRapidCommit());
    try t.expect(m.wants(Opt.dns_servers));
    try t.expect(!m.wants(Opt.ntp_server));
    const ia = parseIaNa(m.find(Opt.ia_na).?);
    try t.expectEqual(@as(u32, 1), ia.?.iaid);
}

test "dhcpv6：截断与垃圾包必须被拒/截断而不是越界" {
    var opts: [16]RawOpt = undefined;
    // 太短
    try t.expectError(error.TooShort, parse(&.{1, 2, 3}, &opts));
    // option 长度超出包 -> 截断在该处，不算错误
    var buf: [16]u8 = undefined;
    var off: usize = 0;
    appendHeader(&buf, &off, .info_request, .{ 1, 2, 3 });
    buf[off] = 0;
    buf[off + 1] = 23;
    buf[off + 2] = 0xff;
    buf[off + 3] = 0xff;
    off += 4;
    const m = try parse(buf[0..off], &opts);
    try t.expectEqual(@as(usize, 0), m.opts.len);
    // 不认识的报文类型
    try t.expectError(error.TooShort, parse(&.{ 99, 1, 2, 3 }, &opts));
}

test "dhcpv6：IAADDR 与 DUID-LL 的字节序" {
    const addr: [16]u8 = .{ 0x20, 0x01, 0xdb, 0x80 } ++ [_]u8{0} ** 11 ++ .{0x01};
    const b = iaAddrBytes(addr, 2700, 5400);
    try t.expectEqualSlices(u8, &addr, b[0..16]);
    try t.expectEqual(@as(u32, 2700), std.mem.readInt(u32, b[16..20], .big));
    try t.expectEqual(@as(u32, 5400), std.mem.readInt(u32, b[20..24], .big));

    var duid: [10]u8 = undefined;
    const d = duidLL(&duid, .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff });
    try t.expectEqual(@as(u16, 3), std.mem.readInt(u16, d[0..2], .big)); // DUID-LL
    try t.expectEqual(@as(u16, 1), std.mem.readInt(u16, d[2..4], .big)); // ethernet
    try t.expectEqualSlices(u8, &.{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, d[4..10]);
}

test "dhcpv6：搜索域编码（RFC1035 标签格式）" {
    var buf: [128]u8 = undefined;
    const enc = encodeDomainList(&buf, &.{"lan"});
    try t.expectEqualSlices(u8, &.{ 3, 'l', 'a', 'n', 0 }, enc);
    const enc2 = encodeDomainList(&buf, &.{ "lan", "example.com" });
    try t.expectEqualSlices(u8, &.{ 3, 'l', 'a', 'n', 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 }, enc2);
}
