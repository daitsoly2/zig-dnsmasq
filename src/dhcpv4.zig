// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! dhcpv4.zig —— DHCPv4 报文的编解码与地址分配（**纯逻辑，不碰 socket**）。
//!
//! ## 为什么单独拆出来
//!
//! 报文格式错一个字节，客户端就会静默不续约，而在路由器上抓包定位极其麻烦。
//! 所以把「构造/解析报文」和「分配地址」这两件事做成**无副作用、可逐字节断言**
//! 的纯函数，socket 与事件循环留给 odhcpd_main.zig。这样绝大多数正确性都能在
//! `zig build test` 里用黄金字节串钉死。
//!
//! ## 对照对象
//!
//! 行为而不是代码照抄 dnsmasq 的 rfc2131.c（3267 行、耦合了 daemon 全局状态），
//! 而是**复刻 odhcpd 的 dhcpv4.c**（1668 行、无全局状态、逻辑线性）：
//!   * 常量取自 odhcpd/src/dhcpv4.h
//!   * 应答目标地址决策 = odhcpd `dhcpv4_set_dest_addr()`（dhcpv4.c:702-770）
//!   * 选项集合与顺序参考 odhcpd 的 iov 表（dhcpv4.c:860-940）
//!
//! ## 与 C 的差异
//!
//!   * 地址一律用 `[4]u8` 保存网络字节序，不转 host order —— 这个移植里所有
//!     「逐字节 A/B」的经验都表明，host/network order 的来回转换是 bug 温床。
//!     需要比较/运算时显式用 `ipToU32`/`u32ToIp`。
//!   * 不复刻 BOOTP 兼容路径（odhcpd 也不支持 BOOTP）。

const std = @import("std");

// ---------------------------------------------------------------------------
// 常量（对照 odhcpd/src/dhcpv4.h:25-110）
// ---------------------------------------------------------------------------

pub const CLIENT_PORT: u16 = 68;
pub const SERVER_PORT: u16 = 67;

/// RFC951/1542/2131：报文不足 300 字节时要用 PAD 补齐
pub const MIN_PACKET_SIZE: usize = 300;

/// BOOTP 固定头长度（到 magic cookie 之前）
pub const HEADER_LEN: usize = 236;
/// magic cookie 长度
pub const COOKIE_LEN: usize = 4;

pub const FLAG_BROADCAST: u16 = 0x8000;

/// 最大可分配掩码长度（odhcpd 限制池不能比 /28 还小）
pub const MAX_PREFIX_LEN: u8 = 28;

pub const Op = enum(u8) {
    bootrequest = 1,
    bootreply = 2,
};

/// RFC2132 message type。只列常用值，其余按原样保留在报文中。
pub const Msg = enum(u8) {
    discover = 1,
    offer = 2,
    request = 3,
    decline = 4,
    ack = 5,
    nak = 6,
    release = 7,
    inform = 8,
    _,
};

pub const Opt = struct {
    pub const pad: u8 = 0;
    pub const netmask: u8 = 1;
    pub const router: u8 = 3;
    pub const dnsserver: u8 = 6;
    pub const hostname: u8 = 12;
    pub const domain: u8 = 15;
    pub const mtu: u8 = 26;
    pub const broadcast: u8 = 28;
    pub const requested_ip: u8 = 50;
    pub const lease_time: u8 = 51;
    pub const message: u8 = 53;
    pub const server_id: u8 = 54;
    pub const req_opts: u8 = 55;
    pub const max_msg_size: u8 = 57;
    pub const t1: u8 = 58;
    pub const t2: u8 = 59;
    pub const client_id: u8 = 61;
    pub const end: u8 = 255;
};

/// RFC2132 规定的 MAGIC COOKIE
pub const MAGIC: [4]u8 = .{ 99, 130, 83, 99 };

/// 广播/零点地址
pub const IP_ANY: [4]u8 = .{ 0, 0, 0, 0 };
pub const IP_BROADCAST: [4]u8 = .{ 255, 255, 255, 255 };

// ---------------------------------------------------------------------------
// 地址小工具
// ---------------------------------------------------------------------------

/// 把 4 字节网络序转成可比较的 u32（**host order 的数值**，只用于比较/加减）。
pub fn ipToU32(ip: [4]u8) u32 {
    return (@as(u32, ip[0]) << 24) | (@as(u32, ip[1]) << 16) | (@as(u32, ip[2]) << 8) | @as(u32, ip[3]);
}

pub fn u32ToIp(v: u32) [4]u8 {
    return .{ @truncate(v >> 24), @truncate(v >> 16), @truncate(v >> 8), @truncate(v) };
}

pub fn ipIsZero(ip: [4]u8) bool {
    return ipToU32(ip) == 0;
}

/// 由 IP + 掩码求网络号
pub fn networkOf(ip: [4]u8, netmask: [4]u8) [4]u8 {
    const a = ipToU32(ip);
    const m = ipToU32(netmask);
    return u32ToIp(a & m);
}

/// 由 IP + 掩码求广播地址
pub fn broadcastOf(ip: [4]u8, netmask: [4]u8) [4]u8 {
    const a = ipToU32(ip);
    const m = ipToU32(netmask);
    return u32ToIp(a | ~m);
}

/// 掩码位数（例如 255.255.255.0 -> 24）。非连续掩码返回 null。
pub fn maskPrefixLen(netmask: [4]u8) ?u8 {
    const m = ipToU32(netmask);
    var seen_zero = false;
    var n: u8 = 0;
    var i: u5 = 0;
    while (true) : (i += 1) {
        const bit = (m >> (31 - i)) & 1;
        if (bit == 1) {
            if (seen_zero) return null; // 中间出现 0 又出现 1 -> 非连续
            n += 1;
        } else seen_zero = true;
        if (i == 31) break;
    }
    return n;
}

/// 点分十进制文本 -> 4 字节。允许省略段（"192.168.1" -> 192.168.1.0）。
pub fn parseIpv4(text: []const u8) ?[4]u8 {
    var out = IP_ANY;
    var idx: usize = 0;
    var it = std.mem.tokenizeScalar(u8, text, '.');
    while (it.next()) |part| {
        if (idx >= 4) return null;
        if (part.len == 0 or part.len > 3) return null;
        var v: u32 = 0;
        for (part) |c| {
            if (c < '0' or c > '9') return null;
            v = v * 10 + (c - '0');
        }
        if (v > 255) return null;
        out[idx] = @intCast(v);
        idx += 1;
    }
    if (idx == 0) return null;
    return out;
}

/// 4 字节 -> 点分十进制，写入调用方缓冲，返回切片
pub fn ipText(ip: [4]u8, buf: []u8) []const u8 {
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] }) catch buf[0..0];
}

/// 从文本解析 MAC（`aa:bb:cc:dd:ee:ff` 或 `aa-bb-...`）。返回 (字节数组, 长度)。
/// 只支持 6 字节 Ethernet —— odhcpd 的 dhcpv4 也只处理 ARPHRD_ETHER。
pub fn parseMac(text: []const u8) ?[6]u8 {
    var out: [6]u8 = undefined;
    var idx: usize = 0;
    var i: usize = 0;
    while (i < text.len) {
        if (idx >= 6) return null;
        if (i + 2 > text.len) return null;
        const hi = std.fmt.charToDigit(text[i], 16) catch return null;
        const lo = std.fmt.charToDigit(text[i + 1], 16) catch return null;
        out[idx] = (@as(u8, hi) << 4) | @as(u8, lo);
        idx += 1;
        i += 2;
        if (i < text.len) {
            const sep = text[i];
            if (sep != ':' and sep != '-') return null;
            i += 1;
        }
    }
    if (idx != 6) return null;
    return out;
}

/// 比较两个 MAC 的长度+内容（chaddr 的 hlen 可能不是 6）
pub fn macEqual(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    // 逐个字节显式比较，避免任何填充字节参与
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        if (a[i] != b[i]) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// 报文
// ---------------------------------------------------------------------------

/// 定长部分的长度（不含 options）
pub const Fixed = 236;

/// 一条解析出来的选项
pub const Option = struct {
    code: u8,
    data: []const u8,
};

/// 解析后的 DHCPv4 报文。地址字段保持**网络字节序的原始 4 字节**。
pub const Message = struct {
    op: u8 = 0,
    htype: u8 = 0,
    hlen: u8 = 0,
    hops: u8 = 0,
    xid: [4]u8 = .{ 0, 0, 0, 0 },
    secs: u16 = 0,
    flags: u16 = 0,
    ciaddr: [4]u8 = IP_ANY,
    yiaddr: [4]u8 = IP_ANY,
    siaddr: [4]u8 = IP_ANY,
    giaddr: [4]u8 = IP_ANY,
    chaddr: [16]u8 = [_]u8{0} ** 16,
    /// 报文里 hlen 声称的硬件地址长度（解析时按 hlen 截取，且不超过 16）
    sname: [64]u8 = [_]u8{0} ** 64,
    file: [128]u8 = [_]u8{0} ** 128,
    /// options 区（不含 magic cookie），仅在解析出的报文里有效
    opts: []const u8 = &.{},

    pub fn chaddrSlice(self: *const Message) []const u8 {
        const n = @min(@as(usize, self.hlen), 16);
        return self.chaddr[0..n];
    }

    pub fn msgType(self: *const Message) u8 {
        return self.optionU8(Opt.message) orelse 0;
    }

    /// 找第一条指定 code 且长度 >= minsize 的选项。找不到返回 null。
    ///
    /// `minsize` 对应 C 的 `option_find(mess, size, opt_type, minsize)`
    /// （rfc2131.c:1976 `option_find1`）末尾的 `opt_len >= minsize` 判断 ——
    /// 客户端可能把 4 字节地址选项写成长度 3，那种必须当「没有这个选项」处理，
    /// 而不是读到越界字节。
    pub fn findOptionMin(self: *const Message, code: u8, minsize: usize) ?[]const u8 {
        var it = self.optIter();
        while (it.next()) |o| {
            if (o.code == code and o.data.len >= minsize) return o.data;
        }
        return null;
    }

    pub fn findOption(self: *const Message, code: u8) ?[]const u8 {
        return self.findOptionMin(code, 0);
    }

    /// 同 code 可能出现多次（例如多个 router 选项），返回计数
    pub fn countOption(self: *const Message, code: u8) usize {
        var n: usize = 0;
        var it = self.optIter();
        while (it.next()) |o| {
            if (o.code == code) n += 1;
        }
        return n;
    }

    pub fn optionU8(self: *const Message, code: u8) ?u8 {
        const d = self.findOptionMin(code, 1) orelse return null;
        return d[0];
    }

    /// 16 位大端选项（max message size 之类）
    pub fn optionU16(self: *const Message, code: u8) ?u16 {
        const d = self.findOptionMin(code, 2) orelse return null;
        return (@as(u16, d[0]) << 8) | d[1];
    }

    /// 32 位大端选项（lease time / server id / 地址等）
    pub fn optionU32(self: *const Message, code: u8) ?u32 {
        const d = self.findOptionMin(code, 4) orelse return null;
        return (@as(u32, d[0]) << 24) | (@as(u32, d[1]) << 16) | (@as(u32, d[2]) << 8) | @as(u32, d[3]);
    }

    /// 4 字节地址型选项
    pub fn optionIp(self: *const Message, code: u8) ?[4]u8 {
        const d = self.findOptionMin(code, 4) orelse return null;
        return .{ d[0], d[1], d[2], d[3] };
    }

    pub fn clientId(self: *const Message) ?[]const u8 {
        return self.findOption(Opt.client_id);
    }

    pub fn hostname(self: *const Message) ?[]const u8 {
        const d = self.findOption(Opt.hostname) orelse return null;
        // 去掉尾随 NUL（有些客户端会带上）
        var n = d.len;
        while (n > 0 and d[n - 1] == 0) n -= 1;
        return d[0..n];
    }

    pub fn optIter(self: *const Message) OptionIter {
        return .{ .buf = self.opts };
    }
};

/// 选项遍历器。RFC2132：0=PAD（跳过）、255=END（结束），其余是 TLV。
///
/// **截断即停止**：声明的长度越过缓冲区结尾时直接结束遍历，而不是把数据
/// 裁到缓冲区末尾返回。这与 C 的 `option_find1()`（rfc2131.c:1976-1999）
/// 完全一致 —— 那里对两种情况都 `return NULL; /* malformed packet */`。
/// 早期版本做的是「裁剪」，结果是长度 9 的选项只剩 2 字节也会被当成有效数据
/// 交给上层，属于典型的长度校验缺失（odhcpd 那一批安全修复修的就是这类问题）。
///
/// 尚未移植：C 支持 option overload（选项 52）把选项区延伸到 `file`/`sname`
/// 字段（rfc2131.c:2002-2029）。PXE 场景会用到，以后再补。
pub const OptionIter = struct {
    buf: []const u8,
    pos: usize = 0,

    pub fn next(self: *OptionIter) ?Option {
        while (self.pos < self.buf.len) {
            const code = self.buf[self.pos];
            if (code == Opt.pad) {
                self.pos += 1;
                continue;
            }
            if (code == Opt.end) return null;
            // 至少要能放下 code + len 两个字节
            if (self.pos + 1 >= self.buf.len) return null;
            const len = self.buf[self.pos + 1];
            const start = self.pos + 2;
            // 声明的长度必须完全落在缓冲区内，否则整包按畸形处理
            if (start + @as(usize, len) > self.buf.len) return null;
            const data = self.buf[start .. start + @as(usize, len)];
            self.pos = start + @as(usize, len);
            return .{ .code = code, .data = data };
        }
        return null;
    }
};

/// 解析一个收到的报文。太短或缺 magic cookie 一律返回 null（不抛错，
/// 因为网络上随时可能收到垃圾包）。
pub fn parse(buf: []const u8) ?Message {
    if (buf.len < HEADER_LEN + COOKIE_LEN) return null;
    if (!std.mem.eql(u8, buf[236..240], &MAGIC)) return null;

    var m = Message{};
    m.op = buf[0];
    m.htype = buf[1];
    m.hlen = buf[2];
    m.hops = buf[3];
    @memcpy(&m.xid, buf[4..8]);
    m.secs = (@as(u16, buf[8]) << 8) | buf[9];
    m.flags = (@as(u16, buf[10]) << 8) | buf[11];
    @memcpy(&m.ciaddr, buf[12..16]);
    @memcpy(&m.yiaddr, buf[16..20]);
    @memcpy(&m.siaddr, buf[20..24]);
    @memcpy(&m.giaddr, buf[24..28]);
    @memcpy(&m.chaddr, buf[28..44]);
    @memcpy(&m.sname, buf[44..108]);
    @memcpy(&m.file, buf[108..236]);
    m.opts = buf[240..];
    return m;
}

/// 构造报文的缓冲区写入器。写完后 `finish()` 会补齐到 MIN_PACKET_SIZE 并
/// 返回可用切片长度。
pub const Builder = struct {
    buf: []u8,
    pos: usize = 0,
    ended: bool = false,

    pub const Error = error{NoSpace};

    pub fn init(buf: []u8) Builder {
        return .{ .buf = buf };
    }

    fn put(self: *Builder, bytes: []const u8) Error!void {
        if (self.pos + bytes.len > self.buf.len) return error.NoSpace;
        @memcpy(self.buf[self.pos .. self.pos + bytes.len], bytes);
        self.pos += bytes.len;
    }

    fn putU8(self: *Builder, v: u8) Error!void {
        if (self.pos + 1 > self.buf.len) return error.NoSpace;
        self.buf[self.pos] = v;
        self.pos += 1;
    }

    fn putU16be(self: *Builder, v: u16) Error!void {
        try self.put(&.{ @truncate(v >> 8), @truncate(v) });
    }

    fn putU32be(self: *Builder, v: u32) Error!void {
        try self.put(&.{ @truncate(v >> 24), @truncate(v >> 16), @truncate(v >> 8), @truncate(v) });
    }

    /// 写固定头
    pub fn header(self: *Builder, m: *const Message) Error!void {
        try self.putU8(m.op);
        try self.putU8(m.htype);
        try self.putU8(m.hlen);
        try self.putU8(m.hops);
        try self.put(&m.xid);
        try self.putU16be(m.secs);
        try self.putU16be(m.flags);
        try self.put(&m.ciaddr);
        try self.put(&m.yiaddr);
        try self.put(&m.siaddr);
        try self.put(&m.giaddr);
        try self.put(&m.chaddr);
        try self.put(&m.sname);
        try self.put(&m.file);
        try self.put(&MAGIC);
    }

    /// 写一个 TLV 选项。数据长度上限 255（RFC2132 的 len 字段只有 1 字节）。
    pub fn option(self: *Builder, code: u8, data: []const u8) Error!void {
        if (data.len > 255) return error.NoSpace;
        try self.putU8(code);
        try self.putU8(@intCast(data.len));
        try self.put(data);
    }

    pub fn optionU8v(self: *Builder, code: u8, v: u8) Error!void {
        try self.option(code, &.{v});
    }

    pub fn optionU32v(self: *Builder, code: u8, v: u32) Error!void {
        try self.option(code, &.{ @truncate(v >> 24), @truncate(v >> 16), @truncate(v >> 8), @truncate(v) });
    }

    pub fn optionIpv(self: *Builder, code: u8, ip: [4]u8) Error!void {
        try self.option(code, &ip);
    }

    /// 收尾：写 END、补齐到 300 字节，返回报文总长
    pub fn finish(self: *Builder) usize {
        if (!self.ended) {
            self.buf[self.pos] = Opt.end;
            self.pos += 1;
            self.ended = true;
        }
        while (self.pos < MIN_PACKET_SIZE and self.pos < self.buf.len) {
            self.buf[self.pos] = Opt.pad;
            self.pos += 1;
        }
        return self.pos;
    }
};

// ---------------------------------------------------------------------------
// 地址池与租约
// ---------------------------------------------------------------------------

/// 一条静态绑定（对应 dnsmasq 的 `--dhcp-host=<mac>,<ip>[,<name>][,<leasetime>]`）
pub const StaticHost = struct {
    /// 6 字节 MAC（odhcpd/dnsmasq 在 v4 上只支持 Ethernet）
    mac: [6]u8,
    ip: [4]u8,
    hostname: ?[]const u8 = null,
    /// 0 表示沿用池的租期
    lease_time: u32 = 0,
};

/// 一个地址池（对应 `--dhcp-range=<start>,<end>,<netmask>[,<leasetime>]`）
pub const Pool = struct {
    start: [4]u8,
    end: [4]u8,
    netmask: [4]u8,
    /// <=0.0.0.0 表示不下发 option 3
    router: [4]u8 = IP_ANY,
    dns: []const [4]u8 = &.{},
    domain: ?[]const u8 = null,
    lease_time: u32 = 43200, // 12h，与 OpenWrt 默认一致
    /// 池绑定的接口名（空表示不限）
    interface: ?[]const u8 = null,
    /// `router` 是否来自配置（`option router` / `--dhcp-option=3,…`）。
    ///
    /// **false 时 router 会在运行期随接口地址刷新** —— 因为网关默认取
    /// 「接口自己的 IPv4」，而 UCI 解析发生在进程启动那一刻；开机时 netifd
    /// 还没给 LAN 配地址，就会拿到 0.0.0.0 → option 3 被省略 → 设备拿到
    /// IP 却没有网关（2026-09-21 重启实测）。显式配置的网关则绝不覆盖。
    router_from_config: bool = false,

    pub fn contains(self: *const Pool, ip: [4]u8) bool {
        const v = ipToU32(ip);
        return v >= ipToU32(self.start) and v <= ipToU32(self.end);
    }

    pub fn size(self: *const Pool) u32 {
        return ipToU32(self.end) - ipToU32(self.start) + 1;
    }
};

/// 租约状态。`expired` 在时钟回拨或本地时区问题下也能退化到「可回收」。
pub const LeaseState = enum { offered, bound, declined, released };

pub const Lease = struct {
    mac: [6]u8 = [_]u8{0} ** 6,
    mac_len: u8 = 6,
    ip: [4]u8 = IP_ANY,
    /// 到期墙钟秒；offered 状态下是「保留到」时刻
    expires: i64 = 0,
    state: LeaseState = .offered,
    /// 该地址是否来自静态绑定
    static: bool = false,
    /// 客户端标识（option 61），有则优先于 MAC 做匹配
    client_id: ?[]const u8 = null,

    /// 客户端上报的主机名（DHCPv4 option 12）。
    ///
    /// 刻意用**内联定长缓冲**而不是 `?[]const u8`：主机名来自网络，每个租约
    /// 都去堆上 dupe 一次，在断线重连/洪泛时会持续分配，而且释放时机很容易
    /// 漏（本模块第一版就是这样在测试里泄漏的）。定长 64 字节覆盖 RFC1035 的
    /// 单标签上限，超长直接截断 —— 反正未通过 LDH 校验的名字也不会被写出。
    hostname_buf: [64]u8 = [_]u8{0} ** 64,
    hostname_len: u8 = 0,

    pub fn hostname(self: *const Lease) ?[]const u8 {
        if (self.hostname_len == 0) return null;
        return self.hostname_buf[0..self.hostname_len];
    }

    /// 写入主机名，超出 64 字节的部分丢弃
    pub fn setHostname(self: *Lease, h: []const u8) void {
        const n = @min(h.len, self.hostname_buf.len);
        @memcpy(self.hostname_buf[0..n], h[0..n]);
        self.hostname_len = @intCast(n);
    }
};

/// 分配失败的原因，方便上层记日志
pub const AllocFail = error{
    PoolExhausted,
    NotInPool,
};

/// 一个 OFFER 发出后，地址为该客户端保留多久（秒）。
///
/// 这个值必须存在：否则刚 OFFER 出去的地址 `expires == now`，下一个客户端
/// 在同一秒内来要地址就会被**重复发出去**，两个客户端拿到同一个 IP。
/// 60 秒足够覆盖客户端发 REQUEST 的往返，也远小于任何合理租期。
pub const OFFER_HOLD_SECS: i64 = 60;

/// 固定容量的租约表。路由器上 LAN 租约数量级是几十到几百，
/// 用线性数组 + 线性查找足够，且没有哈希表的分配与迭代顺序问题。
pub const LeaseDb = struct {
    leases: []Lease,
    count: usize = 0,
    /// 轮转游标：下次从池的哪个位置开始找，避免总把第一个地址发出去
    cursor: u32 = 0,

    pub fn init(storage: []Lease) LeaseDb {
        return .{ .leases = storage };
    }

    pub fn at(self: *LeaseDb, i: usize) *Lease {
        return &self.leases[i];
    }

    pub fn find(self: *LeaseDb, ip: [4]u8) ?*Lease {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            if (ipToU32(self.leases[i].ip) == ipToU32(ip)) return &self.leases[i];
        }
        return null;
    }

    /// 按客户端标识找已有租约。option 61 存在时优先用它，否则用 MAC。
    pub fn findByClient(self: *LeaseDb, mac: []const u8, client_id: ?[]const u8) ?*Lease {
        var i: usize = 0;
        while (i < self.count) : (i += 1) {
            const l = &self.leases[i];
            if (l.state == .released) continue;
            if (client_id) |cid| {
                if (l.client_id) |lcid| {
                    if (std.mem.eql(u8, lcid, cid)) return l;
                }
            }
            if (@as(usize, l.mac_len) == mac.len and macEqual(l.mac[0..l.mac_len], mac)) return l;
        }
        return null;
    }

    /// 该地址是否「现在不能被别人拿走」。
    ///
    /// DECLINE 的地址也会在 `expires`（声明退避期）内保持占用 —— 它与普通租约
    /// 的区别只在于「退避期长短」而不是「永不过期」。早期版本把 DECLINE 写成
    /// 永久占用，会导致池被声明冲突慢慢啃光，且 reap() 也回收不掉。
    pub fn isBusy(self: *LeaseDb, ip: [4]u8, now: i64) bool {
        const l = self.find(ip) orelse return false;
        if (l.state == .released) return false;
        return l.expires > now;
    }

    /// 直接放进一条租约（启动时从状态文件恢复用）。
    ///
    /// 与 `alloc()` 的区别：不做任何「挑地址」的决策，调用方已经知道要给谁什么地址。
    /// 同 IP 已存在时原地覆盖 —— 恢复阶段后到的记录应当覆盖先到的（文件里有重复
    /// 条目时以最后一条为准，与 odhcpd 的「后写覆盖」一致）。
    pub fn insert(self: *LeaseDb, l: Lease) AllocFail!*Lease {
        // 已存在同 IP 的条目则原地覆盖，避免同一地址出现两条租约
        if (self.find(l.ip)) |old| {
            old.* = l;
            return old;
        }
        // 表满：上层应当按「池大小 + 静态绑定条数」开表；真满了就报池满，
        // 而不是越界写（Debug 下 assert 会拦，ReleaseFast 下不会）。
        if (self.count >= self.leases.len) return error.PoolExhausted;
        self.leases[self.count] = l;
        self.count += 1;
        return &self.leases[self.count - 1];
    }

    /// 该地址是否被**别的**客户端静态保留（`--dhcp-host=<mac>,<ip>`）。
    /// dnsmasq 语义：静态绑定地址**不进动态池** —— 否则会出现
    /// 「路由器上给 PC 保留了 X，手机却先拿到了 X」这种真机冲突
    /// （2026-09-21 用户实测：PC 与手机抢同一地址）。
    pub fn reservedForOther(statics: []const StaticHost, ip: [4]u8, mac: []const u8) bool {
        for (statics) |*s| {
            if (ipToU32(s.ip) != ipToU32(ip)) continue;
            if (s.mac.len == mac.len and macEqual(s.mac[0..], mac)) continue;
            return true;
        }
        return false;
    }

    /// 查静态绑定。返回第一条 MAC 全等的记录（dnsmasq 的语义是「先匹配先赢」，
    /// 由调用方保证配置顺序）。
    pub fn findStatic(statics: []const StaticHost, mac: []const u8) ?*const StaticHost {
        if (mac.len != 6) return null;
        for (statics) |*s| {
            if (macEqual(&s.mac, mac)) return s;
        }
        return null;
    }

    /// 为一个客户端挑地址。
    ///
    /// 顺序与 dnsmasq/odhcpd 的实际行为一致：
    ///   1. 静态绑定（MAC 全等）—— 无条件优先，即使已过期也还是它
    ///   2. 该客户端已有的租约（换 IP 会让客户端掉线，尽量保持）
    ///   3. 客户端在 option 50 里点名的地址（在池内且空闲才给）
    ///   4. 从游标位置开始线性扫描池
    ///
    /// `now` 用墙钟秒。返回租约指针，调用方负责改 expires/state。
    pub fn alloc(
        self: *LeaseDb,
        pool: *const Pool,
        statics: []const StaticHost,
        mac: []const u8,
        client_id: ?[]const u8,
        hint: ?[4]u8,
        now: i64,
    ) AllocFail!*Lease {
        // 1. 静态绑定
        if (findStatic(statics, mac)) |s| {
            if (!pool.contains(s.ip)) return error.NotInPool;
            if (self.find(s.ip)) |existing| {
                // 地址被别的客户端占着 —— 静态绑定优先，直接抢过来
                existing.mac = s.mac;
                existing.mac_len = 6;
                existing.static = true;
                existing.state = .offered;
                existing.expires = now + OFFER_HOLD_SECS; // 实际租期由调用方按 ACK 结果改写
                existing.client_id = client_id;
                if (s.hostname) |h| existing.setHostname(h);
                return existing;
            }
            var l6 = Lease{
                .ip = s.ip,
                .state = .offered,
                .static = true,
                .expires = now + OFFER_HOLD_SECS,
                .client_id = client_id,
                .mac = s.mac,
                .mac_len = 6,
            };
            if (s.hostname) |h| l6.setHostname(h);
            return self.insert(l6);
        }

        // 2. 该客户端已有租约
        if (self.findByClient(mac, client_id)) |l| {
            // 该地址后来被保留给别的 MAC 了（管理员新加了 dhcp-host）—— 必须
            // 让位，否则保留地址永远收不回来
            if (pool.contains(l.ip) and !reservedForOther(statics, l.ip, mac)) {
                if (client_id) |cid| l.client_id = cid;
                return l;
            }
            // 池变了（比如改了 --dhcp-range），旧地址不再可用 -> 释放后重挑
            l.state = .released;
        }

        // 3. 客户端点名的地址
        if (hint) |h| {
            if (pool.contains(h) and !self.isBusy(h, now) and !reservedForOther(statics, h, mac)) {
                var lh = Lease{ .ip = h, .state = .offered, .client_id = client_id, .expires = now + OFFER_HOLD_SECS };
                const nh = @min(mac.len, 6);
                @memcpy(lh.mac[0..nh], mac[0..nh]);
                lh.mac_len = @intCast(nh);
                return self.insert(lh);
            }
        }

        // 4. 池内线性扫描（从游标开始，绕一圈）
        const total = pool.size();
        if (total == 0) return error.PoolExhausted;
        const base = ipToU32(pool.start);
        var k: u32 = 0;
        while (k < total) : (k += 1) {
            const off = (self.cursor + k) % total;
            const candidate = u32ToIp(base + off);
            if (self.isBusy(candidate, now)) continue;
            if (reservedForOther(statics, candidate, mac)) continue;
            self.cursor = (off + 1) % total;
            var lc = Lease{ .ip = candidate, .state = .offered, .client_id = client_id, .expires = now + OFFER_HOLD_SECS };
            const nl = @min(mac.len, 6);
            @memcpy(lc.mac[0..nl], mac[0..nl]);
            lc.mac_len = @intCast(nl);
            return self.insert(lc);
        }
        return error.PoolExhausted;
    }

    /// 清掉已过期（含声明退避期满）与已释放的租约槽位（原地压缩），
    /// 返回释放条数。`declined` 不再享受「永不过期」的待遇。
    pub fn reap(self: *LeaseDb, now: i64) usize {
        var n: usize = 0;
        var i: usize = 0;
        while (i < self.count) {
            const l = self.leases[i];
            if (l.state == .released or l.expires <= now) {
                self.leases[i] = self.leases[self.count - 1];
                self.count -= 1;
                n += 1;
                continue;
            }
            i += 1;
        }
        return n;
    }
};

// ---------------------------------------------------------------------------
// 应答目标地址
// ---------------------------------------------------------------------------

pub const Dest = struct {
    ip: [4]u8,
    port: u16,
    /// 是否需要在发包前注入一条内核 ARP 条目。
    ///
    /// 只有走进「单播到刚分配的地址」那个分支才为 true。此时客户端**还没有**
    /// 那个地址，内核 ARP 问不出 MAC，单播包会被静默丢弃 —— odhcpd 的解法是
    /// 在 `dhcpv4.c:745-768` 先 `ioctl(SIOCSARP)` 插一条 `ATF_COM` 条目把
    /// 客户端 MAC 和刚分配的地址绑起来。回环自检暴露不了这个问题（回环不走
    /// ARP），所以这个标记是真机手上才抓出来的。
    needs_arp: bool = false,
};

/// 复刻 odhcpd `dhcpv4_set_dest_addr()`（dhcpv4.c:702-770）。
///
/// `src` 是收到请求时的对端地址（odhcpd 先 `*dest = *src`），保留下来是为了
/// 在「客户端已有配置且用它发过包」的情况下直接回给它，避免额外 ARP。
pub fn replyDest(req: *const Message, reply: *const Message, src: Dest) Dest {
    var d = src;

    if (!ipIsZero(req.giaddr)) {
        // 有中继：回给中继的 67 端口
        d.ip = req.giaddr;
        d.port = SERVER_PORT;
    } else if (!ipIsZero(req.ciaddr) and ipToU32(req.ciaddr) != ipToU32(d.ip)) {
        // 客户端已有配置，且不是用它发这个包 —— 单播回 ciaddr:68
        d.ip = req.ciaddr;
        d.port = CLIENT_PORT;
    } else if ((req.flags & FLAG_BROADCAST) != 0 or
        req.hlen != reply.hlen or ipIsZero(reply.yiaddr))
    {
        // 客户端要求广播 / 没法给它一个地址
        d.ip = IP_BROADCAST;
        d.port = CLIENT_PORT;
    } else if (ipIsZero(req.ciaddr) and reply.msgType() == @intFromEnum(Msg.nak)) {
        // 没旧配置又收到 NAK -> 只能广播（此时回单播它根本收不到）
        d.ip = IP_BROADCAST;
        d.port = CLIENT_PORT;
    } else {
        // 正常情况：单播到刚分配的地址。
        // 这里**必须**由调用方在发包前注入 ARP 条目，否则包发不出去，
        // 客户端表现为「发了 DISCOVER 但永远等不到 OFFER」。
        d.ip = reply.yiaddr;
        d.port = CLIENT_PORT;
        d.needs_arp = true;
    }
    return d;
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

const t = std.testing;

test "dhcpv4：地址与掩码工具" {
    try t.expectEqual(@as(u32, 0xC0A80101), ipToU32(.{ 192, 168, 1, 1 }));
    try t.expectEqual([4]u8{ 192, 168, 1, 1 }, u32ToIp(0xC0A80101));

    try t.expectEqual(@as(?[4]u8, .{ 192, 168, 1, 100 }), parseIpv4("192.168.1.100"));
    try t.expectEqual(@as(?[4]u8, .{ 10, 0, 0, 0 }), parseIpv4("10"));
    try t.expectEqual(@as(?[4]u8, null), parseIpv4("10.0.0.300"));
    try t.expectEqual(@as(?[4]u8, null), parseIpv4("10.0.0.1.5"));
    try t.expectEqual(@as(?[4]u8, null), parseIpv4(""));

    var tb: [16]u8 = undefined;
    try t.expectEqualStrings("172.16.255.1", ipText(.{ 172, 16, 255, 1 }, &tb));

    try t.expectEqual(@as(?u8, 24), maskPrefixLen(.{ 255, 255, 255, 0 }));
    try t.expectEqual(@as(?u8, 25), maskPrefixLen(.{ 255, 255, 255, 128 }));
    try t.expectEqual(@as(?u8, 0), maskPrefixLen(.{ 0, 0, 0, 0 }));
    try t.expectEqual(@as(?u8, null), maskPrefixLen(.{ 255, 0, 255, 0 })); // 非连续

    try t.expectEqual([4]u8{ 192, 168, 1, 0 }, networkOf(.{ 192, 168, 1, 77 }, .{ 255, 255, 255, 0 }));
    try t.expectEqual([4]u8{ 192, 168, 1, 255 }, broadcastOf(.{ 192, 168, 1, 77 }, .{ 255, 255, 255, 0 }));
}

test "dhcpv4：MAC 解析（对照 odhcpd 的 dhcpv4 只支持 Ethernet）" {
    try t.expectEqual([6]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, parseMac("aa:bb:cc:dd:ee:ff").?);
    try t.expectEqual([6]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, parseMac("AA-BB-CC-DD-EE-FF").?);
    try t.expectEqual(@as(?[6]u8, null), parseMac("aa:bb:cc:dd:ee"));
    try t.expectEqual(@as(?[6]u8, null), parseMac("aa:bb:cc:dd:ee:ff:00"));
    try t.expectEqual(@as(?[6]u8, null), parseMac("zz:bb:cc:dd:ee:ff"));
}

test "dhcpv4：报文解析必须钉死 magic cookie，垃圾包一律拒绝" {
    var buf = [_]u8{0} ** 400;
    var m = Message{};
    m.op = @intFromEnum(Op.bootrequest);
    m.htype = 1;
    m.hlen = 6;
    m.xid = .{ 0xDE, 0xAD, 0xBE, 0xEF };
    m.flags = FLAG_BROADCAST;
    @memcpy(m.chaddr[0..6], &[_]u8{ 0xde, 0xad, 0x00, 0x01, 0x02, 0x03 });
    var b = Builder.init(&buf);
    try b.header(&m);
    try b.optionU8v(Opt.message, @intFromEnum(Msg.discover));
    const n = b.finish();
    try t.expectEqual(MIN_PACKET_SIZE, n); // 补齐到 300

    const p = parse(buf[0..n]).?;
    try t.expectEqual(@as(u8, 1), p.op);
    try t.expectEqual(@as(u8, 6), p.hlen);
    try t.expectEqualSlices(u8, &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF }, &p.xid);
    try t.expectEqual(@as(u16, FLAG_BROADCAST), p.flags);
    try t.expectEqualSlices(u8, &[_]u8{ 0xde, 0xad, 0x00, 0x01, 0x02, 0x03 }, p.chaddrSlice());
    try t.expectEqual(@as(u8, @intFromEnum(Msg.discover)), p.msgType());

    // 长度不足
    try t.expectEqual(@as(?Message, null), parse(buf[0 .. HEADER_LEN + 3]));
    // cookie 错
    var bad = buf;
    bad[236] = 0;
    try t.expectEqual(@as(?Message, null), parse(bad[0..n]));
}

test "dhcpv4：选项遍历要能跳过 PAD、遇 END 停下、截断即判为畸形" {
    const raw = [_]u8{
        Opt.pad, Opt.pad,
        Opt.message,      1, @intFromEnum(Msg.request),
        Opt.requested_ip, 4, 192, 168, 1, 50,
        Opt.max_msg_size, 2, 0x05, 0xDC,
        Opt.end,          9, 9, 9, // END 之后的内容必须被忽略
    };
    const m = Message{ .opts = &raw };
    try t.expectEqual(@as(u8, @intFromEnum(Msg.request)), m.msgType());
    try t.expectEqual([4]u8{ 192, 168, 1, 50 }, m.optionIp(Opt.requested_ip).?);
    // max message size 是 **2 字节**选项，用 optionU32 读会得 null
    try t.expectEqual(@as(?u32, null), m.optionU32(Opt.max_msg_size));
    try t.expectEqual(@as(u16, 1500), m.optionU16(Opt.max_msg_size).?);
    // END 之后的字节不能被当成选项
    try t.expectEqual(@as(?[]const u8, null), m.findOption(9));

    // 声明长度越过缓冲区结尾 -> 畸形，整个选项不能被看见
    // （对照 C rfc2131.c:1991 `if (p > end - (2 + opt_len)) return NULL;`）
    const short = Message{ .opts = &[_]u8{ Opt.message, 9, 1, 2 } };
    try t.expectEqual(@as(?u8, null), short.optionU8(Opt.message));

    // 只有长度字节、没有数据 -> 同样畸形
    const half = Message{ .opts = &[_]u8{ Opt.message, 1 } };
    try t.expectEqual(@as(?u8, null), half.optionU8(Opt.message));

    // minsize 语义：长度不足的地址类选项要当「不存在」
    const tiny = Message{ .opts = &[_]u8{ Opt.requested_ip, 3, 192, 168, 1, Opt.end } };
    try t.expectEqual(@as(?[4]u8, null), tiny.optionIp(Opt.requested_ip));
    try t.expectEqual(@as(usize, 3), tiny.findOption(Opt.requested_ip).?.len);
}

test "dhcpv4：同一选项出现多次要能数清楚（多 router 场景）" {
    const raw = [_]u8{
        Opt.router,     4, 192, 168, 1, 1,
        Opt.router,     4, 192, 168, 1, 2,
        Opt.dnsserver,  4, 9,   9,   9, 9,
        Opt.end,
    };
    const m = Message{ .opts = &raw };
    try t.expectEqual(@as(usize, 2), m.countOption(Opt.router));
    try t.expectEqual(@as(usize, 1), m.countOption(Opt.dnsserver));
    try t.expectEqual([4]u8{ 192, 168, 1, 1 }, m.optionIp(Opt.router).?);
}

test "dhcpv4：hostname 要剥掉尾随 NUL" {
    const m = Message{ .opts = &[_]u8{ Opt.hostname, 5, 'a', 'b', 0, 0, 0, Opt.end } };
    try t.expectEqualStrings("ab", m.hostname().?);
}

test "dhcpv4：池内分配要避开占用地址，并且能稳定复用同一地址" {
    var storage: [16]Lease = undefined;
    var db = LeaseDb.init(&storage);
    var pool = Pool{
        .start = .{ 192, 168, 9, 10 },
        .end = .{ 192, 168, 9, 12 },
        .netmask = .{ 255, 255, 255, 0 },
    };
    const mac_a = [_]u8{ 0x02, 0, 0, 0, 0, 0x0a };
    const mac_b = [_]u8{ 0x02, 0, 0, 0, 0, 0x0b };
    const mac_c = [_]u8{ 0x02, 0, 0, 0, 0, 0x0c };
    const mac_d = [_]u8{ 0x02, 0, 0, 0, 0, 0x0d };

    const l1 = try db.alloc(&pool, &.{}, &mac_a, null, null, 1000);
    l1.state = .bound;
    l1.expires = 2000;
    try t.expectEqual([4]u8{ 192, 168, 9, 10 }, l1.ip);

    const l2 = try db.alloc(&pool, &.{}, &mac_b, null, null, 1000);
    l2.state = .bound;
    l2.expires = 2000;
    try t.expectEqual([4]u8{ 192, 168, 9, 11 }, l2.ip); // 游标往前推，不重复发 .10

    // 同一个客户端再来，应当还是它原来的地址
    const l1b = try db.alloc(&pool, &.{}, &mac_a, null, null, 1500);
    try t.expectEqual([4]u8{ 192, 168, 9, 10 }, l1b.ip);

    // 第三个客户端拿最后一个
    const l3 = try db.alloc(&pool, &.{}, &mac_c, null, null, 1000);
    l3.state = .bound;
    l3.expires = 2000;
    try t.expectEqual([4]u8{ 192, 168, 9, 12 }, l3.ip);

    // 第四个：池满
    try t.expectError(error.PoolExhausted, db.alloc(&pool, &.{}, &mac_d, null, null, 1000));

    // 时间推到全部过期之后，reap 之后再分配应当又能成功
    _ = db.reap(3000);
    const l4 = try db.alloc(&pool, &.{}, &mac_d, null, null, 3000);
    try t.expectEqual([4]u8{ 192, 168, 9, 10 }, l4.ip);
}

test "dhcpv4：静态绑定优先，且能从别人手里把地址抢回来" {
    var storage: [16]Lease = undefined;
    var db = LeaseDb.init(&storage);
    var pool = Pool{
        .start = .{ 10, 0, 0, 10 },
        .end = .{ 10, 0, 0, 20 },
        .netmask = .{ 255, 255, 255, 0 },
    };
    const mac_pc = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01 };
    const mac_other = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02 };
    const statics = [_]StaticHost{
        .{ .mac = mac_pc, .ip = .{ 10, 0, 0, 15 }, .hostname = "nas", .lease_time = 86400 },
    };

    // 保留地址不能通过动态分配落到别人手里（dnsmasq 语义：静态地址不进动态池）
    const third = try db.alloc(&pool, &statics, &mac_other, null, .{ 10, 0, 0, 15 }, 100);
    try t.expect(!std.mem.eql(u8, &third.ip, &[4]u8{ 10, 0, 0, 15 }));
    third.state = .released;

    // 「抢回来」针对的是**先于保留存在的租约**（典型来源：状态文件恢复、
    // 或管理员刚加了一条 dhcp-host）。这种租约直接插进表里模拟。
    const stolen = try db.insert(Lease{
        .ip = .{ 10, 0, 0, 15 },
        .state = .bound,
        .expires = 9999,
        .mac = mac_other,
        .mac_len = 6,
    });
    try t.expectEqual([4]u8{ 10, 0, 0, 15 }, stolen.ip);

    // 静态绑定的客户端来了：必须拿到 .15，原来的租约被顶掉
    const fixed = try db.alloc(&pool, &statics, &mac_pc, null, null, 200);
    try t.expectEqual([4]u8{ 10, 0, 0, 15 }, fixed.ip);
    try t.expect(fixed.static);
    try t.expectEqualStrings("nas", fixed.hostname().?);
    // 现在 .15 归静态绑定的那个客户端，原承租人不再持有
    const now_owner = db.find(.{ 10, 0, 0, 15 }).?;
    try t.expectEqualSlices(u8, &mac_pc, &now_owner.mac);
    try t.expect(now_owner.static);
}

test "dhcpv4：静态地址不在池内必须报 NotInPool（而不是偷偷发出去）" {
    var storage: [8]Lease = undefined;
    var db = LeaseDb.init(&storage);
    var pool = Pool{
        .start = .{ 10, 0, 0, 10 },
        .end = .{ 10, 0, 0, 20 },
        .netmask = .{ 255, 255, 255, 0 },
    };
    const mac = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03 };
    const statics = [_]StaticHost{.{ .mac = mac, .ip = .{ 10, 0, 99, 99 } }};
    try t.expectError(error.NotInPool, db.alloc(&pool, &statics, &mac, null, null, 1));
}

test "dhcpv4：option 50 点名的地址，池内空闲才给" {
    var storage: [8]Lease = undefined;
    var db = LeaseDb.init(&storage);
    var pool = Pool{
        .start = .{ 10, 0, 0, 10 },
        .end = .{ 10, 0, 0, 20 },
        .netmask = .{ 255, 255, 255, 0 },
    };
    const mac_x = [_]u8{ 1, 2, 3, 4, 5, 6 };
    const mac_y = [_]u8{ 1, 2, 3, 4, 5, 7 };

    // 池外点名 -> 忽略，按正常扫描分配
    const l = try db.alloc(&pool, &.{}, &mac_x, null, .{ 10, 0, 9, 200 }, 100);
    try t.expectEqual([4]u8{ 10, 0, 0, 10 }, l.ip);

    // 池内点名且空闲 -> 采纳
    const l2 = try db.alloc(&pool, &.{}, &mac_y, null, .{ 10, 0, 0, 19 }, 100);
    try t.expectEqual([4]u8{ 10, 0, 0, 19 }, l2.ip);
}

test "dhcpv4：clientid 优先于 MAC 认客户端（RFC4361 客户端会换 MAC）" {
    var storage: [8]Lease = undefined;
    var db = LeaseDb.init(&storage);
    var pool = Pool{
        .start = .{ 10, 0, 0, 10 },
        .end = .{ 10, 0, 0, 20 },
        .netmask = .{ 255, 255, 255, 0 },
    };
    const mac1 = [_]u8{ 0, 0, 0, 0, 0, 1 };
    const mac2 = [_]u8{ 0, 0, 0, 0, 0, 2 };
    const cid = [_]u8{ 1, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };

    const a = try db.alloc(&pool, &.{}, &mac1, &cid, null, 100);
    a.state = .bound;
    a.expires = 5000;
    try t.expectEqual([4]u8{ 10, 0, 0, 10 }, a.ip);

    // 同一个 clientid、不同 MAC -> 还是同一个地址
    const b = try db.alloc(&pool, &.{}, &mac2, &cid, null, 200);
    try t.expectEqual([4]u8{ 10, 0, 0, 10 }, b.ip);
}

test "dhcpv4：DECLINE 的地址在退避期内不再分配，退避期满后被回收" {
    var storage: [8]Lease = undefined;
    var db = LeaseDb.init(&storage);
    var pool = Pool{
        .start = .{ 10, 0, 0, 10 },
        .end = .{ 10, 0, 0, 12 },
        .netmask = .{ 255, 255, 255, 0 },
    };
    const mac_a = [_]u8{ 0, 0, 0, 0, 0, 1 };
    const mac_b = [_]u8{ 0, 0, 0, 0, 0, 2 };
    const mac_c = [_]u8{ 0, 0, 0, 0, 0, 3 };

    // A 点着 .10 却声明地址冲突（ARP 探测发现被占）
    const a = try db.alloc(&pool, &.{}, &mac_a, null, .{ 10, 0, 0, 10 }, 100);
    a.state = .declined;
    a.expires = 160; // 退避 60 秒

    // 退避期内 .10 不能再发出去
    try t.expect(db.isBusy(.{ 10, 0, 0, 10 }, 100));
    const b = try db.alloc(&pool, &.{}, &mac_b, null, null, 100);
    try t.expectEqual([4]u8{ 10, 0, 0, 11 }, b.ip);

    // 退避期满 -> 不再占用，回收后可重新分配
    try t.expect(!db.isBusy(.{ 10, 0, 0, 10 }, 200));
    _ = db.reap(200);
    const c = try db.alloc(&pool, &.{}, &mac_c, null, .{ 10, 0, 0, 10 }, 200);
    try t.expectEqual([4]u8{ 10, 0, 0, 10 }, c.ip);
}

test "dhcpv4：OFFER 之后同一秒内的第二个客户端不能拿到同一个地址" {
    // 这是 OFFER_HOLD_SECS 存在的理由：没有它，刚 OFFER 出去的地址
    // expires == now，立刻就会被发给下一个客户端。
    var storage: [8]Lease = undefined;
    var db = LeaseDb.init(&storage);
    var pool = Pool{
        .start = .{ 10, 0, 0, 10 },
        .end = .{ 10, 0, 0, 11 },
        .netmask = .{ 255, 255, 255, 0 },
    };
    const mac_a = [_]u8{ 0, 0, 0, 0, 0, 1 };
    const mac_b = [_]u8{ 0, 0, 0, 0, 0, 2 };
    const mac_c = [_]u8{ 0, 0, 0, 0, 0, 3 };

    const a = try db.alloc(&pool, &.{}, &mac_a, null, null, 1000); // 仍是 offered
    try t.expectEqual([4]u8{ 10, 0, 0, 10 }, a.ip);
    const b = try db.alloc(&pool, &.{}, &mac_b, null, null, 1000); // 同一秒
    try t.expectEqual([4]u8{ 10, 0, 0, 11 }, b.ip); // 不会重复发 .10
    try t.expectError(error.PoolExhausted, db.alloc(&pool, &.{}, &mac_c, null, null, 1000));
    // 保留期过后（且没被 ACK），地址回到池里
    const c = try db.alloc(&pool, &.{}, &mac_c, null, null, 1000 + OFFER_HOLD_SECS + 1);
    try t.expectEqual([4]u8{ 10, 0, 0, 10 }, c.ip);
}

test "dhcpv4：应答目标地址 —— 逐条对照 odhcpd dhcpv4_set_dest_addr" {
    const src = Dest{ .ip = .{ 192, 168, 1, 100 }, .port = CLIENT_PORT };

    // 1) giaddr 非零 -> 回中继的 67
    {
        var req = Message{ .giaddr = .{ 10, 0, 0, 1 }, .ciaddr = .{ 192, 168, 1, 100 } };
        var rep = Message{};
        rep.opts = &[_]u8{ Opt.message, 1, @intFromEnum(Msg.offer), Opt.end };
        const d = replyDest(&req, &rep, src);
        try t.expectEqual([4]u8{ 10, 0, 0, 1 }, d.ip);
        try t.expectEqual(SERVER_PORT, d.port);
        try t.expectEqual(false, d.needs_arp);
    }

    // 2) ciaddr 非零且与来源不同 -> 回 ciaddr:68
    {
        var req = Message{ .ciaddr = .{ 192, 168, 1, 77 }, .hlen = 6 };
        const rep = Message{ .yiaddr = .{ 192, 168, 1, 100 }, .hlen = 6 };
        const d = replyDest(&req, &rep, src);
        try t.expectEqual([4]u8{ 192, 168, 1, 77 }, d.ip);
        try t.expectEqual(CLIENT_PORT, d.port);
        // 客户端已经持有这个地址，内核 ARP 问得出来，不用注入
        try t.expectEqual(false, d.needs_arp);
    }

    // 2b) ciaddr 恰好等于来源地址 -> 该分支被跳过，落到正常单播路径
    //     （对照 odhcpd：条件是 `ciaddr != dest->sin_addr`，两者相等时确实不走）
    {
        var req = Message{ .ciaddr = .{ 192, 168, 1, 100 }, .hlen = 6 };
        var rep = Message{ .yiaddr = .{ 192, 168, 1, 100 }, .hlen = 6 };
        rep.opts = &[_]u8{ Opt.message, 1, @intFromEnum(Msg.ack), Opt.end };
        const d = replyDest(&req, &rep, src);
        try t.expectEqual([4]u8{ 192, 168, 1, 100 }, d.ip);
        try t.expectEqual(CLIENT_PORT, d.port);
        try t.expectEqual(true, d.needs_arp);
    }

    // 3) 广播标志 -> 255.255.255.255:68
    {
        var req = Message{ .flags = FLAG_BROADCAST, .hlen = 6 };
        const rep = Message{ .yiaddr = .{ 192, 168, 1, 50 }, .hlen = 6 };
        const d = replyDest(&req, &rep, src);
        try t.expectEqual(IP_BROADCAST, d.ip);
        try t.expectEqual(CLIENT_PORT, d.port);
        try t.expectEqual(false, d.needs_arp);
    }

    // 4) 没旧配置 + NAK -> 只能广播
    {
        var req = Message{ .hlen = 6 };
        var rep = Message{ .hlen = 6 };
        rep.opts = &[_]u8{ Opt.message, 1, @intFromEnum(Msg.nak), Opt.end };
        const d = replyDest(&req, &rep, src);
        try t.expectEqual(IP_BROADCAST, d.ip);
        try t.expectEqual(false, d.needs_arp);
    }

    // 5) hlen 不一致（客户端换了链路层类型）-> 广播
    {
        var req = Message{ .hlen = 6 };
        const rep = Message{ .hlen = 1, .yiaddr = .{ 192, 168, 1, 50 } };
        const d = replyDest(&req, &rep, src);
        try t.expectEqual(IP_BROADCAST, d.ip);
        try t.expectEqual(false, d.needs_arp);
    }

    // 6) 正常路径 -> 单播到 yiaddr:68
    {
        var req = Message{ .hlen = 6, .ciaddr = IP_ANY };
        var rep = Message{ .yiaddr = .{ 192, 168, 1, 50 }, .hlen = 6 };
        rep.opts = &[_]u8{ Opt.message, 1, @intFromEnum(Msg.offer), Opt.end };
        const d = replyDest(&req, &rep, src);
        try t.expectEqual([4]u8{ 192, 168, 1, 50 }, d.ip);
        try t.expectEqual(CLIENT_PORT, d.port);
        // 只有这一条路需要注入 ARP：客户端还没有这个地址，内核问不出 MAC
        try t.expectEqual(true, d.needs_arp);
    }

    // 7) 广播应答绝不能去碰 ARP 表（回环自检也走这条）
    {
        var req = Message{ .hlen = 6, .flags = FLAG_BROADCAST };
        var rep = Message{ .yiaddr = .{ 127, 0, 0, 2 }, .hlen = 6 };
        rep.opts = &[_]u8{ Opt.message, 1, @intFromEnum(Msg.offer), Opt.end };
        const d = replyDest(&req, &rep, src);
        try t.expectEqual(IP_BROADCAST, d.ip);
        try t.expectEqual(false, d.needs_arp);
    }
}

test "dhcpv4：构造 OFFER 的字节布局（黄金串，防止选项顺序被无意改动）" {
    var buf = [_]u8{0} ** 512;
    var rep = Message{};
    rep.op = @intFromEnum(Op.bootreply);
    rep.htype = 1;
    rep.hlen = 6;
    rep.xid = .{ 1, 2, 3, 4 };
    rep.yiaddr = .{ 192, 168, 9, 10 };
    rep.siaddr = .{ 192, 168, 9, 1 };
    @memcpy(rep.chaddr[0..6], &[_]u8{ 0x02, 0, 0, 0, 0, 0x0a });

    var b = Builder.init(&buf);
    try b.header(&rep);
    try b.optionU8v(Opt.message, @intFromEnum(Msg.offer));
    try b.optionU32v(Opt.server_id, ipToU32(.{ 192, 168, 9, 1 }));
    try b.optionU32v(Opt.lease_time, 43200);
    try b.optionIpv(Opt.netmask, .{ 255, 255, 255, 0 });
    try b.optionIpv(Opt.router, .{ 192, 168, 9, 1 });
    try b.option(Opt.dnsserver, &[_]u8{ 192, 168, 9, 1 });
    const n = b.finish();

    try t.expectEqual(MIN_PACKET_SIZE, n);
    try t.expectEqual(@as(u8, 2), buf[0]); // op = BOOTREPLY
    try t.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, buf[4..8]);
    try t.expectEqualSlices(u8, &[_]u8{ 192, 168, 9, 10 }, buf[16..20]); // yiaddr
    try t.expectEqualSlices(u8, &MAGIC, buf[236..240]);
    // 选项区
    try t.expectEqual(@as(u8, Opt.message), buf[240]);
    try t.expectEqual(@as(u8, 1), buf[241]);
    try t.expectEqual(@as(u8, @intFromEnum(Msg.offer)), buf[242]);
    try t.expectEqual(@as(u8, Opt.server_id), buf[243]);
    try t.expectEqual(@as(u8, 4), buf[244]);
    try t.expectEqualSlices(u8, &[_]u8{ 192, 168, 9, 1 }, buf[245..249]);
    try t.expectEqual(@as(u8, Opt.lease_time), buf[249]);
    try t.expectEqualSlices(u8, &[_]u8{ 0, 0, 0xA8, 0xC0 }, buf[251..255]); // 43200 = 0xA8C0
    try t.expectEqual(@as(u8, Opt.netmask), buf[255]);
    try t.expectEqual(@as(u8, Opt.router), buf[261]);
    try t.expectEqual(@as(u8, Opt.dnsserver), buf[267]);
    try t.expectEqual(@as(u8, Opt.end), buf[273]);
}
