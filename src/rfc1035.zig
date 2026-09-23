// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! rfc1035.zig — 对应 C 源码 src/rfc1035.c 的核心部分
//!
//! 已移植：
//!   * extract_request / setup_reply（请求解析与应答头构造）
//!   * add_resource_record（RR 组装，format 字符串语义与 C 一致）
//!   * find_pseudoheader / add_pseudoheader（EDNS0 OPT 记录）
//!   * extract_addresses（从上游应答里提取记录写入缓存，含负缓存与 TTL 上限）
//!   * answer_request（本地应答：hosts/config/缓存/--address/local=/--bogus-priv）
//! 未移植（见 README 进度表）：DNSSEC 校验与 rrfilter、auth 权威区、RRNAME/SRV 组装、
//! do_doctor、TCP 分片重组（TCP 收发在 server.zig 中实现）。

const std = @import("std");
const protocol = @import("protocol.zig");
const addr = @import("addr.zig");
const name = @import("name.zig");
const cache = @import("cache.zig");
const daemon_mod = @import("daemon.zig");
const log = @import("log.zig");
const hosts = @import("hosts.zig");
const dmn = @import("domain.zig");

const Daemon = daemon_mod.Daemon;

/// 对应 rfc1035.c: 的工作区名字缓冲
pub const MAXNAMEBUF = protocol.MAXDNAMESTR + 1;

/// extractAddresses 专用：记录「本应答内已经整组替换过的 (名字, 类别位)」。
///
/// 对应 C 版 `really_insert()` 把新记录先挂到 `new_chain`、直到
/// `cache_end_insert()` 才 `cache_hash()` 入桶的**批处理**效果：同一应答里的
/// 多条 A/AAAA（或 CNAME）在插入时互相看不见，因此不会彼此驱逐，一个应答里的
/// 多个地址能全部保留。这里用「每 (名字, 类别) 只调用一次
/// `cache.clearForwardAddrs`」达到同样的可观测结果。
///
/// 表满（>4 个不同名字）时不再清理；最坏只是多留一条旧记录，不做进一步处理。
const ClearedAddrName = struct {
    buf: [MAXNAMEBUF]u8 = undefined,
    len: usize = 0,
    family: u32 = 0,
};

fn clearFamilyOnce(
    d: *Daemon,
    list: []ClearedAddrName,
    n: *usize,
    nm: []const u8,
    family: u32,
    now: i64,
) void {
    for (list[0..n.*]) |e| {
        if (e.family == family and e.len == nm.len and name.hostnameIsEqual(e.buf[0..e.len], nm))
            return;
    }
    _ = d.cache.clearForwardAddrs(nm, family, now);
    if (n.* < list.len and nm.len <= list[0].buf.len) {
        @memcpy(list[n.*].buf[0..nm.len], nm);
        list[n.*].len = nm.len;
        list[n.*].family = family;
        n.* += 1;
    }
}

/// 把一条 SRV / PTR 的 RDATA **去压缩、重新编码**后写入缓存
/// （对应 C rfc1035.c:905-990 的 F_RR 分支）。
///
/// 为什么必须重编码：RDATA 里的域名可能带压缩指针（指向原报文的其它部分），
/// 把这段字节原样拷进另一个报文后指针就失去意义。C 按 `rrfilter_desc()` 的描述
/// 逐段处理 RDATA：
///   * `T_PTR` → 描述 `0,-1`：整段就是一个域名；
///   * `T_SRV` → 描述 `6,0,-1`：6 字节固定（priority/weight/port）+ 一个域名。
/// 本移植只覆盖这两种（即 README 里「高5」的范围），按同样的布局走一遍：
/// 固定字节原样拷贝，域名用 extractName + doRfc1035Name 重编码为无压缩 wire 形式。
fn cacheRrData(
    d: *Daemon,
    pkt: []u8,
    n: usize,
    rdstart: usize,
    rdlen: usize,
    rrtype: u16,
    nm: []const u8,
    now: i64,
    ttl: u32,
) bool {
    const fixed: usize = if (rrtype == protocol.T_SRV) 6 else 0;
    if (rdlen < fixed) return false;

    // 6 字节固定部分 + 域名。SRV/PTR 的 RDATA 里没有别的内容，走到域名结束即完
    //（对照 C 的描述表：-1 紧跟在域名之后）。
    var buf: [6 + protocol.MAXDNAMESTR * 2]u8 = undefined;
    var out: usize = 0;
    if (fixed != 0) {
        @memcpy(buf[0..fixed], pkt[rdstart..][0..fixed]);
        out = fixed;
    }

    var off = rdstart + fixed;
    var nmbuf: [MAXNAMEBUF]u8 = undefined;
    if (name.extractName(pkt, n, &off, &nmbuf, name.EXTR_NAME_EXTRACT, 0) == 0) return false;
    // rdlen 可能撒谎（C 注释：extract_name() advances p1 past where it says the record ends）
    if (off > rdstart + rdlen) return false;

    const target = std.mem.sliceTo(&nmbuf, 0);
    const wlen = name.doRfc1035Name(buf[out..], target) orelse return false;
    out += wlen;

    const owned = d.allocator.dupe(u8, buf[0..out]) catch return false;
    const rec = d.cache.insert(
        nm,
        .{ .rr = .{ .rrtype = rrtype, .data = owned, .owned = true } },
        protocol.C_IN,
        now,
        ttl,
        protocol.F_FORWARD | protocol.F_RR,
    );
    if (rec == null) {
        d.allocator.free(owned);
        return false;
    }
    return true;
}

/// 对应 extract_request()：解析问题区
pub const Request = struct {
    /// 解析出的名字（内部转义格式，指向调用者提供的缓冲区）
    name: []u8,
    qtype: u16 = 0,
    qclass: u16 = 0,
    /// 对应 C 的返回值：F_IPV4/F_IPV6/F_QUERY/... 组合
    flags: u32 = 0,
    /// 该请求是否带 EDNS0 OPT（伪头部）
    has_edns0: bool = false,
    /// 客户端通告的 UDP 负载大小（EDNS0），无 EDNS0 时为 512
    edns_pktsz: u16 = protocol.PACKETSZ,

    /// 查询被发往的本地 IPv4 地址（网络序）；0 = 未知。
    /// 对应 C 的 `daemon->local_addr` —— 即 IP_PKTINFO 给出的**目的地址**。
    /// 本移植按「每个具体地址一个 socket」绑定（等价 bind-interfaces），
    /// 所以目的地址就是该监听 socket 的绑定地址（见 server.zig 的 addListener）。
    local4: u32 = 0,
    /// 该地址所在接口的掩码（网络序）；0 表示未知（is_same_net 恒真）。
    /// 对应 C 的 `daemon->local_netmask`，供 --localise-queries 使用。
    netmask4: u32 = 0,
};

/// 对应 C util.c: is_same_net()：`(a & mask) == (b & mask)`（三个参数都是网络序）。
pub inline fn sameNet4(a: u32, b: u32, mask: u32) bool {
    return (a & mask) == (b & mask);
}

/// 对应 rfc1035.c: extract_request()
pub fn extractRequest(header: []u8, qlen: usize, namebuf: []u8) ?Request {
    if (qlen < protocol.HEADER_SIZE) return null;
    var p: usize = protocol.HEADER_SIZE;

    namebuf[0] = 0;
    if (protocol.qdcount(header) != 1 or protocol.opcode(protocol.headerHb3(header)) != protocol.OPCODE_QUERY)
        return null;

    if (protocol.isResponse(protocol.headerHb3(header)) and
        (protocol.ancount(header) != 0 or protocol.nscount(header) != 0))
        return null;

    if (name.extractName(header, qlen, &p, namebuf, name.EXTR_NAME_EXTRACT, 4) == 0) return null;

    if (p + 4 > qlen) return null;
    const qtype = protocol.getShort(header, p);
    const qclass = protocol.getShort(header, p + 2);
    p += 4;

    var flags: u32 = 0;
    if (qclass == protocol.C_IN) {
        if (qtype == protocol.T_A) flags = protocol.F_IPV4;
        if (qtype == protocol.T_AAAA) flags = protocol.F_IPV6;
        if (qtype == protocol.T_ANY) flags = protocol.F_IPV4 | protocol.F_IPV6;
    }
    if (qtype == protocol.T_DS) flags = protocol.F_DNSSECOK | protocol.F_DS;
    if (qtype == protocol.T_DNSKEY) flags = protocol.F_DNSSECOK | protocol.F_DNSKEY;
    if (flags == 0) flags = protocol.F_QUERY;

    // 取名字末尾（问题区之后）的 EDNS0 信息
    const edns = findPseudoheader(header, qlen);

    const name_slice = std.mem.sliceTo(namebuf, 0);

    return .{
        .name = namebuf[0..name_slice.len],
        .qtype = qtype,
        .qclass = qclass,
        .flags = flags,
        .has_edns0 = edns.found,
        .edns_pktsz = edns.udp_size,
    };
}

/// 对应 setup_reply()：把请求头改造成应答头
pub fn setupReply(header: []u8, flags: u32, ede: i32) void {
    _ = ede;
    header[protocol.OFF_HB3] = (header[protocol.OFF_HB3] & ~(protocol.HB3_AA | protocol.HB3_TC)) | protocol.HB3_QR;
    header[protocol.OFF_HB4] = (header[protocol.OFF_HB4] & ~protocol.HB4_AD) | protocol.HB4_RA;

    protocol.setNscount(header, 0);
    protocol.setArcount(header, 0);
    protocol.setAncount(header, 0);

    var hb4 = header[protocol.OFF_HB4];
    if (flags == protocol.F_NOERR) {
        protocol.setRcode(&hb4, protocol.NOERROR);
    } else if ((flags & protocol.F_NXDOMAIN) != 0) {
        protocol.setRcode(&hb4, protocol.NXDOMAIN);
    } else if ((flags & protocol.F_RCODE) != 0) {
        protocol.setRcode(&hb4, protocol.NOTIMP);
    } else if ((flags & (protocol.F_IPV4 | protocol.F_IPV6)) != 0) {
        protocol.setRcode(&hb4, protocol.NOERROR);
        header[protocol.OFF_HB3] |= protocol.HB3_AA;
    } else {
        protocol.setRcode(&hb4, protocol.REFUSED);
    }
    header[protocol.OFF_HB4] = hb4;
}

// ---------------------------------------------------------------------------
// RR 组装（对应 add_resource_record）
// ---------------------------------------------------------------------------
pub const AddError = error{Truncated};

/// 对应 add_resource_record()：
///   * `limit` 为报文缓冲上限（null 表示不限制）
///   * `nameoffset` > 0 用压缩指针指向该偏移；< 0 表示指针取反；== 0 写根名字
///   * `format` 的字符含义与 C 一致：'4' IPv4、'6' IPv6、'd' 域名，其它字符跳过
/// 返回值：写入后的新偏移
pub fn addResourceRecord(
    header: []u8,
    limit: ?usize,
    truncp: ?*bool,
    nameoffset: i32,
    p_in: usize,
    ttl: u32,
    offset: ?*i32,
    rr_type: u16,
    class: u16,
    format: []const u8,
    data: []const u8,
) AddError!usize {
    var p = p_in;

    const over = struct {
        fn check(buf: []u8, lim: ?usize, cur: usize, need: usize) bool {
            if (cur + need > buf.len) return true;
            if (lim) |l| {
                if (cur + need > l) return true;
            }
            return false;
        }
    }.check;

    if (truncp) |tp| {
        if (tp.*) return error.Truncated;
    }

    if (nameoffset > 0) {
        if (over(header, limit, p, 2)) {
            if (truncp) |tp| tp.* = true;
            return error.Truncated;
        }
        protocol.putShort(header, p, @as(u16, @truncate(@as(u32, @intCast(nameoffset)))) | 0xC000);
        p += 2;
    } else if (nameoffset < 0) {
        if (over(header, limit, p, 2)) {
            if (truncp) |tp| tp.* = true;
            return error.Truncated;
        }
        const off: u16 = @truncate(@as(u32, @intCast(-nameoffset)));
        protocol.putShort(header, p, off | 0xC000);
        p += 2;
    } else {
        if (over(header, limit, p, 1)) {
            if (truncp) |tp| tp.* = true;
            return error.Truncated;
        }
        header[p] = 0;
        p += 1;
    }

    if (over(header, limit, p, 10)) {
        if (truncp) |tp| tp.* = true;
        return error.Truncated;
    }

    protocol.putShort(header, p, rr_type);
    protocol.putShort(header, p + 2, class);
    protocol.putLong(header, p + 4, ttl);
    const sav = p + 8;
    protocol.putShort(header, p + 8, 0);
    p += 10;

    var dpos: usize = 0;
    for (format) |f| {
        switch (f) {
            '4' => {
                if (over(header, limit, p, protocol.INADDRSZ)) {
                    if (truncp) |tp| tp.* = true;
                    return error.Truncated;
                }
                if (dpos + protocol.INADDRSZ > data.len) {
                    if (truncp) |tp| tp.* = true;
                    return error.Truncated;
                }
                @memcpy(header[p..][0..protocol.INADDRSZ], data[dpos..][0..protocol.INADDRSZ]);
                dpos += protocol.INADDRSZ;
                p += protocol.INADDRSZ;
            },
            '6' => {
                if (over(header, limit, p, protocol.IN6ADDRSZ)) {
                    if (truncp) |tp| tp.* = true;
                    return error.Truncated;
                }
                if (dpos + protocol.IN6ADDRSZ > data.len) {
                    if (truncp) |tp| tp.* = true;
                    return error.Truncated;
                }
                @memcpy(header[p..][0..protocol.IN6ADDRSZ], data[dpos..][0..protocol.IN6ADDRSZ]);
                dpos += protocol.IN6ADDRSZ;
                p += protocol.IN6ADDRSZ;
            },
            's' => {
                // 原始字节块：把 data 的剩余部分**逐字节原样**写入 rdata。
                // 用于回放缓存里已存的 RR 内容（高5 的 SRV/PTR，见 addr.RrData）——
                // 那段内容在写入缓存时就已去压缩、重编码，这里不能再动它。
                const rest = data[dpos..];
                if (over(header, limit, p, rest.len)) {
                    if (truncp) |tp| tp.* = true;
                    return error.Truncated;
                }
                @memcpy(header[p..][0..rest.len], rest);
                dpos += rest.len;
                p += rest.len;
            },
            'd' => {
                if (offset) |op| op.* = @intCast(p);
                const sval = std.mem.sliceTo(data[dpos..], 0);
                dpos += sval.len + 1;
                const written = name.doRfc1035Name(header[p..], sval) orelse {
                    if (truncp) |tp| tp.* = true;
                    return error.Truncated;
                };
                p += written;
            },
            else => {},
        }
    }

    const rdlen: u16 = @truncate(p - sav - 2);
    protocol.putShort(header, sav, rdlen);
    return p;
}

// ---------------------------------------------------------------------------
// EDNS0（对应 edns0.c: find_pseudoheader / add_pseudoheader 的基础部分）
// ---------------------------------------------------------------------------
pub const PseudoHeader = struct {
    found: bool = false,
    /// OPT 记录在报文中的偏移
    off: usize = 0,
    /// 客户端通告的 UDP 负载大小
    udp_size: u16 = protocol.PACKETSZ,
    /// DO 位
    do_bit: bool = false,
    /// OPT 记录总长度（含名字、type 等固定 11 字节 + RDLEN）
    total_len: usize = 0,
    /// 扩展 RCODE（TTL 高 8 位）
    ext_rcode: u8 = 0,
    /// 是否为被签名的 OPT（DNSSEC 场景）。本移植未实现 DNSSEC，恒为 false。
    is_sign: bool = false,
    /// udp_size 字段在报文中的偏移（对应 C 版 process_reply 里的 sizep）
    udp_size_off: usize = 0,
    /// RR 头结束的位置（type/class/ttl/rdlen 之后），即 rdata 起点
    rdstart: usize = 0,
};

/// 在附加区查找 OPT 记录（简化版：只处理附加区最后一个 RR）
pub fn findPseudoheader(header: []u8, plen: usize) PseudoHeader {
    var result = PseudoHeader{};
    if (plen < protocol.HEADER_SIZE) return result;

    const qend = name.skipQuestions(header, plen) orelse return result;
    var p = qend;

    if (name.skipSection(header, p, protocol.ancount(header), plen)) |np| p = np else return result;
    if (name.skipSection(header, p, protocol.nscount(header), plen)) |np| p = np else return result;

    var remaining = protocol.arcount(header);
    while (remaining != 0) : (remaining -= 1) {
        const start = p;
        const next = name.skipName(header, p, plen, 10) orelse return result;
        p = next;
        if (p + 10 > plen) return result;
        const rr_type = protocol.getShort(header, p);
        const rdlen = protocol.getShort(header, p + 8);
        const rdstart = p + 10;
        if (rdstart + rdlen > plen) return result;

        if (rr_type == protocol.T_OPT) {
            result.found = true;
            result.off = start;
            result.udp_size_off = p + 2;
            result.rdstart = rdstart;
            result.udp_size = protocol.getShort(header, p + 2);
            // TTL 字段：高 8 位是扩展 RCODE，低 16 位是标志（DO 位在 TTL 最低位）
            const ttl = protocol.getLong(header, p + 4);
            result.ext_rcode = @truncate(ttl >> 24);
            result.do_bit = (ttl & 0x8000) != 0;
            result.total_len = (rdstart + rdlen) - start;
            return result;
        }
        p = rdstart + rdlen;
    }

    return result;
}

/// 对应 edns0.c: add_pseudoheader() 的最小实现：在报文末尾追加一个空的 OPT 记录
/// （表示服务器支持 EDNS0 并通告自己的 UDP 负载大小）
pub fn addPseudoheader(header: []u8, plen: usize, limit: usize, udp_size: u16, do_bit: bool) ?usize {
    var p = plen;
    if (p + 11 > limit or p + 11 > header.len) return null;

    header[p] = 0; // 根名字
    p += 1;
    protocol.putShort(header, p, protocol.T_OPT);
    protocol.putShort(header, p + 2, @min(udp_size, protocol.OPT_PKTSZ));
    const ttl: u32 = if (do_bit) 0x8000 else 0;
    protocol.putLong(header, p + 4, ttl);
    protocol.putShort(header, p + 8, 0);
    p += 10;

    protocol.setArcount(header, protocol.arcount(header) + 1);
    return p;
}

// ---------------------------------------------------------------------------
// 资源记录过滤（对应 rrfilter.c）
// ---------------------------------------------------------------------------
pub const RrFilter = enum(u32) {
    /// 删掉 EDNS0 伪记录（对应 RRFILTER_EDNS0）
    edns0 = 0,
    /// 删掉 --filter-AAAA 之类配置要求过滤的类型（对应 RRFILTER_CONF）
    conf = 1,
    /// 删掉 DNSSEC 相关类型（对应 RRFILTER_DNSSEC）
    dnssec = 2,
};

/// 对应 rrfilter.c: rrfilter()：把匹配的记录从报文里删掉，返回删除条数。
/// `n` 是 in/out：函数内会就地收缩报文并更新各区的计数字段。
pub fn rrfilter(pkt: []u8, n: *usize, filter: RrFilter) usize {
    var removed: usize = 0;
    const plen = n.*;

    const qend = name.skipQuestions(pkt, plen) orelse return 0;

    // 每个区分别处理：(计数字段偏移, 起始偏移, 数量)
    const Section = struct { count_off: usize, start: usize, count: usize };
    var sections = [_]Section{
        .{ .count_off = protocol.OFF_ANCOUNT, .start = qend, .count = protocol.ancount(pkt) },
        .{ .count_off = protocol.OFF_NSCOUNT, .start = 0, .count = protocol.nscount(pkt) },
        .{ .count_off = protocol.OFF_ARCOUNT, .start = 0, .count = protocol.arcount(pkt) },
    };

    var write_off = qend;
    var read_off = qend;
    var si: usize = 0;
    while (si < sections.len) : (si += 1) {
        if (si > 0) sections[si].start = read_off;
        var kept: usize = 0;
        var i: usize = 0;
        while (i < sections[si].count) : (i += 1) {
            const rr_start = read_off;
            var p = read_off;
            if (name.skipName(pkt, p, plen, 10) == null) break;
            p = name.skipName(pkt, p, plen, 10).?;
            if (p + 10 > plen) break;
            const rr_type = protocol.getShort(pkt, p);
            const rdlen = protocol.getShort(pkt, p + 8);
            const rr_end = p + 10 + rdlen;
            if (rr_end > plen) break;

            const drop = switch (filter) {
                .edns0 => rr_type == protocol.T_OPT,
                .dnssec => rr_type == protocol.T_RRSIG or rr_type == protocol.T_DNSKEY or
                    rr_type == protocol.T_DS or rr_type == protocol.T_NSEC or rr_type == protocol.T_NSEC3,
                .conf => false,
            };

            if (drop) {
                removed += 1;
            } else if (write_off != rr_start) {
                std.mem.copyForwards(u8, pkt[write_off .. write_off + (rr_end - rr_start)], pkt[rr_start..rr_end]);
                write_off += rr_end - rr_start;
                kept += 1;
            } else {
                write_off = rr_end;
                kept += 1;
            }
            read_off = rr_end;
        }
        // 由于删除后偏移整体前移，後续区的计数字段读取不受影响（都在头部）
        protocol.putShort(pkt, sections[si].count_off, @intCast(kept));
    }

    n.* = write_off;
    return removed;
}

// ---------------------------------------------------------------------------
// 从上游应答中提取记录写入缓存（对应 extract_addresses）
// ---------------------------------------------------------------------------
pub const ExtractResult = struct {
    /// 是否出现「名字不存在 / 无此类型」（用于决定是否负缓存）
    nxdomain: bool = false,
    nodata: bool = false,
    /// 解析出的 CNAME 目标（需要追加查询时使用）
    cname: ?[]const u8 = null,
    /// 缓存的记录数
    cached: usize = 0,
};

/// 对应 C 版 rfc1035.c:527 find_soa()：在应答的**权威段**里找 SOA，返回它的 TTL。
///
/// C 版用它做两件事：拿到负数应答的真实 TTL，以及判断「这条负数应答值不值得缓存」
/// （没找到 SOA 且没配 --neg-ttl 就不缓存）。判定条件与 C 完全一致：
/// SOA 的 owner 名字必须是**查询名字的后缀**（忽略大小写）—— 例如查
/// `www.example.com` 时，owner 为 `example.com` 或 `com` 的 SOA 都算命中，
/// 而 owner 为 `example.net` 的 SOA 不算。
fn findSoa(reply: []u8, n: usize, qname: []const u8, namebuf: []u8) ?u32 {
    var p = name.skipQuestions(reply, n) orelse return null;
    const ancount = protocol.ancount(reply);
    const nscount = protocol.nscount(reply);

    // 跳过应答段
    var i: u16 = 0;
    while (i < ancount) : (i += 1) {
        p = name.skipName(reply, p, n, 0) orelse return null;
        if (p + 10 > n) return null;
        p += 10 + protocol.getShort(reply, p + 8);
        if (p > n) return null;
    }

    // 扫权威段
    i = 0;
    while (i < nscount) : (i += 1) {
        const start = p;
        p = name.skipName(reply, p, n, 10) orelse return null;
        if (p + 10 > n) return null;
        const rr_type = protocol.getShort(reply, p);
        const rr_class = protocol.getShort(reply, p + 2);
        const ttl = protocol.getLong(reply, p + 4);
        const rdlen = protocol.getShort(reply, p + 8);
        const rdstart = p + 10;
        if (rdstart + rdlen > n) return null;

        if (rr_class == protocol.C_IN and rr_type == protocol.T_SOA) {
            var off = start;
            if (name.extractName(reply, n, &off, namebuf, name.EXTR_NAME_EXTRACT, 0) != 0) {
                const owner = std.mem.sliceTo(namebuf, 0);
                if (owner.len <= qname.len and owner.len != 0 and
                    name.hostnameIsEqual(owner, qname[qname.len - owner.len ..]))
                    return ttl;
            }
        }
        p = rdstart + rdlen;
    }
    return null;
}

/// 对应 rfc1035.c: extract_addresses()
/// `reply` 为完整应答报文；`qname` 为问题区的名字（规范化，不带尾点）
pub fn extractAddresses(
    d: *Daemon,
    reply: []u8,
    n: usize,
    now: i64,
    qname: []const u8,
    qtype: u16,
    qclass: u16,
    namebuf: []u8,
) ExtractResult {
    var res = ExtractResult{};
    var after_cname = false;

    // 把上游应答里的记录写进缓存：整段持锁（纯内存，无网络 IO）
    d.cache.lock(d.io);
    defer d.cache.unlock(d.io);

    if (qclass != protocol.C_IN) return res;

    const qend = name.skipQuestions(reply, n) orelse return res;
    var p = qend;
    const ancount = protocol.ancount(reply);

    var flags: u32 = 0;
    switch (qtype) {
        protocol.T_A => flags = protocol.F_IPV4 | protocol.F_FORWARD,
        protocol.T_AAAA => flags = protocol.F_IPV6 | protocol.F_FORWARD,
        protocol.T_CNAME => flags = protocol.F_CNAME | protocol.F_FORWARD,
        // 高5：SRV / PTR 走 F_RR（对应 C rfc1035.c:810-812 的
        // `else if (qtype == T_SRV || qtype == T_PTR || rr_on_list(cache_rr, qtype)) flags |= F_RR;`）。
        // 其余类型 C 是 `insert = 0`（完全不缓存），这里保持一致。
        protocol.T_SRV, protocol.T_PTR => flags = protocol.F_RR | protocol.F_FORWARD,
        else => {},
    }
    if ((protocol.headerHb3(reply) & protocol.HB3_AA) != 0) flags |= protocol.F_AUTH;

    const rcode_val = protocol.rcode(protocol.headerHb4(reply));

    // 存储用的「当前名字」：初始为问题名（qname）；一旦遇到 CNAME 就改写成它的
    // 目标名，于是后续的 A/AAAA 记录会挂到 CNAME 目标名下 —— 这正是 C 版
    // extract_addresses() 里 `extract_name(..., name, ...); goto cname_loop;`
    // 所做的事。少了这一步，A 记录会被记在原始名字下，应答时沿链找不到地址。
    // C 版 extract_addresses() 用 `found` 标记「应答里有**类型等于 qtype** 的记录」。
    // 它只在真正缓存了最终答案时置 1：CNAME 会让 C 代码 goto cname_loop 继续追链，
    // 唯独 qtype==T_CNAME 时才算命中（见 rfc1035.c:889-892、901-903）。
    //
    // 因此「NOERROR + 只有 CNAME + 没有最终记录」的应答 found==0，C 会写负缓存。
    // 早期版本这里用 `ancount == 0` 近似，恰好漏掉这种应答 —— 实机表现为
    // copilot.tencent.com 的 AAAA 每次都重问上游（21 秒内转发 49 次）。
    var found = false;
    var cur_name_buf: [MAXNAMEBUF]u8 = undefined;
    var cur_name: []const u8 = qname;

    // 本应答内已整组替换过的 (名字, 类别) —— 见 clearFamilyOnce / clearForwardAddrs
    var cleared: [4]ClearedAddrName = .{ .{}, .{}, .{}, .{} };
    var cleared_n: usize = 0;

    var i: u16 = 0;
    while (i < ancount) : (i += 1) {
        const start = p;
        const next = name.skipName(reply, p, n, 10) orelse return res;
        p = next;
        if (p + 10 > n) return res;

        const rr_type = protocol.getShort(reply, p);
        const rr_class = protocol.getShort(reply, p + 2);
        var ttl = protocol.getLong(reply, p + 4);
        const rdlen = protocol.getShort(reply, p + 8);
        const rdstart = p + 10;
        if (rdstart + rdlen > n) return res;

        // 提取本条 RR 的名字
        var off = start;
        if (name.extractName(reply, n, &off, namebuf, name.EXTR_NAME_EXTRACT, 0) == 0) return res;
        const rr_name = std.mem.sliceTo(namebuf, 0);

        // 只缓存与当前名字相同（或 follow CNAME 链）的记录
        const matches = name.hostnameIsEqual(rr_name, cur_name) or after_cname;
        if (!matches) {
            p = rdstart + rdlen;
            continue;
        }

        if (ttl == 0) ttl = 2; // 与 dnsmasq 相同：TTL 为 0 的记录按 2 秒缓存
        if (d.max_ttl != 0 and ttl > d.max_ttl) ttl = d.max_ttl;
        if (d.max_cache_ttl != 0 and ttl > d.max_cache_ttl) ttl = d.max_cache_ttl;
        // 对应 C 版 cache.c:686-687：--min-cache-ttl 把过短的上游 TTL 抬到该值。
        // 之前只解析了选项、插入时没用上，配了 mincachettl 的机器完全没有效果。
        if (d.min_cache_ttl != 0 and ttl < d.min_cache_ttl) ttl = d.min_cache_ttl;

        if (rr_class == protocol.C_IN) {
            if (rr_type == protocol.T_A and rdlen == protocol.INADDRSZ) {
                var a: addr.AllAddr = .{ .ip4 = 0 };
                @memcpy(@as([*]u8, @ptrCast(&a.ip4))[0..4], reply[rdstart..][0..4]);
                // 见 cache.clearForwardAddrs：整组替换本名的旧 A 记录，避免重转发后出现重复 RR
                clearFamilyOnce(d, &cleared, &cleared_n, cur_name, protocol.F_IPV4, now);
                if (d.cache.insert(cur_name, a, protocol.C_IN, now, ttl, flags & ~protocol.F_CNAME) != null) {
                    res.cached += 1;
                    if (qtype == protocol.T_A) found = true;
                }
                after_cname = true;
            } else if (rr_type == protocol.T_AAAA and rdlen == protocol.IN6ADDRSZ) {
                var a: addr.AllAddr = .{ .ip6 = undefined };
                @memcpy(&a.ip6, reply[rdstart..][0..16]);
                clearFamilyOnce(d, &cleared, &cleared_n, cur_name, protocol.F_IPV6, now);
                if (d.cache.insert(cur_name, a, protocol.C_IN, now, ttl, flags & ~protocol.F_CNAME) != null) {
                    res.cached += 1;
                    if (qtype == protocol.T_AAAA) found = true;
                }
                after_cname = true;
            } else if (rr_type == protocol.T_CNAME) {
                var off2 = rdstart;
                if (name.extractName(reply, n, &off2, namebuf, name.EXTR_NAME_EXTRACT, 0) != 0) {
                    const target = std.mem.sliceTo(namebuf, 0);
                    if (d.cache.insertCname(cur_name, null, target, now, ttl, protocol.F_FORWARD | protocol.F_CNAME) != null) {
                        res.cached += 1;
                        res.cname = target;
                        // 只有「查的就是 CNAME」才算命中；查 A/AAAA 时见到的 CNAME
                        // 只是链上的一环，必须继续追，不能置 found。
                        if (qtype == protocol.T_CNAME) found = true;
                        after_cname = true;
                    }
                    // 无条件推进「当前名字」（与 C 版一致：无论插入成败都改 name 再续链）
                    if (target.len > 0 and target.len < cur_name_buf.len) {
                        @memcpy(cur_name_buf[0..target.len], target);
                        cur_name_buf[target.len] = 0;
                        cur_name = cur_name_buf[0..target.len];
                    }
                }
            } else if ((flags & protocol.F_RR) != 0 and rr_type == qtype) {
                // 高5：SRV / PTR 的正向 RR 缓存（对应 C rfc1035.c:905-990 的 F_RR 分支）。
                // 先按 (名字, F_RR) 整组替换旧记录（与 A/AAAA 的去重机制一致），
                // 再把去压缩重编码后的 RDATA 存进缓存。
                clearFamilyOnce(d, &cleared, &cleared_n, cur_name, protocol.F_RR, now);
                if (cacheRrData(d, reply, n, rdstart, rdlen, rr_type, cur_name, now, ttl)) {
                    res.cached += 1;
                    found = true;
                    after_cname = true;
                }
            }
        }

        p = rdstart + rdlen;
    }

    // 负缓存：对应 C 版 extract_addresses() 末尾的
    //   if (!found && (qtype != T_ANY || (flags & F_NXDOMAIN))) { ... }
    //
    // C 在真正写缓存之前有三重门槛，下面逐条对齐。少任何一条都会让实机
    // A/B 出现「C 不缓存、Zig 却缓存」的差异，进而让失败结果被后续不同类型的
    // 查询（尤其是 ANY）捡去回答。
    //
    //   1. `insert`：A/AAAA 查询为 1；CNAME 及未列入 cache_rr 的类型为 0
    //      —— C 源码原注释：do not cache data from CNAME queries。
    //      所以只有 A/AAAA 能算出类型位，其它 qtype 一律不写。
    //   2. `!option_bool(OPT_NO_NEG)`：配了 no-negcache 就完全不缓存失败结果。
    //      本项目的路由器自动配置里正好开了这一项。
    //   3. `have_soa || daemon->neg_ttl`：应答里带 SOA（TTL 取自 SOA）或显式
    //      配了 --neg-ttl 才写。这里用 findSoa() 做与 C 相同的真实判定
    //      （以前是近似成「权威段非空」，于是上游随手塞的任何记录都算 SOA，
    //      实测会让本该丢弃的负数应答被缓存）。
    const soa_ttl = findSoa(reply, n, qname, namebuf);

    // 负数应答的 TTL：--neg-ttl 优先，否则用 SOA 的 TTL；都给不出时退回 60s。
    //
    // 上限 3600s 是本移植的**有意加固**（C 版不设限）：实测上游 119.29.29.29
    // 对存在的名字的 PTR 查询会回 NXDOMAIN + SOA(TTL=86400)，若照搬 SOA TTL，
    // 一次误判就能让一个正常域名 24 小时解析不了。
    const NEG_TTL_MAX: u32 = 3600;
    const neg_ttl: u32 = if (d.neg_ttl != 0)
        d.neg_ttl
    else
        @min(soa_ttl orelse 60, NEG_TTL_MAX);

    const neg_ok = !d.option(protocol.OPT_NO_NEG) and (soa_ttl != null or d.neg_ttl != 0);

    // PTR 查询的 NXDOMAIN 不允许污染正向名字。
    //
    // 依据（实机可复现）：本路由器上游列表里的 119.29.29.29 对**存在**的名字的
    // PTR 查询会回 NXDOMAIN + SOA；all-servers 竞速时它一旦抢先，这条 NXDOMAIN
    // 就被按「名字不存在」缓存下来，随后该名字的 A/AAAA 查询全部回 NXDOMAIN，
    // 直到负数 TTL 到期 —— 表现为「个别域名时不时解析不了」。
    //
    // C 版靠 `insert = 1`（注释：Can store NXDOMAIN reply for any qtype）把这条
    // 也存下来，但它缓存的是 SOA 的 TTL（这里是 86400s），后果比本移植严重得多。
    // 这里只对「真正的反向名字」（in-addr.arpa / ip6.arpa）保留该语义：
    // 反向区里 NXDOMAIN 才是可信的。
    var arpa_addr: addr.AllAddr = .{ .none = {} };
    const is_reverse_name = name.inArpaName2Addr(qname, &arpa_addr) != 0;
    const nxdomain_cacheable = is_reverse_name or qtype != protocol.T_PTR;

    if (!found and (qtype != protocol.T_ANY or rcode_val == protocol.NXDOMAIN)) {
        if (rcode_val == protocol.NXDOMAIN) {
            res.nxdomain = true;
            // NXDOMAIN 表示「名字不存在」，与查询类型无关，任何 qtype 都存
            // （C 版会先 `flags &= ~(F_IPV4 | F_IPV6 | F_RR)` 再把 insert 置 1）
            if (neg_ok and nxdomain_cacheable) {
                _ = d.cache.insert(qname, null, protocol.C_IN, now, neg_ttl, protocol.F_NEG | protocol.F_NXDOMAIN | protocol.F_FORWARD);
            }
        } else {
            // NODATA：「这个名字没有**该类型**的记录」。注意这里的入口条件是 !found，
            // 而**不是** ancount==0 —— 后者会把「NOERROR + 只有 CNAME + 无最终记录」
            // 这种应答漏出去，导致它每次都得重问上游。C 版就是靠 !found 覆盖这类应答的。
            res.nodata = true;

            // NODATA 与查询类型绑定，所以记录**必须带查询类型位**。查找侧也是按
            // 类型位过滤的，于是「查 A 得到的 NODATA」只对 A 生效。
            //
            // 只给 A/AAAA 存 NODATA，与 C 一致：C 里 qtype == T_A 时 flags |= F_IPV4、
            // qtype == T_AAAA 时 flags |= F_IPV6，两者 insert 都保持 1；MX/TXT/NS/SOA
            // 之类既不在 SRV/PTR/cache_rr 名单里、也没被赋类型位，insert 被置 0。
            //
            // 少了这条限制会跨类型污染：实机验证时观察到「CNAME 查询得出没有记录」
            // 的 NODATA 被后续 ANY 查询捡去回答，客户端看到的是「这个域名什么都没有」。
            const type_bit: u32 = switch (qtype) {
                protocol.T_A => protocol.F_IPV4,
                protocol.T_AAAA => protocol.F_IPV6,
                else => 0,
            };
            if (neg_ok and type_bit != 0) {
                _ = d.cache.insert(qname, null, protocol.C_IN, now, neg_ttl, protocol.F_NEG | protocol.F_FORWARD | type_bit);
            }
        }
    }

    return res;
}

/// 跳过一个 RR（名字 + 10 字节固定头 + rdata）。成功返回 true。
fn skipOneRr(pkt: []u8, n: usize, off: *usize, namebuf: []u8) bool {
    if (name.extractName(pkt, n, off, namebuf, name.EXTR_NAME_EXTRACT, 4) == 0) return false;
    if (off.* + 10 > n) return false;
    const rdlen = protocol.getShort(pkt, off.* + 8);
    off.* += 10 + rdlen;
    return off.* <= n;
}

/// 对应 rfc1035.c: do_doctor()（`--alias`）：把上游应答里的 A 记录按掩码改写，
/// 并清掉 AA 位（改写过的数据不再权威）。返回 true 表示发生了改写。
///
/// 逐字对照 C：
///   * 遍历 **ANSWER + ADDITIONAL** 两段（C 在 `i == ancount` 时用
///     `skip_section(p, nscount, …)` 跳过 AUTHORITY 段）；
///   * 只处理 class=C_IN、type=A、rdlen=4 的记录；
///   * 每条规则：`end == 0` → `(in & mask) == (addr & mask)`；否则要求
///     `in <= addr <= end`（主机序比较）；
///   * 命中即 `addr = (addr & ~mask) | (out & mask)`、清 AA、break（一条 RR 只改一次）。
pub fn doDoctor(d: *Daemon, pkt: []u8, n: usize) bool {
    if (d.doctors.items.len == 0) return false;

    var namebuf: [MAXNAMEBUF]u8 = undefined;
    var off = name.skipQuestions(pkt, n) orelse return false;

    const ancount: usize = protocol.ancount(pkt);
    const nscount: usize = protocol.nscount(pkt);
    const arcount: usize = protocol.arcount(pkt);
    const total = ancount + arcount;

    var done = false;
    var i: usize = 0;
    while (i < total) : (i += 1) {
        // 跳过 AUTHORITY 段（对应 C 的 skip_section）
        if (i == ancount) {
            var k: usize = 0;
            while (k < nscount) : (k += 1) {
                if (!skipOneRr(pkt, n, &off, &namebuf)) return done;
            }
        }

        if (name.extractName(pkt, n, &off, &namebuf, name.EXTR_NAME_EXTRACT, 4) == 0) return done;
        if (off + 10 > n) return done;
        const rr_type = protocol.getShort(pkt, off);
        const rr_class = protocol.getShort(pkt, off + 2);
        const rdlen = protocol.getShort(pkt, off + 8);
        const rdstart = off + 10;
        if (rdstart + rdlen > n) return done;

        if (rr_class == protocol.C_IN and rr_type == protocol.T_A and rdlen == protocol.INADDRSZ) {
            var a_net: u32 = undefined;
            @memcpy(@as([*]u8, @ptrCast(&a_net))[0..4], pkt[rdstart..][0..4]);

            for (d.doctors.items) |doc| {
                if (doc.end == 0) {
                    if ((doc.in & doc.mask) != (a_net & doc.mask)) continue;
                } else {
                    if (@byteSwap(doc.in) > @byteSwap(a_net) or @byteSwap(doc.end) < @byteSwap(a_net))
                        continue;
                }
                a_net = (a_net & ~doc.mask) | (doc.out & doc.mask);
                @memcpy(pkt[rdstart..][0..4], @as([*]const u8, @ptrCast(&a_net))[0..4]);
                pkt[protocol.OFF_HB3] &= ~protocol.HB3_AA;
                log.logQuery(
                    protocol.F_FORWARD | protocol.F_CONFIG | protocol.F_IPV4,
                    std.mem.sliceTo(&namebuf, 0),
                    .{ .ip4 = a_net },
                    null,
                    0,
                );
                done = true;
                break;
            }
        }

        off = rdstart + rdlen;
    }
    return done;
}

// ---------------------------------------------------------------------------
// 本地应答（对应 rfc1035.c: answer_request 的核心路径）
// ---------------------------------------------------------------------------
pub const AnswerResult = struct {
    /// 生成的应答长度；0 表示本地无法回答，需要转发
    len: usize = 0,
    /// 已在缓存中查到（用于日志区分 cached / forwarded）
    from_cache: bool = false,
    /// 应答状态（对应 C 的 ans 累加器）
    answered: bool = false,
};

/// 判断 --address=/dom/ip 规则是否匹配该名字（对应 blockdata.c 的匹配语义）
fn addressRuleMatches(rule: daemon_mod.AddressRule, nm: []const u8) bool {
    if (rule.wildcard) return true;
    return name.hostnameIsSubdomain(rule.domain, nm) != 0;
}

/// 生成一条地址应答（A / AAAA / PTR / CNAME）
fn answerOne(
    header: []u8,
    limit: usize,
    nameoffset: i32,
    p: usize,
    ttl: u32,
    rr_type: u16,
    format: []const u8,
    data: []const u8,
) ?usize {
    return answerOneOff(header, limit, nameoffset, p, ttl, rr_type, format, data, null);
}

/// 带 rdata 名字偏移回写的版本。对应 C 版 add_resource_record 的第 7 个参数
/// `int *offset`：'d' 格式把 rdata 里的名字**写入前**的偏移回传给调用者。
///
/// C 版 answer_request 的 CNAME 链应答正是靠它实现「后续记录的 owner 压缩
/// 指向上一条 CNAME 的 rdata 目标名」：
///     add_resource_record(..., nameoffset, &ansp, ttl, &nameoffset,
///                         T_CNAME, C_IN, "d", cname_target)
/// 每写一条 CNAME，nameoffset 就变成该条 rdata 目标名的偏移；于是同一应答里
/// 的 A/AAAA 记录 owner 显示为 CNAME 目标（nslookup 输出 Name:
/// www.workbuddy.cn.eo.dnse5.com），而不是查询原名。少了这一步，客户端
/// （尤其严格的解析器）会认为 A 记录不属于链上目标，某些应用直接判为无效。
fn answerOneOff(
    header: []u8,
    limit: usize,
    nameoffset: i32,
    p: usize,
    ttl: u32,
    rr_type: u16,
    format: []const u8,
    data: []const u8,
    rdname_offset: ?*i32,
) ?usize {
    return addResourceRecord(header, limit, null, nameoffset, p, ttl, rdname_offset, rr_type, protocol.C_IN, format, data) catch null;
}

/// 对应 rfc1035.c: answer_request()
/// 返回 len>0 表示已经生成应答，调用者直接发送；len==0 表示需要转发。
pub fn answerRequest(
    d: *Daemon,
    header: []u8,
    qlen: usize,
    limit: usize,
    now: i64,
    req: Request,
    source: ?*const addr.SockAddr,
) AnswerResult {
    var result = AnswerResult{};
    if (qlen < protocol.HEADER_SIZE) return result;

    // 整段保存原始查询报文：本地应答不成立、要转上游时原样还原。
    //
    // 对应 C 版 forward.c 的 blockdata_store(saved_question, n, header) /
    // blockdata_retrieve(saved_question, n, header) —— 2021 行的注释把这件
    // 事说得很直白："Get the question back, since it may have been mangled
    // by answer_request()"。
    //
    // 为什么必须还原：本函数是**就地**改写调用方缓冲区的 ——
    //   * setupReply() 把 QR 位置 1、写入 rcode，并清零 an/ns/ar 计数；
    //   * answerOne() 在问题区之后追加 CNAME/地址记录，而那里原本可能是
    //     客户端带来的 EDNS0 OPT 记录。
    // 而转发路径是直接把这段缓冲区当上游查询发出去的：带着 QR=1 的报文会被
    // 上游当成「应答」直接丢弃，被覆盖的 OPT 也会让上游看不到客户端的 EDNS0
    // 能力。缓存未命中（连 CNAME 都没有）时本该不受影响，但「CNAME 命中而目标
    // 类型缺失」这条路径会走到这里，所以还原是必需的。
    //
    // 拷贝长度就是实际报文长度，热路径只多一次几十字节的 memcpy。
    var orig: [protocol.MAXPKT]u8 = undefined;
    const orig_len = @min(qlen, header.len);
    @memcpy(orig[0..orig_len], header[0..orig_len]);

    // 查询级缓存记账：defer 在函数返回前执行，此时 result 已定型。
    // 放在这里而不是函数最开头，是为了让「畸形报文」不被计成缓存未命中。
    defer d.cache.noteQuery(result.from_cache, result.answered);

    // 整段「本地应答」持缓存锁：这里全是纯内存操作（查缓存 / 查 hosts /
    // 匹配 --address 规则），没有任何网络等待，因此持锁不会串行化转发。
    // 反过来，若不持锁，多线程查询会并发改写哈希链与 LRU 链。
    d.cache.lock(d.io);
    defer d.cache.unlock(d.io);

    const nm = req.name;

    // 只处理 IN / ANY（CH TXT 的 version.bind 未移植）
    if (req.qclass != protocol.C_IN and req.qclass != protocol.C_ANY) {
        setupReply(header, protocol.F_RCODE, -1);
        result.len = protocol.HEADER_SIZE;
        result.answered = true;
        return result;
    }

    var namebuf: [MAXNAMEBUF]u8 = undefined;

    // 问题区的名字结束位置即压缩指针的目标
    var ppos: usize = protocol.HEADER_SIZE;
    if (name.extractName(header, qlen, &ppos, &namebuf, name.EXTR_NAME_EXTRACT, 4) == 0) return result;
    const qend = ppos;
    var ansp = name.skipQuestions(header, qlen) orelse return result;

    const nameoffset: i32 = @intCast(protocol.HEADER_SIZE);
    var anscount: u16 = 0;

    // 对应 C 版 answer_request() 里的 `ans`：「本次查询是否真的被回答了」。
    //
    // 注意它**不等于** anscount。沿 CNAME 链答出一条上游 CNAME 会让 anscount
    // 变成 1，但 C 只在
    //     if (crecp->flags & F_CONFIG || qtype == T_CNAME) ans = 1;
    // 时才认账。少了这个区分，AAAA/MX/TXT/ANY 查询会拿到「只有 CNAME、没有
    // 目标记录」的半截应答，并因为 anscount != 0 而停止转发、永远学不到目标
    // 记录 —— 实机 A/B 里 www.qq.com 的 AAAA/TXT/ANY 就是这样。
    var ans_ok: bool = false;

    // 对应 C 版 answer_request() 的 `auth`：AA（权威应答）位的开关，初值 1。
    //
    // C 版函数末尾的注释是 "authoritative - only hosts and DHCP derived names."，
    // 即**只有**从 hosts / DHCP 派生的记录应答时才保持权威；凡是从上游转发
    // 缓存里取出的地址记录（flags 不含 F_HOSTS|F_DHCP）或负记录（F_NEG）
    // 应答时都要清零。
    //
    // 实机 A/B 抓包发现差异：`localhost` / `ip6-localhost` 的 A/AAAA 由 /etc/hosts
    // 应答，C 回 AA=1 而本实现回 AA=0；转发而来的名字（www.baidu.com 等）
    // 两端同为 AA=0。
    //
    // 注意这是**独立于 setupReply() 的另一套机制**：C 的 answer_request 并不调用
    // setup_reply()，而是在末尾按 auth 自行置位。setup_reply() 里那套
    // `flags & (F_IPV4|F_IPV6) -> AA` 只服务于 make_local_answer()（local=/
    // --address=/--server= 路径），不能拿来复用，否则转发来的 A 记录也会被
    // 误标成权威。
    var auth: bool = true;

    _ = source; // 源地址选择（IP_PKTINFO）尚未移植

    // ---- 1. PTR 查询：in-addr.arpa / ip6.arpa ----
    if (req.qtype == protocol.T_PTR and req.qclass == protocol.C_IN) {
        var a: addr.AllAddr = .{ .none = {} };
        const enc = name.inArpaName2Addr(nm, &a);
        if (enc != 0) {
            // --bogus-priv：私网反查直接回 NXDOMAIN
            const is_private = switch (a) {
                .ip4 => |v| addr.privateNet(v, !d.option(protocol.OPT_BOGUSPRIV)),
                .ip6 => |v| addr.privateNet6(&v, !d.option(protocol.OPT_BOGUSPRIV)),
                else => false,
            };
            if (is_private and d.option(protocol.OPT_BOGUSPRIV)) {
                setupReply(header, protocol.F_NXDOMAIN, -1);
                protocol.setNscount(header, 0);
                result.len = ansp;
                result.answered = true;
                return result;
            }

            if (d.cache.findByAddr(a, now, enc)) |crecp| {
                const target = d.cache.getName(crecp);
                const ttl = d.cache.crecTtl(crecp, now, d.local_ttl);
                setupReply(header, protocol.F_NOERR, -1);
                if (answerOne(header, limit, nameoffset, ansp, ttl, protocol.T_PTR, "d", target)) |np| {
                    ansp = np;
                    anscount += 1;
                }
                protocol.setAncount(header, anscount);
                result.len = ansp;
                result.answered = true;
                result.from_cache = true;
                return result;
            }
        }
    }

    // ---- 2. --address=/dom/ip 规则 ----
    //
    // C 版把 address= 规则注册成 SERV_LITERAL_ADDRESS 服务器（带 SERV_4ADDR /
    // SERV_6ADDR），应答走 lookup_domain -> is_local_answer -> make_local_answer。
    // 由此产生一条**必须逐字复刻**的语义：凡是命中规则的名字（含子域、含通配）
    // 一律由本机权威应答，绝不转发上游 ——
    //   * 地址族与查询类型匹配      -> 回该地址，NOERROR + AA；
    //   * 没有该族地址 / 查询非地址类 -> 回 **NODATA**，NOERROR + AA。
    //
    // 本移植把规则存在 address_list 里自行应答，没有进 serverarray，于是
    // 「规则命中但答不出该类型」时会一路漏到上游，拿回 **NXDOMAIN**。这等于
    // 告诉客户端、并让下游负缓存「这个名字不存在」，而它明明存在（有另一族的
    // 地址）—— 一旦某个解析器缓存了 aat4.example 的 NXDOMAIN，连它的 A 记录
    // 也再也解析不了。实测 C(5362) 全 rc=0+AA，本实现全 rc=3，覆盖
    // A/AAAA/MX/TXT/NS/CNAME/PTR/SOA/ANY 与子域。
    if (d.address_list.items.len != 0) {
        // 同一域名可以有多条规则（address=/dom/1.2.3.4 与 address=/dom/::1 是两条），
        // C 版会把它们并进同一个服务器条目。所以命中规则但本条答不出时**不能立即
        // 返回**，要接着扫后面的规则；整个列表扫完仍答不出才回 NODATA。
        var matched = false;
        for (d.address_list.items) |rule| {
            if (!addressRuleMatches(rule, nm)) continue;
            matched = true;

            const ttl = if (d.local_ttl != 0) d.local_ttl else protocol.NEG_TTL;
            if (rule.local and rule.addr4 == null and rule.addr6 == null) {
                setupReply(header, protocol.F_NXDOMAIN, -1);
                result.len = ansp;
                result.answered = true;
                return result;
            }
            if (req.qtype == protocol.T_ANY or req.qtype == protocol.T_A) {
                if (rule.addr4) |v4| {
                    // 传 F_IPV4（而非 F_NOERR）让 setupReply 置 AA 位，
                    // 对应 make_local_answer() 收到 F_IPV4 的行为。
                    setupReply(header, protocol.F_IPV4, -1);
                    const bytes = @as([4]u8, @bitCast(v4));
                    if (answerOne(header, limit, nameoffset, ansp, ttl, protocol.T_A, "4", &bytes)) |np| {
                        ansp = np;
                        anscount += 1;
                    }
                }
            }
            if (req.qtype == protocol.T_ANY or req.qtype == protocol.T_AAAA) {
                if (rule.addr6) |v6| {
                    if (anscount == 0) setupReply(header, protocol.F_IPV6, -1);
                    if (answerOne(header, limit, nameoffset, ansp, ttl, protocol.T_AAAA, "6", &v6)) |np| {
                        ansp = np;
                        anscount += 1;
                    }
                }
            }
            if (anscount != 0) {
                protocol.setAncount(header, anscount);
                result.len = ansp;
                result.answered = true;
                return result;
            }
        }

        // 命中规则但所有规则都答不出本查询：回 NODATA（NOERROR + AA），不转上游。
        // F_IPV4|F_IPV6 只为借 setupReply 置 AA —— 该分支 rcode 仍是 NOERROR。
        if (matched) {
            setupReply(header, protocol.F_IPV4 | protocol.F_IPV6, -1);
            result.len = ansp;
            result.answered = true;
            return result;
        }
    }

    // 本查询期望的**类型位**，供缓存查找使用。
    //
    // 必须只含类型位，绝不能掺进 F_FORWARD：`Cache.findByName()` 的匹配是
    // `(crecp.flags & prot) != 0`（与 C 版 cache_find_by_name 里的 `crecp->flags & prot`
    // 一致），是「交集判空」而不是「类型相等」。C 版所有调用点传的都是单一类型位，
    // 所以交集判空恰好等价于类型精确匹配；一旦我们多传 F_FORWARD，所有正向记录都会
    // 满足交集，于是 AAAA 查询命中了 A 记录、MX 查询命中了 A 记录。
    // 这是实机（192.168.0.1）A/B 对比才暴露出来的：本地套件只查 A，永远碰不到。
    const want: u32 = switch (req.qtype) {
        protocol.T_A => protocol.F_IPV4,
        protocol.T_AAAA => protocol.F_IPV6,
        protocol.T_ANY => protocol.F_IPV4 | protocol.F_IPV6,
        // 高5：SRV / PTR 查缓存里的 F_RR 记录（对应 C 的
        // `cache_find_by_name(NULL, name, now, F_RR | F_NXDOMAIN)`）。
        // 注意 F_RR 会命中同名的**任意** rrtype 记录，所以回放前必须再比对 rrtype。
        protocol.T_SRV, protocol.T_PTR => protocol.F_RR,
        else => 0,
    };

    // ---- 3. 缓存 / hosts：先看 CNAME，再看地址 ----
    if (req.qclass == protocol.C_IN) {
        // 3.1 CNAME 链
        //
        // `chain_nameoffset` 对应 C 版 answer_request 里被 `&nameoffset` 回写
        // 更新的那个变量：每输出一条 CNAME，它就变成该条 rdata 目标名的偏移，
        // 链上后续记录（更深的 CNAME / 最终的 A/AAAA）的 owner 都压缩指向它。
        // 初始值 = 问题区名字偏移，所以没有 CNAME 时一切照旧。
        var cname_name = nm;
        var cname_buf: [MAXNAMEBUF]u8 = undefined;
        var chain_nameoffset = nameoffset;
        var depth: usize = 0;
        while (depth < protocol.CNAME_CHAIN) : (depth += 1) {
            const crecp = d.cache.findByName(cname_name, now, protocol.F_CNAME) orelse break;
            if (d.cache.isStale(crecp, now)) break;

            const ttl = d.cache.crecTtl(crecp, now, d.local_ttl);
            const target = d.cache.getCnameTarget(crecp);

            if (anscount == 0) setupReply(header, protocol.F_NOERR, -1);
            if (answerOneOff(header, limit, chain_nameoffset, ansp, ttl, protocol.T_CNAME, "d", target, &chain_nameoffset)) |np| {
                ansp = np;
                anscount += 1;

                // 对应 C 版 CNAME 链循环里的
                //   if (crecp->flags & F_CONFIG || qtype == T_CNAME) ans = 1;
                // 只有「本地配置出来的 CNAME」（cname=/--cname 等 F_CONFIG 来源）
                // 或客户端本来就在查 CNAME，这条 CNAME 才算回答了问题。
                if ((crecp.flags & protocol.F_CONFIG) != 0 or req.qtype == protocol.T_CNAME) {
                    ans_ok = true;
                }
            }

            if (req.qtype == protocol.T_CNAME) break;

            // 继续沿 CNAME 链找目标地址
            const tlen = @min(target.len, cname_buf.len);
            @memcpy(cname_buf[0..tlen], target[0..tlen]);
            cname_buf[tlen] = 0;
            cname_name = cname_buf[0..tlen];
        }

        if (req.qtype == protocol.T_CNAME and anscount != 0) {
            // C 版 CNAME 链循环**不**改 auth，故此处仍按 auth 置 AA。
            if (auth) header[protocol.OFF_HB3] |= protocol.HB3_AA;
            protocol.setAncount(header, anscount);
            result.len = ansp;
            result.answered = true;
            result.from_cache = true;
            return result;
        }

        // 3.2 地址记录
        if (anscount == 0 or req.qtype != protocol.T_CNAME) {
            if (want != 0) {
                // ---- 高1/高3：--localise-queries ----
                // 逐字对照 C rfc1035.c:2012-2029（判定）与 :2084-2089（过滤）：
                //   1) 先扫一遍同名记录：若**存在**一条 F_HOSTS 的 A 记录与「查询到达的
                //      本地地址」同网段 → localise = 1；
                //   2) 之后遍历时只对 **F_HOSTS** 记录跳过不同网段的（DHCP / 上游缓存的
                //      记录不受影响）—— 于是多网段主机名只回客户端所在网段的那个地址。
                // 触发条件与 C 一致：仅 A 查询、OPT_LOCALISE 已配、local_addr != 0。
                var localise = false;
                if (d.option(protocol.OPT_LOCALISE) and want == protocol.F_IPV4 and req.local4 != 0) {
                    var scan = d.cache.findByName(cname_name, now, want);
                    while (scan) |sc| {
                        if ((sc.flags & protocol.F_HOSTS) != 0 and
                            sameNet4(sc.addr.ip4, req.local4, req.netmask4))
                        {
                            localise = true;
                            break;
                        }
                        scan = d.cache.findByNameFrom(sc, cname_name, now, want);
                    }
                }

                // 同名记录可能有多条（CDN 的 A 记录常见十几条），必须全部应答。
                // 只答第一条会让客户端把所有流量压到同一台机器上，负载均衡与
                // 容灾一起失效 —— 这是实机测试发现的行为差异：C 版通过
                // cache_find_by_name() 沿哈希链续查，直到没有同类型记录为止。
                var cur = d.cache.findByName(cname_name, now, want);
                while (cur) |crecp| {
                    // 先取出下一条再应答当前条：应答会往报文尾部追加数据。
                    const next = d.cache.findByNameFrom(crecp, cname_name, now, want);

                    // ANY 不用「转发来的」缓存记录应答，只允许 hosts / DHCP / 配置来源。
                    // 对应 C 版 answer_request 里那句
                    //   if (qtype == T_ANY && !(crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG)))
                    //     break;
                    // 原注释：don't answer wildcard queries with data not from
                    // /etc/hosts or DHCP leases。意义是避免 ANY 变成「把缓存里这个
                    // 名字的全部记录一次性吐出去」的放大/信息泄露通道。
                    // 差异：C 用 break 直接中断遍历，我们改成 continue 继续扫完整个桶 ——
                    // C 能提前 break 是因为它顺手把命中的条目挪到链首、顺序不固定，
                    // 扫完整个桶才能稳定地找到同名的 hosts 记录，代价可以忽略。
                    if (req.qtype == protocol.T_ANY and
                        (crecp.flags & (protocol.F_HOSTS | protocol.F_DHCP | protocol.F_CONFIG)) == 0)
                    {
                        cur = next;
                        continue;
                    }

                    if (!d.cache.isStale(crecp, now)) {
                        // 类型匹配的负记录（NODATA）：对应 C 里缓存循环体内
                        // `else if (crecp->flags & F_NEG) { if (qtype != T_ANY) { ans = 1; ...} }`
                        // 那段。写入时带了类型位，所以这里只会命中「同类型」的 NODATA；
                        // T_ANY 在上面已被 hosts/DHCP/config 过滤挡掉，走到这里必然是具体类型。
                        //
                        // 直接回空应答，但**保留链上已写出的 CNAME** —— C 版不会丢弃
                        // 已经累积的应答内容（它只是不再往里加记录）。
                        if ((crecp.flags & protocol.F_NEG) != 0) {
                            // C 版同处 `auth = 0;`：负应答不权威。
                            auth = false;
                            setupReply(header, protocol.F_NOERR, -1);
                            protocol.setAncount(header, anscount);
                            result.len = ansp;
                            result.answered = true;
                            result.from_cache = true;
                            return result;
                        }

                        // 高1：localise 命中时，只回与「查询到达地址」同网段的 **hosts** 记录
                        //（对应 C rfc1035.c:2086-2089 的 `continue`）。DHCP/缓存记录不过滤。
                        if (localise and (crecp.flags & protocol.F_HOSTS) != 0 and
                            !sameNet4(crecp.addr.ip4, req.local4, req.netmask4))
                        {
                            cur = next;
                            continue;
                        }

                        const ttl = d.cache.crecTtl(crecp, now, d.local_ttl);

                        // 对应 C 版 rfc1035.c 的
                        //     if (!(crecp->flags & (F_HOSTS | F_DHCP))) auth = 0;
                        // 从上游转发缓存取出的地址记录不是本机权威数据。
                        // 注意 C 这里只认 F_HOSTS|F_DHCP，**不含 F_CONFIG**。
                        if ((crecp.flags & (protocol.F_HOSTS | protocol.F_DHCP)) == 0) auth = false;

                        if (anscount == 0) setupReply(header, protocol.F_NOERR, -1);
                        var space_out = false;
                        // owner 用 chain_nameoffset 而非 nameoffset：
                        // 走过 CNAME 链后它指向链尾 CNAME 的 rdata 目标名（C 版
                        // 语义：A 记录的 owner 显示为 CNAME 目标）；没走链时
                        // chain_nameoffset == nameoffset == 问题区名字偏移。
                        switch (crecp.addr) {
                            .ip4 => |v| {
                                const bytes = @as([4]u8, @bitCast(v));
                                if (answerOne(header, limit, chain_nameoffset, ansp, ttl, protocol.T_A, "4", &bytes)) |np| {
                                    ansp = np;
                                    anscount += 1;
                                    ans_ok = true;
                                } else space_out = true;
                            },
                            .ip6 => |v| {
                                if (answerOne(header, limit, chain_nameoffset, ansp, ttl, protocol.T_AAAA, "6", &v)) |np| {
                                    ansp = np;
                                    anscount += 1;
                                    ans_ok = true;
                                } else space_out = true;
                            },
                            .rr => |r| {
                                // 高5：SRV / PTR 从缓存回放。F_RR 的查找只按 F_RR 位匹配，
                                // 会命中同名的任意 rrtype 记录，所以这里必须再比一次 rrtype
                                //（对应 C answer_request 的 `rrtype == qtype`）。
                                if (r.rrtype == req.qtype) {
                                    if (answerOne(header, limit, chain_nameoffset, ansp, ttl, r.rrtype, "s", r.data)) |np| {
                                        ansp = np;
                                        anscount += 1;
                                        ans_ok = true;
                                    } else space_out = true;
                                }
                            },
                            else => {},
                        }
                        // 报文写不下了就没必要继续遍历
                        if (space_out) break;
                    }
                    cur = next;
                }

                // round-robin（C 默认开启，`--no-round-robin` 关闭）：本应答写完后把
                // 「第一条同名同族记录」移到桶尾，于是**下一次**应答从下一条记录开头，
                // 同名多条 A/AAAA 在连续查询间轮转 —— 对应 C 版 cache_find_by_name()
                // 每次查找重排哈希链的效果。单条记录时该调用内部直接返回。
                if (!d.option(protocol.OPT_NORR) and req.qtype != protocol.T_CNAME)
                    d.cache.rotateForwardAddrs(cname_name, want);
            }
        }

        // 3.3 负缓存：命中 F_NEG 直接回 NXDOMAIN / NODATA
        //
        // prot 只传 F_NEG。以前写成 `F_NEG | F_FORWARD`，同样因为「交集判空」而
        // 命中任意一条正向记录 —— 表现为 MX 查询对已缓存的 A 记录回了 NODATA，
        // 客户端拿到「这个域名没有 MX」的错误结论。
        //
        // 门槛用 !ans_ok 而不是 anscount == 0：只答出一条**上游** CNAME 不算
        // 回答了问题（见 ans_ok 的说明），此时仍应继续尝试负缓存、否则转上游。
        if (!ans_ok) {
            if (d.cache.findByName(nm, now, protocol.F_NEG)) |crecp| {
                if (!d.cache.isStale(crecp, now)) {
                    const is_nx = (crecp.flags & protocol.F_NXDOMAIN) != 0;

                    // NXDOMAIN 表示「名字不存在」，与查询类型无关，任何类型都可以
                    // 用它（对应 C 版 answer_request 开头那句
                    // cache_find_by_name(NULL, name, now, F_CNAME | F_NXDOMAIN)）。
                    //
                    // NODATA 表示「这个名字没有**该类型**的记录」，所以必须再校验
                    // **记录自己的类型位**是否与本次查询相符 —— 只看 `want != 0`
                    // 只能说明「这是 A/AAAA 查询」，说明不了「这条负记录讲的正是这个
                    // 类型」。漏掉这步的后果（实机复现）：一条 AAAA 的 NODATA
                    // （F_NEG|F_IPV6）会把同名域名的 **A** 查询也答成空应答。
                    //
                    //   复现：干净实例上 1) 查 ghfast.top/AAAA → NODATA（该名字确实
                    //   没有 AAAA，正确）2) 紧接着查 ghfast.top/A → 被这条 AAAA 负
                    //   记录截胡，回 NODATA（错，应回 A 记录）。C 版此时正常回 an=1。
                    //
                    //   真实危害：上游对「有 A 无 AAAA」的名字（ghfast.top /
                    //   api.github.com / github.io …）回 AAAA 的 NODATA 后，浏览器等
                    //   客户端一旦查询过 AAAA，该名字的 A 就会持续解析不了，直到负数
                    //   TTL（最长 1h）到期；期间负记录若被后续 AAAA 查询不断刷新，
                    //   则表现为「个别域名长时间无法解析」。
                    //
                    // C 版不会踩到，是因为它这个位置的查找只匹配 F_CNAME | F_NXDOMAIN，
                    // 纯 NODATA 记录根本进不来 —— NODATA 只在**按类型过滤**的
                    // cache_find_by_name(..., F_IPV4/F_IPV6) 循环里才被使用
                    // （即下面 3.2 的命中分支）。这里补上同样的类型约束。
                    //
                    // T_ANY 也排除：对应 C 里 `if (qtype != T_ANY) { ans = 1; ... }`。
                    // ANY 查询若被一条 NODATA 记录答成空包，客户端会以为「这个名字
                    // 什么都没有」，而实际上只是某个类型没记录。
                    if (is_nx or (want != 0 and (crecp.flags & want) != 0 and
                        req.qtype != protocol.T_ANY))
                    {
                        setupReply(header, if (is_nx) protocol.F_NXDOMAIN else protocol.F_NOERR, -1);
                        result.len = ansp;
                        result.answered = true;
                        result.from_cache = true;
                        return result;
                    }
                }
            }
        }
    }

    // 只有「真的回答了问题」才把应答交出去；否则必须转上游。
    //
    // 这里曾经写成 `if (anscount != 0)`，等价于「应答段里有东西就算答了」，
    // 于是「只沿链带出一条上游 CNAME」也被当成已回答。实测 www.qq.com：
    // 先查 A（缓存到 CNAME + 目标 A），再查 AAAA 时只回一条 CNAME 就收工，
    // 从不转发、也永远学不到目标 AAAA；C 版此时会转发并回 CNAME + AAAA。
    if (ans_ok) {
        // 对应 C 版 answer_request() 末尾的
        //     /* authoritative - only hosts and DHCP derived names. */
        //     if (auth) header->hb3 |= HB3_AA;
        // hosts / DHCP 派生的地址记录一路走到这里时 auth 仍为 true，补上 AA 位。
        if (auth) header[protocol.OFF_HB3] |= protocol.HB3_AA;
        protocol.setAncount(header, anscount);
        result.len = ansp;
        result.answered = true;
        result.from_cache = true;
        return result;
    }
    // ---- 4./5. 本地域判定与 --domain-needed ----
    //
    // 严格对照 forward.c:347-361（tcp_request 里 2598-2611 是同一段）：
    //
    //     if (lookup_domain(name, gotname, &first, &last))
    //       flags = is_local_answer(now, first, name);   /* 注意不是「查到就算本地」 */
    //     else { flags = 0; }
    //
    //     if (!flags && option_bool(OPT_NODOTS_LOCAL) &&
    //         (gotname & (F_IPV4|F_IPV6)) && !strchr(name, '.') && strlen(name))
    //       flags = check_for_local_domain(name, now) ? F_NOERR : F_NXDOMAIN;
    //
    // 之前的实现把「lookup_domain 命中」直接当成本地域，于是默认上游也会
    // 被误判为本地，导致 --domain-needed 的无点名字回成了 NOERROR。
    var local: u32 = 0;
    if (d.serverarray.items.len != 0) {
        if (dmn.lookupDomain(d, nm, req.flags)) |srv| {
            local = dmn.isLocalAnswer(d, srv, nm);
        }
    }

    // 4.1 本域没有这个记录 -> NXDOMAIN；本域有这个名字但类型不符 -> NoData
    if (local != 0) {
        const fl: u32 = if ((local & (protocol.F_NXDOMAIN | protocol.F_NOERR)) != 0)
            local
        else
            protocol.F_NOERR; // 只配了 IPv4 却查 AAAA 之类：NODATA
        setupReply(header, fl, -1);
        protocol.setNscount(header, 0);
        result.len = ansp;
        result.answered = true;
        return result;
    }

    // 5. --domain-needed：无点的 A/AAAA 查询不转发上游
    if (d.option(protocol.OPT_NODOTS_LOCAL) and
        (req.flags & (protocol.F_IPV4 | protocol.F_IPV6)) != 0 and
        nm.len != 0 and std.mem.indexOfScalar(u8, nm, '.') == null)
    {
        const fl: u32 = if (dmn.checkForLocalDomain(d, nm)) protocol.F_NOERR else protocol.F_NXDOMAIN;
        setupReply(header, fl, -1);
        protocol.setNscount(header, 0);
        result.len = ansp;
        result.answered = true;
        return result;
    }

    // ---- 6. --filterwin2k（OPT_FILTER）----
    // 对应 rfc1035.c:2206 / 2282：过滤 Windows 主机的多余查询
    //   - SOA 查询直接回 NODATA
    //   - SRV 查询（或含下划线的 ANY）直接回 NODATA
    if (d.option(protocol.OPT_FILTER) and
        (req.qtype == protocol.T_SOA or
            req.qtype == protocol.T_SRV or
            (req.qtype == protocol.T_ANY and std.mem.indexOfScalar(u8, nm, '_') != null)))
    {
        setupReply(header, protocol.F_NOERR, -1);
        result.len = ansp;
        result.answered = true;
        return result;
    }

    _ = qend;

    // 决定转上游：把缓冲区还原成客户端原始查询（见函数开头 orig 的说明），
    // 否则 setupReply 写入的 QR=1 / rcode 以及被追加/覆盖的应答字节会跟着
    // 一起发给上游。
    @memcpy(header[0..orig_len], orig[0..orig_len]);
    return result;
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------
const testing = std.testing;

/// 构造一条最小查询报文（1 个问题，IN 类），返回长度
fn buildQuery(pkt: []u8, nm: []const u8, qtype: u16) usize {
    @memset(pkt, 0);
    protocol.setId(pkt, 0x1234);
    protocol.setQdcount(pkt, 1);
    var n: usize = protocol.HEADER_SIZE;
    var labels = std.mem.splitScalar(u8, nm, '.');
    while (labels.next()) |part| {
        if (part.len == 0) continue;
        pkt[n] = @intCast(part.len);
        n += 1;
        @memcpy(pkt[n..][0..part.len], part);
        n += part.len;
    }
    pkt[n] = 0;
    n += 1;
    protocol.putShort(pkt, n, qtype);
    n += 2;
    protocol.putShort(pkt, n, protocol.C_IN);
    n += 2;
    return n;
}

/// 从应答报文里读出第一段 rdata 的原始字节（无应答返回空切片）
fn firstRdata(pkt: []const u8, len: usize) []const u8 {
    if (protocol.ancount(pkt) == 0) return &[_]u8{};
    var p = name.skipQuestions(pkt, len) orelse return &[_]u8{};
    p = name.skipName(pkt, p, len, 10) orelse return &[_]u8{};
    if (p + 10 > len) return &[_]u8{};
    const rdlen = protocol.getShort(pkt, p + 8);
    const rd = p + 10;
    if (rd + rdlen > len) return &[_]u8{};
    return pkt[rd..][0..rdlen];
}

/// 第一段应答记录的 RR 类型
fn firstRrtype(pkt: []const u8, len: usize) u16 {
    if (protocol.ancount(pkt) == 0) return 0;
    var p = name.skipQuestions(pkt, len) orelse return 0;
    p = name.skipName(pkt, p, len, 10) orelse return 0;
    if (p + 2 > len) return 0;
    return protocol.getShort(pkt, p);
}

// ---------------------------------------------------------------------------
// CNAME 链回归测试（实机环境发现）
//
// 背景：单元测试原先只覆盖「指针模式」的 insertCname，而生产路径
// （extractAddresses）走的是「目标名字」模式，于是这个 bug 一路躲过了
// 全部本地测试，直到把二进制部署到路由器上查真实域名才暴露：
//   缓存命中的应答里 CNAME 目标名为空，且链上的 A 记录整个丢失。
// ---------------------------------------------------------------------------

/// 测试辅助：按 DNS wire 格式写入域名
fn putName(pkt: []u8, n0: usize, nm: []const u8) usize {
    var n = n0;
    var labels = std.mem.splitScalar(u8, nm, '.');
    while (labels.next()) |part| {
        if (part.len == 0) continue;
        pkt[n] = @intCast(part.len);
        n += 1;
        @memcpy(pkt[n..][0..part.len], part);
        n += part.len;
    }
    pkt[n] = 0;
    return n + 1;
}

/// 测试辅助：域名编码后的字节数
fn wireLen(nm: []const u8) usize {
    var n: usize = 1; // 末尾的根标签
    var labels = std.mem.splitScalar(u8, nm, '.');
    while (labels.next()) |part| {
        if (part.len != 0) n += 1 + part.len;
    }
    return n;
}

/// 测试辅助：构造「qname CNAME target」+「target A ip」的上游应答
fn buildCnameReply(pkt: []u8, qname: []const u8, target: []const u8, ip: [4]u8) usize {
    @memset(pkt, 0);
    protocol.setId(pkt, 0x1234);
    protocol.putShort(pkt, 2, 0x8180); // QR=1, RD, RA
    protocol.setQdcount(pkt, 1);
    protocol.setAncount(pkt, 2);

    var n: usize = protocol.HEADER_SIZE;
    n = putName(pkt, n, qname);
    protocol.putShort(pkt, n, protocol.T_A);
    n += 2;
    protocol.putShort(pkt, n, protocol.C_IN);
    n += 2;

    // RR1: qname CNAME target
    n = putName(pkt, n, qname);
    protocol.putShort(pkt, n, protocol.T_CNAME);
    n += 2;
    protocol.putShort(pkt, n, protocol.C_IN);
    n += 2;
    protocol.putLong(pkt, n, 600);
    n += 4;
    protocol.putShort(pkt, n, @intCast(wireLen(target)));
    n += 2;
    n = putName(pkt, n, target);

    // RR2: target A ip
    n = putName(pkt, n, target);
    protocol.putShort(pkt, n, protocol.T_A);
    n += 2;
    protocol.putShort(pkt, n, protocol.C_IN);
    n += 2;
    protocol.putLong(pkt, n, 60);
    n += 4;
    protocol.putShort(pkt, n, 4);
    n += 2;
    @memcpy(pkt[n..][0..4], &ip);
    n += 4;

    return n;
}

test "doDoctor：--alias 按掩码改写 A 记录并清 AA（与 C 实机一致）" {
    const alloc = std.testing.allocator;
    var d = Daemon{ .allocator = alloc };
    defer d.doctors.deinit(alloc);
    // 172.16.0.0/12 -> 10.0.0.0/12（C 实机：172.16.5.5 ⇒ 10.0.5.5，AA 清零）
    try d.doctors.append(alloc, .{
        .in = @as(u32, @bitCast([4]u8{ 172, 16, 0, 0 })),
        .out = @as(u32, @bitCast([4]u8{ 10, 0, 0, 0 })),
        .mask = @as(u32, @bitCast([4]u8{ 255, 240, 0, 0 })),
    });

    var pkt = [_]u8{0} ** 64;
    pkt[protocol.OFF_HB3] = protocol.HB3_QR | protocol.HB3_AA;
    protocol.putShort(&pkt, protocol.OFF_QDCOUNT, 1);
    protocol.setAncount(&pkt, 1);
    var off: usize = protocol.HEADER_SIZE;
    const qn = [_]u8{ 5, 'a', 'l', 'i', 'a', 's', 4, 't', 'e', 's', 't', 0 };
    @memcpy(pkt[off..][0..qn.len], &qn);
    off += qn.len;
    protocol.putShort(&pkt, off, protocol.T_A);
    off += 2;
    protocol.putShort(&pkt, off, protocol.C_IN);
    off += 2;
    protocol.putShort(&pkt, off, 0xC00C); // owner = 问题区名字
    off += 2;
    protocol.putShort(&pkt, off, protocol.T_A);
    off += 2;
    protocol.putShort(&pkt, off, protocol.C_IN);
    off += 2;
    protocol.putLong(&pkt, off, 60);
    off += 4;
    protocol.putShort(&pkt, off, 4);
    off += 2;
    @memcpy(pkt[off..][0..4], &[_]u8{ 172, 16, 5, 5 });
    off += 4;
    const n = off;

    try testing.expect(doDoctor(&d, &pkt, n));
    try testing.expectEqual(@as(u8, 0), pkt[protocol.OFF_HB3] & protocol.HB3_AA);
    try testing.expectEqualSlices(u8, &[_]u8{ 10, 0, 5, 5 }, pkt[off - 4 ..][0..4]);

    // 不含掩码网段的地址：不改写、AA 保留
    @memcpy(pkt[off - 4 ..][0..4], &[_]u8{ 192, 168, 1, 1 });
    pkt[protocol.OFF_HB3] |= protocol.HB3_AA;
    try testing.expect(!doDoctor(&d, &pkt, n));
    try testing.expect(pkt[protocol.OFF_HB3] & protocol.HB3_AA != 0);
}

test "extractAddresses：CNAME 目标名与链上 A 记录都要落在正确位置（实机回归）" {
    const allocator = testing.allocator;
    var d = daemon_mod.Daemon{ .allocator = allocator };
    defer d.deinit();
    d.cache = try cache.Cache.init(allocator, 64);
    d.cache_ready = true;

    const now: i64 = 1000;
    const qname = "www.baidu.com";
    const target = "www.a.shifen.com";
    const ip = [4]u8{ 183, 2, 172, 177 };

    var pkt: [512]u8 = undefined;
    var namebuf: [MAXNAMEBUF]u8 = undefined;
    const n = buildCnameReply(&pkt, qname, target, ip);

    const res = extractAddresses(&d, &pkt, n, now, qname, protocol.T_A, protocol.C_IN, &namebuf);
    try testing.expectEqual(@as(usize, 2), res.cached);

    // ① CNAME 记录的目标名必须取得到（旧实现只认指针模式，这里恒为空串）
    const cn = d.cache.findByName(qname, now, protocol.F_CNAME);
    try testing.expect(cn != null);
    try testing.expectEqualStrings(target, d.cache.getCnameTarget(cn.?));

    // ② A 记录必须挂在 CNAME 目标名下
    const a = d.cache.findByName(target, now, protocol.F_IPV4);
    try testing.expect(a != null);
    try testing.expectEqual(@as(u32, @bitCast(ip)), a.?.addr.ip4);

    // ③ 原始名字下不该再挂着这条 A 记录
    try testing.expect(d.cache.findByName(qname, now, protocol.F_IPV4) == null);
}

test "高5：SRV 正向缓存必须把压缩指针解压后重编码（实机 A/B 回归）" {
    const allocator = testing.allocator;
    var d = daemon_mod.Daemon{ .allocator = allocator };
    defer d.deinit();
    d.cache = try cache.Cache.init(allocator, 64);
    d.cache_ready = true;

    const now: i64 = 1000;
    const qname = "_sip._tcp.test";

    var pkt: [256]u8 = [_]u8{0} ** 256;
    protocol.putShort(&pkt, 0, 0x1234);
    pkt[protocol.OFF_HB3] = protocol.HB3_QR;
    protocol.putShort(&pkt, protocol.OFF_QDCOUNT, 1);
    protocol.setAncount(&pkt, 1);
    var off: usize = protocol.HEADER_SIZE;
    const qn = [_]u8{ 4, '_', 's', 'i', 'p', 4, '_', 't', 'c', 'p', 4, 't', 'e', 's', 't', 0 };
    @memcpy(pkt[off..][0..qn.len], &qn);
    off += qn.len;
    protocol.putShort(&pkt, off, protocol.T_SRV);
    off += 2;
    protocol.putShort(&pkt, off, protocol.C_IN);
    off += 2;
    // answer：owner 用压缩指针指向问题名
    protocol.putShort(&pkt, off, 0xC00C);
    off += 2;
    protocol.putShort(&pkt, off, protocol.T_SRV);
    off += 2;
    protocol.putShort(&pkt, off, protocol.C_IN);
    off += 2;
    protocol.putLong(&pkt, off, 300);
    off += 4;
    // rdata = prio(10) weight(20) port(5060) + target 压缩指针 0xC00C
    protocol.putShort(&pkt, off, 8);
    off += 2;
    protocol.putShort(&pkt, off, 10);
    off += 2;
    protocol.putShort(&pkt, off, 20);
    off += 2;
    protocol.putShort(&pkt, off, 5060);
    off += 2;
    protocol.putShort(&pkt, off, 0xC00C);
    off += 2;
    const n = off;

    var namebuf: [MAXNAMEBUF]u8 = undefined;
    const res = extractAddresses(&d, &pkt, n, now, qname, protocol.T_SRV, protocol.C_IN, &namebuf);
    try testing.expectEqual(@as(usize, 1), res.cached);

    const rec = d.cache.findByName(qname, now, protocol.F_RR);
    try testing.expect(rec != null);
    try testing.expectEqual(@as(u16, protocol.T_SRV), rec.?.addr.rr.rrtype);
    // 存的必须是「6 字节固定 + 解压后的完整名字」，绝不能留着压缩指针 0xC00C
    const want = [_]u8{
        0,   10,  0,   20,  0x13, 0xc4, // prio/weight/port
        4,   '_', 's', 'i', 'p',  4,   '_', 't', 'c', 'p', 4, 't', 'e', 's', 't', 0,
    };
    try testing.expectEqualSlices(u8, &want, rec.?.addr.rr.data);
}

test "高5：SRV 命中缓存后由本地应答（rdata 原样回放）" {
    const allocator = testing.allocator;
    var d = daemon_mod.Daemon{ .allocator = allocator };
    defer d.deinit();
    d.cache = try cache.Cache.init(allocator, 64);
    d.cache_ready = true;

    const now: i64 = 1000;
    const qname = "_sip._tcp.test";
    const rdata = [_]u8{
        0, 10, 0, 20, 0x13, 0xc4,
        4, '_', 's', 'i', 'p', 4, '_', 't', 'c', 'p', 4, 't', 'e', 's', 't', 0,
    };
    _ = d.cache.insert(
        qname,
        .{ .rr = .{ .rrtype = protocol.T_SRV, .data = &rdata, .owned = false } },
        protocol.C_IN,
        now,
        300,
        protocol.F_FORWARD | protocol.F_RR,
    );

    var pkt: [512]u8 = undefined;
    var namebuf: [MAXNAMEBUF]u8 = undefined;
    const src4: addr.SockAddr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 127, 0, 0, 1 }), 5353);
    const n = buildQuery(&pkt, qname, protocol.T_SRV);
    const req = extractRequest(&pkt, n, &namebuf) orelse return error.TestUnexpectedResult;
    const res = answerRequest(&d, &pkt, n, pkt.len, now, req, &src4);
    try testing.expect(res.answered and res.from_cache);
    try testing.expectEqual(protocol.T_SRV, firstRrtype(&pkt, res.len));
    try testing.expectEqualSlices(u8, &rdata, firstRdata(&pkt, res.len));
}

test "answerRequest：缓存里的 CNAME 链要能答出 CNAME + A（实机回归）" {
    const allocator = testing.allocator;
    var d = daemon_mod.Daemon{ .allocator = allocator };
    defer d.deinit();
    d.cache = try cache.Cache.init(allocator, 64);
    d.cache_ready = true;

    const now: i64 = 1000;
    const qname = "www.baidu.com";
    const target = "www.a.shifen.com";
    const ip = [4]u8{ 183, 2, 172, 177 };

    var pkt: [512]u8 = undefined;
    var namebuf: [MAXNAMEBUF]u8 = undefined;

    // 先把上游应答灌进缓存（模拟转发拿到应答后的动作）
    const rn = buildCnameReply(&pkt, qname, target, ip);
    _ = extractAddresses(&d, &pkt, rn, now, qname, protocol.T_A, protocol.C_IN, &namebuf);

    // 再以客户端身份查同一个名字 —— 应当由缓存直接答出
    var q: [512]u8 = undefined;
    const qn = buildQuery(&q, qname, protocol.T_A);
    const req = extractRequest(&q, qn, &namebuf) orelse return error.TestUnexpectedResult;
    const src4: addr.SockAddr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 127, 0, 0, 1 }), 5353);
    const res = answerRequest(&d, &q, qn, q.len, now, req, &src4);

    try testing.expect(res.answered);
    try testing.expect(res.from_cache);
    // CNAME 与 A 两条都要在 —— 缺任意一条就是这次实机踩到的坑
    try testing.expectEqual(@as(u16, 2), protocol.ancount(&q));
    try testing.expectEqual(protocol.T_CNAME, firstRrtype(&q, res.len));

    // 第一条 CNAME 的 rdata 解出来应当就是目标名
    var p = name.skipQuestions(&q, res.len) orelse return error.TestUnexpectedResult;
    p = name.skipName(&q, p, res.len, 10) orelse return error.TestUnexpectedResult;
    var off = p + 10;
    var nb: [MAXNAMEBUF]u8 = undefined;
    _ = name.extractName(&q, res.len, &off, &nb, name.EXTR_NAME_EXTRACT, 0);
    try testing.expectEqualStrings(target, std.mem.sliceTo(&nb, 0));
}

test "answerRequest：上游 CNAME 命中但目标缺该类型时必须转上游（实机回归 www.qq.com）" {
    const allocator = testing.allocator;
    var d = daemon_mod.Daemon{ .allocator = allocator };
    defer d.deinit();
    d.cache = try cache.Cache.init(allocator, 64);
    d.cache_ready = true;

    const now: i64 = 1000;
    const qname = "www.qq.com";
    const target = "www.qq.com.cdn.example";
    const ip = [4]u8{ 1, 2, 3, 4 };
    var namebuf: [MAXNAMEBUF]u8 = undefined;

    // 上游应答里只有 CNAME + 目标的 A 记录：于是缓存里「有 CNAME、没有目标 AAAA」
    var pkt: [512]u8 = undefined;
    const rn = buildCnameReply(&pkt, qname, target, ip);
    _ = extractAddresses(&d, &pkt, rn, now, qname, protocol.T_A, protocol.C_IN, &namebuf);
    try testing.expect(d.cache.findByName(qname, now, protocol.F_CNAME) != null);

    var q: [512]u8 = undefined;
    const src4: addr.SockAddr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 127, 0, 0, 1 }), 5353);

    // 客户端改查 AAAA：C 版此时会转上游，绝不能拿「只有一条 CNAME」的半截应答糊弄
    const qn = buildQuery(&q, qname, protocol.T_AAAA);
    const req = extractRequest(&q, qn, &namebuf) orelse return error.TestUnexpectedResult;
    const res = answerRequest(&d, &q, qn, q.len, now, req, &src4);

    try testing.expect(!res.answered);
    try testing.expectEqual(@as(usize, 0), res.len);

    // 既然要转上游，缓冲区必须被还原成「查询」形态：
    // setupReply 曾把 QR 位置 1，若原样发给上游会被当成应答丢弃。
    try testing.expectEqual(@as(u8, 0), q[protocol.OFF_HB3] & protocol.HB3_QR);

    // 对照 1：同一条链查 A 时应当正常答出 CNAME + A
    const qn2 = buildQuery(&q, qname, protocol.T_A);
    const req2 = extractRequest(&q, qn2, &namebuf) orelse return error.TestUnexpectedResult;
    const res2 = answerRequest(&d, &q, qn2, q.len, now, req2, &src4);
    try testing.expect(res2.answered);
    try testing.expectEqual(@as(u16, 2), protocol.ancount(&q));

    // 对照 2：显式查 CNAME 时，链上那条 CNAME 本身就足以回答
    const qn3 = buildQuery(&q, qname, protocol.T_CNAME);
    const req3 = extractRequest(&q, qn3, &namebuf) orelse return error.TestUnexpectedResult;
    const res3 = answerRequest(&d, &q, qn3, q.len, now, req3, &src4);
    try testing.expect(res3.answered);
    try testing.expectEqual(@as(u16, 1), protocol.ancount(&q));
}

/// 测试辅助：收集应答里所有 A 记录的地址，返回条数
fn collectA(pkt: []const u8, len: usize, out: *[8][4]u8) usize {    var cnt: usize = 0;
    var p = name.skipQuestions(pkt, len) orelse return 0;
    const an = protocol.ancount(pkt);
    var i: u16 = 0;
    while (i < an) : (i += 1) {
        p = name.skipName(pkt, p, len, 10) orelse return cnt;
        if (p + 10 > len) return cnt;
        const rt = protocol.getShort(pkt, p);
        const rdlen = protocol.getShort(pkt, p + 8);
        const rd = p + 10;
        if (rd + rdlen > len) return cnt;
        if (rt == protocol.T_A and rdlen == 4 and cnt < out.len) {
            @memcpy(&out[cnt], pkt[rd..][0..4]);
            cnt += 1;
        }
        p = rd + rdlen;
    }
    return cnt;
}

test "answerRequest：同一名字的多条 A 记录必须全部应答（实机回归）" {
    const allocator = testing.allocator;
    var d = daemon_mod.Daemon{ .allocator = allocator };
    defer d.deinit();
    d.cache = try cache.Cache.init(allocator, 64);
    d.cache_ready = true;

    const now: i64 = 1000;
    const nm = "cdn.example";
    // 模拟 CDN 域名：一个名字挂多条 A 记录
    const addrs = [3][4]u8{ .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 2 }, .{ 10, 0, 0, 3 } };
    for (addrs) |b| {
        const a: addr.AllAddr = .{ .ip4 = @bitCast(b) };
        _ = d.cache.insert(nm, a, protocol.C_IN, now, 60, protocol.F_FORWARD | protocol.F_IPV4);
    }

    var q: [512]u8 = undefined;
    var namebuf: [MAXNAMEBUF]u8 = undefined;
    const qn = buildQuery(&q, nm, protocol.T_A);
    const req = extractRequest(&q, qn, &namebuf) orelse return error.TestUnexpectedResult;
    const src4: addr.SockAddr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 127, 0, 0, 1 }), 5353);
    const res = answerRequest(&d, &q, qn, q.len, now, req, &src4);

    try testing.expect(res.answered);
    // 旧实现只答第一条（ancount == 1），客户端会把流量全压到同一台机器上
    try testing.expectEqual(@as(u16, 3), protocol.ancount(&q));

    var got: [8][4]u8 = undefined;
    const n = collectA(&q, res.len, &got);
    try testing.expectEqual(@as(usize, 3), n);
    for (addrs) |want| {
        var found = false;
        for (got[0..n]) |g| {
            if (std.mem.eql(u8, &g, &want)) found = true;
        }
        try testing.expect(found);
    }
}

test "answerRequest：AAAA 的 NODATA 不得截胡同名的 A 查询（实机回归 ghfast.top）" {
    const allocator = testing.allocator;
    var d = daemon_mod.Daemon{ .allocator = allocator };
    defer d.deinit();
    d.cache = try cache.Cache.init(allocator, 64);
    d.cache_ready = true;

    const now: i64 = 1000;
    const nm = "ghfast.top";

    // 上游对这个名字回「AAAA 的 NODATA」：名字存在，但没有 AAAA 记录。
    // ghfast.top / api.github.com / github.io 都是这类「有 A、无 AAAA」的名字。
    _ = d.cache.insert(nm, null, protocol.C_IN, now, 300, protocol.F_NEG | protocol.F_FORWARD | protocol.F_IPV6);

    var q: [512]u8 = undefined;
    var namebuf: [MAXNAMEBUF]u8 = undefined;
    const src4: addr.SockAddr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 127, 0, 0, 1 }), 5353);

    // 1) AAAA 查询：这条负记录讲的正是 AAAA，应当本地答 NODATA（an=0 但 answered）
    {
        const qn = buildQuery(&q, nm, protocol.T_AAAA);
        const req = extractRequest(&q, qn, &namebuf) orelse return error.TestUnexpectedResult;
        const res = answerRequest(&d, &q, qn, q.len, now, req, &src4);
        try testing.expect(res.answered);
        try testing.expectEqual(@as(u16, 0), protocol.ancount(&q));
    }

    // 2) A 查询：**绝不能**被那条 AAAA 负记录回答，必须交回上游转发。
    //    旧 bug：负缓存查找只按 F_NEG 匹配、不校验记录自己的类型位，于是这里
    //    会返回 answered=true + ancount=0 —— 客户端永远拿不到 A 记录，直到
    //    负数 TTL（最长 1h）到期；期间若还有 AAAA 查询不断刷新这条负记录，
    //    就表现为「个别域名长时间无法解析」。
    {
        const qn = buildQuery(&q, nm, protocol.T_A);
        const req = extractRequest(&q, qn, &namebuf) orelse return error.TestUnexpectedResult;
        const res = answerRequest(&d, &q, qn, q.len, now, req, &src4);
        try testing.expect(!res.answered);
    }

    // 3) 反向也要对称：A 的 NODATA 不该影响 AAAA 查询
    {
        _ = d.cache.insert("only4.example", null, protocol.C_IN, now, 300, protocol.F_NEG | protocol.F_FORWARD | protocol.F_IPV4);
        const qn = buildQuery(&q, "only4.example", protocol.T_AAAA);
        const req = extractRequest(&q, qn, &namebuf) orelse return error.TestUnexpectedResult;
        const res = answerRequest(&d, &q, qn, q.len, now, req, &src4);
        try testing.expect(!res.answered);
    }

    // 4) 但 A 的 NODATA 对 A 查询本身仍然有效（别把正常功能一起改坏）
    {
        const qn = buildQuery(&q, "only4.example", protocol.T_A);
        const req = extractRequest(&q, qn, &namebuf) orelse return error.TestUnexpectedResult;
        const res = answerRequest(&d, &q, qn, q.len, now, req, &src4);
        try testing.expect(res.answered);
        try testing.expectEqual(@as(u16, 0), protocol.ancount(&q));
    }
}

test "extractRequest 正确解析 qtype 与 qclass（回归：曾经把 qtype 当成 qclass）" {
    var pkt: [512]u8 = undefined;
    var namebuf: [MAXNAMEBUF]u8 = undefined;

    // A / IN
    var n = buildQuery(&pkt, "a.example", protocol.T_A);
    var req = extractRequest(&pkt, n, &namebuf) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(protocol.T_A, req.qtype);
    try testing.expectEqual(protocol.C_IN, req.qclass);
    try testing.expectEqualStrings("a.example", req.name);

    // AAAA：qtype=28，不能被误判成非 IN 类
    n = buildQuery(&pkt, "aaaa.example", protocol.T_AAAA);
    req = extractRequest(&pkt, n, &namebuf) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(protocol.T_AAAA, req.qtype);
    try testing.expectEqual(protocol.C_IN, req.qclass);

    // PTR：qtype=12，同上
    n = buildQuery(&pkt, "1.0.0.10.in-addr.arpa", protocol.T_PTR);
    req = extractRequest(&pkt, n, &namebuf) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(protocol.T_PTR, req.qtype);
    try testing.expectEqual(protocol.C_IN, req.qclass);

    // 非 IN 类必须被如实解析（例如 CH TXT）
    n = buildQuery(&pkt, "version.bind", protocol.T_TXT);
    protocol.putShort(&pkt, n - 2, 3); // class=CH
    req = extractRequest(&pkt, n, &namebuf) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u16, 3), req.qclass);
}

test "answerRequest：hosts 记录的 A/AAAA/PTR 都由缓存本地应答" {
    const allocator = testing.allocator;
    var d = daemon_mod.Daemon{ .allocator = allocator };
    defer d.deinit();
    d.cache = try cache.Cache.init(allocator, 64);
    d.cache_ready = true;

    const now: i64 = 1000;
    var a4: addr.AllAddr = .{ .ip4 = 0 };
    _ = addr.parseIp4("10.1.2.3", &a4.ip4);
    var a6: addr.AllAddr = .{ .ip6 = [_]u8{0} ** 16 };
    _ = addr.parseIp6("fd00::1", &a6.ip6);
    _ = hosts.addHostEntry(&d.cache, "host.example", a4, 0, now);
    _ = hosts.addHostEntry(&d.cache, "v6.example", a6, 0, now);

    var pkt: [512]u8 = undefined;
    var namebuf: [MAXNAMEBUF]u8 = undefined;
    var src4: addr.SockAddr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 127, 0, 0, 1 }), 5353);

    // --- A ---
    var n = buildQuery(&pkt, "host.example", protocol.T_A);
    var req = extractRequest(&pkt, n, &namebuf) orelse return error.TestUnexpectedResult;
    var res = answerRequest(&d, &pkt, n, pkt.len, now, req, &src4);
    try testing.expect(res.answered and res.from_cache);
    try testing.expectEqual(protocol.T_A, firstRrtype(&pkt, res.len));
    try testing.expectEqualSlices(u8, &[4]u8{ 10, 1, 2, 3 }, firstRdata(&pkt, res.len));

    // --- AAAA（曾被 qclass 误判导致走不到缓存） ---
    n = buildQuery(&pkt, "v6.example", protocol.T_AAAA);
    req = extractRequest(&pkt, n, &namebuf) orelse return error.TestUnexpectedResult;
    res = answerRequest(&d, &pkt, n, pkt.len, now, req, &src4);
    try testing.expect(res.answered and res.from_cache);
    try testing.expectEqual(protocol.T_AAAA, firstRrtype(&pkt, res.len));
    try testing.expectEqual(@as(usize, 16), firstRdata(&pkt, res.len).len);
    try testing.expectEqual(@as(u8, 0xfd), firstRdata(&pkt, res.len)[0]);

    // --- PTR（按地址反查） ---
    n = buildQuery(&pkt, "3.2.1.10.in-addr.arpa", protocol.T_PTR);
    req = extractRequest(&pkt, n, &namebuf) orelse return error.TestUnexpectedResult;
    res = answerRequest(&d, &pkt, n, pkt.len, now, req, &src4);
    try testing.expect(res.answered and res.from_cache);
    try testing.expectEqual(protocol.T_PTR, firstRrtype(&pkt, res.len));

    // rdata 是目标主机名 "host.example"。
    // 注意两点（都与 C 的 add_resource_record 一致）：
    //   1. 写的是**未压缩**的域名（`case 'd'` 走 do_rfc1035_name，不打压缩指针）；
    //   2. 名字是主机名，而不是 arpa 形式——反查记录的名字就是主机名。
    var rd = firstRdata(&pkt, res.len);
    try testing.expectEqual(@as(usize, 1 + 4 + 1 + 7 + 1), rd.len);
    try testing.expectEqual(@as(u8, 4), rd[0]);
    try testing.expectEqualStrings("host", rd[1..5]);
    try testing.expectEqual(@as(u8, 7), rd[5]);
    try testing.expectEqualStrings("example", rd[6..13]);
    try testing.expectEqual(@as(u8, 0), rd[13]);
}

test "高1：--localise-queries 只回与查询到达网段一致的 hosts 地址" {
    const allocator = testing.allocator;
    var d = daemon_mod.Daemon{ .allocator = allocator };
    defer d.deinit();
    d.cache = try cache.Cache.init(allocator, 64);
    d.cache_ready = true;

    const now: i64 = 1000;
    var a1: addr.AllAddr = .{ .ip4 = 0 };
    _ = addr.parseIp4("192.168.1.10", &a1.ip4);
    var a2: addr.AllAddr = .{ .ip4 = 0 };
    _ = addr.parseIp4("192.168.2.10", &a2.ip4);
    _ = hosts.addHostEntry(&d.cache, "multi.local", a1, 0, now);
    _ = hosts.addHostEntry(&d.cache, "multi.local", a2, 0, now);

    var pkt: [512]u8 = undefined;
    var namebuf: [MAXNAMEBUF]u8 = undefined;
    const src4: addr.SockAddr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 127, 0, 0, 1 }), 5353);

    // ① 未开 --localise-queries：两条 hosts 地址都回
    {
        const n = buildQuery(&pkt, "multi.local", protocol.T_A);
        const req = extractRequest(&pkt, n, &namebuf) orelse return error.TestUnexpectedResult;
        const res = answerRequest(&d, &pkt, n, pkt.len, now, req, &src4);
        try testing.expect(res.answered);
        try testing.expectEqual(@as(u16, 2), protocol.ancount(pkt[0..res.len]));
    }

    // ② 开 localise，查询到达 192.168.1.1/24 → 只回 192.168.1.10
    d.setOpt(protocol.OPT_LOCALISE);
    {
        const n = buildQuery(&pkt, "multi.local", protocol.T_A);
        var req = extractRequest(&pkt, n, &namebuf) orelse return error.TestUnexpectedResult;
        var l4: u32 = 0;
        _ = addr.parseIp4("192.168.1.1", &l4);
        req.local4 = l4;
        var mask: u32 = 0;
        _ = addr.parseIp4("255.255.255.0", &mask);
        req.netmask4 = mask;
        const res = answerRequest(&d, &pkt, n, pkt.len, now, req, &src4);
        try testing.expect(res.answered);
        try testing.expectEqual(@as(u16, 1), protocol.ancount(pkt[0..res.len]));
        try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 10 }, firstRdata(&pkt, res.len));
    }

    // ③ 查询到达 192.168.3.1/24：两条 hosts 都不在任何同网段 → localise 不置位，
    //    因此两条都回（对应 C：localise 只有在**存在**同网段 hosts 记录时才过滤）
    {
        const n = buildQuery(&pkt, "multi.local", protocol.T_A);
        var req = extractRequest(&pkt, n, &namebuf) orelse return error.TestUnexpectedResult;
        var l4: u32 = 0;
        _ = addr.parseIp4("192.168.3.1", &l4);
        req.local4 = l4;
        var mask: u32 = 0;
        _ = addr.parseIp4("255.255.255.0", &mask);
        req.netmask4 = mask;
        const res = answerRequest(&d, &pkt, n, pkt.len, now, req, &src4);
        try testing.expect(res.answered);
        try testing.expectEqual(@as(u16, 2), protocol.ancount(pkt[0..res.len]));
    }
}

test "answerRequest：AA 位只在 hosts/DHCP 派生的应答上置位（实机回归 localhost）" {
    const allocator = testing.allocator;
    var d = daemon_mod.Daemon{ .allocator = allocator };
    defer d.deinit();
    d.cache = try cache.Cache.init(allocator, 64);
    d.cache_ready = true;

    const now: i64 = 1000;
    var a4: addr.AllAddr = .{ .ip4 = 0 };
    _ = addr.parseIp4("10.1.2.3", &a4.ip4);
    _ = hosts.addHostEntry(&d.cache, "host.example", a4, 0, now);

    var pkt: [512]u8 = undefined;
    var namebuf: [MAXNAMEBUF]u8 = undefined;
    const src4: addr.SockAddr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 127, 0, 0, 1 }), 5353);

    // 1) hosts 派生的 A 应答 -> 权威，AA=1（C 版 answer_request 的 auth 保持为 1）
    const n = buildQuery(&pkt, "host.example", protocol.T_A);
    const req = extractRequest(&pkt, n, &namebuf) orelse return error.TestUnexpectedResult;
    const res = answerRequest(&d, &pkt, n, pkt.len, now, req, &src4);
    try testing.expect(res.answered and res.from_cache);
    try testing.expectEqual(protocol.T_A, firstRrtype(&pkt, res.len));
    try testing.expect((pkt[protocol.OFF_HB3] & protocol.HB3_AA) != 0);

    // 2) 上游转发来的地址记录 -> 非权威，AA=0
    //    （C 版同处 `if (!(crecp->flags & (F_HOSTS | F_DHCP))) auth = 0;`）
    const rn = buildCnameReply(&pkt, "www.fwd.example", "edge.example", [4]u8{ 203, 0, 113, 5 });
    _ = extractAddresses(&d, &pkt, rn, now, "www.fwd.example", protocol.T_A, protocol.C_IN, &namebuf);

    var q: [512]u8 = undefined;
    const qn = buildQuery(&q, "www.fwd.example", protocol.T_A);
    const req2 = extractRequest(&q, qn, &namebuf) orelse return error.TestUnexpectedResult;
    const res2 = answerRequest(&d, &q, qn, q.len, now, req2, &src4);
    try testing.expect(res2.answered and res2.from_cache);
    try testing.expectEqual(@as(u8, 0), q[protocol.OFF_HB3] & protocol.HB3_AA);
}

test "answerRequest 把查询级缓存统计记对" {
    const allocator = testing.allocator;
    var d = daemon_mod.Daemon{ .allocator = allocator };
    defer d.deinit();
    d.cache = try cache.Cache.init(allocator, 32);
    d.cache_ready = true;

    const now: i64 = 1000;
    var a4: addr.AllAddr = .{ .ip4 = 0 };
    _ = addr.parseIp4("10.9.9.9", &a4.ip4);
    _ = hosts.addHostEntry(&d.cache, "stats.example", a4, 0, now);

    var pkt: [512]u8 = undefined;
    var namebuf: [MAXNAMEBUF]u8 = undefined;
    var src4: addr.SockAddr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 127, 0, 0, 1 }), 5353);

    // 命中：本地 hosts 直接应答
    var n = buildQuery(&pkt, "stats.example", protocol.T_A);
    var req = extractRequest(&pkt, n, &namebuf) orelse return error.TestUnexpectedResult;
    _ = answerRequest(&d, &pkt, n, pkt.len, now, req, &src4);
    try testing.expectEqual(@as(u64, 1), d.cache.stats().query_hits);
    try testing.expectEqual(@as(u64, 0), d.cache.stats().query_misses);

    // 未命中：本地无法回答，需要转发
    n = buildQuery(&pkt, "unknown.example", protocol.T_A);
    req = extractRequest(&pkt, n, &namebuf) orelse return error.TestUnexpectedResult;
    const res = answerRequest(&d, &pkt, n, pkt.len, now, req, &src4);
    try testing.expectEqual(@as(usize, 0), res.len);
    try testing.expectEqual(@as(u64, 1), d.cache.stats().query_misses);
    try testing.expectEqual(@as(u64, 1), d.cache.stats().query_hits);

    // 畸形报文不计入任何一方（避免把坏包算成缓存未命中）
    const before = d.cache.stats();
    _ = answerRequest(&d, &pkt, 4, 4, now, req, &src4);
    try testing.expectEqual(before.query_misses, d.cache.stats().query_misses);
    try testing.expectEqual(before.query_hits, d.cache.stats().query_hits);
}

test "answerRequest：--address/local 规则与 domain-needed" {
    const allocator = testing.allocator;
    var d = daemon_mod.Daemon{ .allocator = allocator };
    defer d.deinit();
    d.cache = try cache.Cache.init(allocator, 16);
    d.cache_ready = true;
    d.local_ttl = 60;

    // address=/ads.example/0.0.0.0
    try d.address_list.append(allocator, .{
        .domain = try allocator.dupe(u8, "ads.example"),
        .wildcard = false,
        .addr4 = 0,
        .addr6 = null,
        .addr_name = null,
        .local = false,
    });
    // domain 由 Daemon.deinit() 统一释放，这里不要再 free

    var pkt: [512]u8 = undefined;
    var namebuf: [MAXNAMEBUF]u8 = undefined;
    var src4: addr.SockAddr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 127, 0, 0, 1 }), 5353);

    var n = buildQuery(&pkt, "x.ads.example", protocol.T_A);
    var req = extractRequest(&pkt, n, &namebuf) orelse return error.TestUnexpectedResult;
    const res = answerRequest(&d, &pkt, n, pkt.len, 1000, req, &src4);
    try testing.expect(res.answered and !res.from_cache);
    try testing.expectEqual(protocol.T_A, firstRrtype(&pkt, res.len));
    try testing.expectEqualSlices(u8, &[4]u8{ 0, 0, 0, 0 }, firstRdata(&pkt, res.len));

    // domain-needed（OPT_NODOTS_LOCAL）：无点名字直接 NXDOMAIN
    d.setOpt(protocol.OPT_NODOTS_LOCAL);
    n = buildQuery(&pkt, "nodots", protocol.T_A);
    req = extractRequest(&pkt, n, &namebuf) orelse return error.TestUnexpectedResult;
    const res2 = answerRequest(&d, &pkt, n, pkt.len, 1000, req, &src4);
    try testing.expect(res2.answered);
    try testing.expectEqual(protocol.NXDOMAIN, protocol.rcode(pkt[protocol.OFF_HB4]));
}

test "answerRequest：address 规则命中却无该类型/地址族时回 NODATA+AA（实机回归）" {
    const allocator = testing.allocator;
    var d = daemon_mod.Daemon{ .allocator = allocator };
    defer d.deinit();
    d.cache = try cache.Cache.init(allocator, 16);
    d.cache_ready = true;
    d.local_ttl = 60;

    // address=/aat4.example/10.9.9.9 —— 规则只提供 IPv4
    var v4: u32 = 0;
    _ = addr.parseIp4("10.9.9.9", &v4);
    try d.address_list.append(allocator, .{
        .domain = try allocator.dupe(u8, "aat4.example"),
        .wildcard = false,
        .addr4 = v4,
        .addr6 = null,
        .addr_name = null,
        .local = false,
    });

    var pkt: [512]u8 = undefined;
    var namebuf: [MAXNAMEBUF]u8 = undefined;
    const src4: addr.SockAddr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 127, 0, 0, 1 }), 5353);

    // 1) 匹配地址族：回地址，且 AA=1（对应 make_local_answer 收到 F_IPV4）
    const n = buildQuery(&pkt, "aat4.example", protocol.T_A);
    const req = extractRequest(&pkt, n, &namebuf) orelse return error.TestUnexpectedResult;
    const res = answerRequest(&d, &pkt, n, pkt.len, 1000, req, &src4);
    try testing.expect(res.answered);
    try testing.expectEqualSlices(u8, &[4]u8{ 10, 9, 9, 9 }, firstRdata(&pkt, res.len));
    try testing.expect((pkt[protocol.OFF_HB3] & protocol.HB3_AA) != 0);

    // 2) 名字存在但没有 AAAA：必须 NODATA（NOERROR + AA），既不能 NXDOMAIN，
    //    也不能漏给上游 —— 否则下游负缓存 NXDOMAIN 后连 A 也解析不了。
    const n2 = buildQuery(&pkt, "aat4.example", protocol.T_AAAA);
    const req2 = extractRequest(&pkt, n2, &namebuf) orelse return error.TestUnexpectedResult;
    const res2 = answerRequest(&d, &pkt, n2, pkt.len, 1000, req2, &src4);
    try testing.expect(res2.answered);
    try testing.expectEqual(protocol.NOERROR, protocol.rcode(pkt[protocol.OFF_HB4]));
    try testing.expectEqual(@as(u16, 0), protocol.ancount(&pkt));
    try testing.expect((pkt[protocol.OFF_HB3] & protocol.HB3_AA) != 0);

    // 3) 非地址类型（MX）同样 NODATA + AA
    const n3 = buildQuery(&pkt, "aat4.example", protocol.T_MX);
    const req3 = extractRequest(&pkt, n3, &namebuf) orelse return error.TestUnexpectedResult;
    const res3 = answerRequest(&d, &pkt, n3, pkt.len, 1000, req3, &src4);
    try testing.expect(res3.answered);
    try testing.expectEqual(protocol.NOERROR, protocol.rcode(pkt[protocol.OFF_HB4]));
    try testing.expect((pkt[protocol.OFF_HB3] & protocol.HB3_AA) != 0);

    // 4) 同一域名的多条规则（IPv4 一条、IPv6 一条）必须合并生效：
    //    AAAA 查询要能扫到第二条规则并答出地址，不能被第一条的「答不出」提前截胡。
    var v6: [16]u8 = undefined;
    _ = addr.parseIp6("fd00::9", &v6);
    try d.address_list.append(allocator, .{
        .domain = try allocator.dupe(u8, "aat4.example"),
        .wildcard = false,
        .addr4 = null,
        .addr6 = v6,
        .addr_name = null,
        .local = false,
    });
    const n4 = buildQuery(&pkt, "aat4.example", protocol.T_AAAA);
    const req4 = extractRequest(&pkt, n4, &namebuf) orelse return error.TestUnexpectedResult;
    const res4 = answerRequest(&d, &pkt, n4, pkt.len, 1000, req4, &src4);
    try testing.expect(res4.answered);
    try testing.expectEqual(@as(u16, 1), protocol.ancount(&pkt));
    try testing.expectEqual(protocol.T_AAAA, firstRrtype(&pkt, res4.len));
    try testing.expect((pkt[protocol.OFF_HB3] & protocol.HB3_AA) != 0);
}

// ---------------------------------------------------------------------------
// findSoa / 负缓存加固的单元测试
// ---------------------------------------------------------------------------
/// 造一条「NXDOMAIN + 权威段 SOA(owner, ttl)」的应答
fn buildNxResponse(buf: []u8, qname: []const u8, soa_owner: []const u8, soa_ttl: u32) usize {
    var p: usize = 0;
    @memset(buf[0..64], 0);
    protocol.setId(buf, 0x1234);
    buf[protocol.OFF_HB3] = protocol.HB3_RD;
    buf[protocol.OFF_HB4] = protocol.HB4_RA;
    protocol.setRcode(&buf[protocol.OFF_HB4], protocol.NXDOMAIN);
    protocol.setQdcount(buf, 1);
    protocol.setNscount(buf, 1);
    p = protocol.HEADER_SIZE;
    var qit = std.mem.splitScalar(u8, qname, '.');
    while (qit.next()) |lab| {
        if (lab.len == 0) continue;
        buf[p] = @intCast(lab.len);
        @memcpy(buf[p + 1 ..][0..lab.len], lab);
        p += 1 + lab.len;
    }
    buf[p] = 0;
    p += 1;
    p += 4; // qtype + qclass（已被 memset 置 0，仅占位）
    // 权威段 SOA
    var sit = std.mem.splitScalar(u8, soa_owner, '.');
    while (sit.next()) |lab| {
        if (lab.len == 0) continue;
        buf[p] = @intCast(lab.len);
        @memcpy(buf[p + 1 ..][0..lab.len], lab);
        p += 1 + lab.len;
    }
    buf[p] = 0;
    p += 1;
    protocol.putShort(buf, p, protocol.T_SOA);
    protocol.putShort(buf, p + 2, protocol.C_IN);
    protocol.putLong(buf, p + 4, soa_ttl);
    protocol.putShort(buf, p + 8, 22); // rdlen：mname(1)+rname(1)+5×u32(20)
    p += 10;
    p += 22;
    return p;
}

test "findSoa：SOA owner 是查询名后缀才命中（含 ttl 取值）" {
    var buf: [512]u8 = undefined;
    var namebuf: [MAXNAMEBUF]u8 = undefined;

    // 查 www.example.com，SOA owner = example.com -> 命中，TTL 取自 SOA
    var n = buildNxResponse(&buf, "www.example.com", "example.com", 86400);
    try testing.expectEqual(@as(?u32, 86400), findSoa(&buf, n, "www.example.com", &namebuf));

    // SOA owner = com（更上级的区）-> 仍是后缀，命中
    n = buildNxResponse(&buf, "www.example.com", "com", 3600);
    try testing.expectEqual(@as(?u32, 3600), findSoa(&buf, n, "www.example.com", &namebuf));

    // SOA owner = example.net -> 不是后缀，不命中（防止拿别的区的 SOA 当依据）
    n = buildNxResponse(&buf, "www.example.com", "example.net", 86400);
    try testing.expectEqual(@as(?u32, null), findSoa(&buf, n, "www.example.com", &namebuf));

    // SOA owner 比查询名还长 -> 不命中
    n = buildNxResponse(&buf, "example.com", "www.example.com", 86400);
    try testing.expectEqual(@as(?u32, null), findSoa(&buf, n, "example.com", &namebuf));

    // 大小写不敏感
    n = buildNxResponse(&buf, "WWW.Example.COM", "example.com", 1800);
    try testing.expectEqual(@as(?u32, 1800), findSoa(&buf, n, "WWW.Example.COM", &namebuf));
}
