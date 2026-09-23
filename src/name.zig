// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! name.zig — 域名编解码（对应 C 源码 rfc1035.c 的 extract_name / skip_name /
//! skip_questions / skip_section、in_arpa_name_2_addr，以及 util.c 的
//! do_rfc1035_name / check_name / legal_hostname / canonicalise /
//! hostname_order / hostname_isequal / hostname_issubdomain）
//!
//! 与 C 版本的差异：全部改为「报文切片 + 偏移量」实现，越界一律返回失败，
//! 不再有裸指针算术；但控制流、返回码（0 失败 / 1 匹配 / 2 不匹配 / 3 大小写不同）
//! 与 C 版本保持一致，便于对照阅读。

const std = @import("std");
const protocol = @import("protocol.zig");
const addr = @import("addr.zig");

// 名字处理模式（对应 dnsmasq.h 里的 EXTR_NAME_*）
pub const EXTR_NAME_EXTRACT: u32 = 1;
pub const EXTR_NAME_COMPARE: u32 = 2;
pub const EXTR_NAME_NOCASE: u32 = 3;
pub const EXTR_NAME_FLIP: u32 = 4;

/// C 版本 in_arpa_name_2_addr 里 MAXARPANAME
pub const MAXARPANAME: usize = 75;

pub const ExtractError = error{Malformed};

/// CHECK_LEN(header, p, plen, len)：等价于 (p - header) + len <= plen
pub inline fn checkLen(plen: usize, off: usize, len: usize) bool {
    if (off > plen) return false;
    return len <= plen - off;
}

// ---------------------------------------------------------------------------
// extract_name（rfc1035.c:35）
// ---------------------------------------------------------------------------
/// 返回值与 C 完全一致：0 = 解析失败，1 = 成功/匹配，2 = 与 name 不同，3 = 仅大小写不同。
/// * `pp`   传入当前位置（偏移量），函数结束时会更新到名字之后（若发生压缩跳转则为跳转点）
/// * `name` EXTRACT 模式写入转义后的名字；COMPARE/NOCASE 模式为待比较的字符串
/// * `parm` EXTRACT/COMPARE 模式表示名字之后至少还要有多少字节
pub fn extractName(
    header: []u8,
    plen: usize,
    pp: ?*usize,
    name: ?[]u8,
    func: u32,
    parm: u32,
) i32 {
    var cp: usize = 0;
    var p1: ?usize = null;
    var namelen: u32 = 0;
    var hops: u32 = 0;
    var bigmap_counter: u32 = 0;
    var bigmap_posn: u32 = 0;
    const bigmap_size: u32 = parm;
    var bitmap: u32 = 0;
    var retvalue: i32 = 1;
    var case_insens = true;
    var is_extract = false;
    var flip = false;
    var extrabytes: usize = parm;
    var bigmap: []const u32 = &.{};
    var out: ?[]u8 = name;

    // C 用 (unsigned int *)name 复用作大小写翻转位图（DNSSEC 规范化时使用）
    if (name) |n| {
        if (@intFromPtr(n.ptr) % @alignOf(u32) == 0 and n.len >= @sizeOf(u32)) {
            const words: [*]const u32 = @ptrCast(@alignCast(n.ptr));
            bigmap = words[0 .. n.len / @sizeOf(u32)];
        }
    }

    var p: usize = if (pp) |q| q.* else protocol.HEADER_SIZE;

    if (func == EXTR_NAME_EXTRACT) {
        is_extract = true;
        if (name) |n| if (n.len > 0) {
            n[0] = 0;
        };
    } else if (func == EXTR_NAME_NOCASE) {
        case_insens = false;
    } else if (func == EXTR_NAME_FLIP) {
        flip = true;
        extrabytes = 0;
        out = null;
    }

    while (true) {
        var label_type: u32 = 0;

        if (!checkLen(plen, p, 1)) return 0;

        var l: u32 = header[p];
        p += 1;

        if (l == 0) {
            // 名字结束标记
            if (!checkLen(plen, p1 orelse p, extrabytes)) return 0;

            if (is_extract) {
                const n = out.?;
                if (cp != 0) cp -= 1; // 去掉末尾的 '.'
                if (cp < n.len) n[cp] = 0;
            } else if (!flip) {
                const n = out orelse &[_]u8{};
                const c1: u8 = if (cp < n.len) n[cp] else 0;
                if (c1 != 0) retvalue = 2;
            }

            if (pp) |q| q.* = p1 orelse p;
            return retvalue;
        }

        label_type = l & 0xc0;

        if (label_type == 0xc0) {
            // 压缩指针
            if (!checkLen(plen, p, 1)) return 0;

            l = (l & 0x3f) << 8;
            l |= header[p];
            p += 1;

            if (p1 == null) p1 = p; // 记住第一个跳转点

            hops += 1;
            if (hops > 255) return 0;

            p = l; // 跳转
        } else if (label_type == 0x00) {
            // 普通 label
            namelen += l + 1;
            if (namelen >= protocol.MAXDNAME) return 0;
            if (!checkLen(plen, p, l)) return 0;

            var j: u32 = 0;
            while (j < l) : ({
                j += 1;
                p += 1;
            }) {
                if (is_extract) {
                    const n = out.?;
                    const c = header[p];
                    if (protocol.isNameEscape(c)) {
                        if (cp + 2 > n.len) return 0;
                        n[cp] = protocol.NAME_ESCAPE;
                        n[cp + 1] = c +% 1;
                        cp += 2;
                    } else {
                        if (cp + 1 > n.len) return 0;
                        n[cp] = c;
                        cp += 1;
                    }
                } else if (flip) {
                    const c = header[p];
                    if ((c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z')) {
                        if (bigmap_posn < bigmap_size) {
                            if (bigmap_counter == 0) {
                                bitmap = if (bigmap_posn < bigmap.len) bigmap[bigmap_posn] else 0;
                                bigmap_posn += 1;
                                bigmap_counter = @sizeOf(u32) * 8 - 1;
                            } else {
                                bigmap_counter -= 1;
                            }
                        }

                        if (bitmap & 1 != 0) header[p] ^= 0x20;
                        bitmap >>= 1;
                    }
                } else {
                    const n = out orelse &[_]u8{};
                    var c1: u8 = if (cp < n.len) n[cp] else 0;
                    var c2: u8 = header[p];

                    if (c1 == 0) {
                        retvalue = 2;
                    } else {
                        cp += 1;

                        if (c1 == protocol.NAME_ESCAPE) {
                            c1 = (if (cp < n.len) n[cp] else 0) -% 1;
                            cp += 1;
                        } else if (case_insens and c1 >= 'A' and c1 <= 'Z') {
                            c1 += 'a' - 'A';
                        }

                        if (case_insens and c2 >= 'A' and c2 <= 'Z') {
                            c2 += 'a' - 'A';
                        }

                        if (!case_insens and retvalue != 2 and c1 != c2) {
                            if (c1 >= 'A' and c1 <= 'Z') c1 += 'a' - 'A';
                            if (c2 >= 'A' and c2 <= 'Z') c2 += 'a' - 'A';
                            if (c1 == c2) retvalue = 3;
                        }

                        if (c1 != c2) retvalue = 2;
                    }
                }
            }

            if (is_extract) {
                const n = out.?;
                if (cp + 1 > n.len) return 0;
                n[cp] = '.';
                cp += 1;
            } else if (!flip) {
                const n = out orelse &[_]u8{};
                const c1: u8 = if (cp < n.len) n[cp] else 0;
                if (c1 != 0) {
                    cp += 1;
                    if (c1 != '.') retvalue = 2;
                }
            }
        } else {
            return 0; // 0x40 / 0x80 类型不支持
        }
    }
}

// ---------------------------------------------------------------------------
// skip_name / skip_questions / skip_section（rfc1035.c）
// ---------------------------------------------------------------------------
pub fn skipName(header: []const u8, start: usize, plen: usize, extrabytes: usize) ?usize {
    var ansp = start;

    while (true) {
        if (!checkLen(plen, ansp, 1)) return null;
        const label_type: u32 = header[ansp] & 0xc0;

        if (label_type == 0xc0) {
            // 压缩指针
            ansp += 2;
            break;
        } else if (label_type == 0x80) {
            return null; // reserved
        } else if (label_type == 0x40) {
            // 扩展 label（DNSSEC 的 bit-string label）
            if (!checkLen(plen, ansp, 2)) return null;
            if ((header[ansp] & 0x3f) != 1) return null;
            ansp += 1;
            var count: usize = header[ansp];
            ansp += 1;
            if (count == 0) count = 256;
            if (!checkLen(plen, ansp, count)) return null;
            if (header[ansp + count - 1] & 0x80 != 0) return null;
            ansp += count;
        } else {
            if (!checkLen(plen, ansp, @as(usize, header[ansp]) + 1)) return null;
            const l = header[ansp];
            ansp += 1;
            if (l == 0) break;
            ansp += l;
        }
    }

    if (!checkLen(plen, ansp, extrabytes)) return null;
    return ansp;
}

/// 跳过问题区，返回回答区起始偏移
pub fn skipQuestions(header: []const u8, plen: usize) ?usize {
    var ansp: usize = protocol.HEADER_SIZE;
    var q = protocol.qdcount(header);

    while (q != 0) : (q -= 1) {
        ansp = skipName(header, ansp, plen, 4) orelse return null;
        ansp += 4; // type + class
    }

    return ansp;
}

/// 跳过 count 个 RR，返回下一节起始偏移
pub fn skipSection(header: []const u8, start: usize, count: u16, plen: usize) ?usize {
    var ansp = start;

    var i: u16 = 0;
    while (i < count) : (i += 1) {
        ansp = skipName(header, ansp, plen, 10) orelse return null;
        ansp += 8; // type/class/ttl
        const rdlen = protocol.getShort(header, ansp);
        ansp += 2;
        if (!checkLen(plen, ansp, rdlen)) return null;
        ansp += rdlen;
    }

    return ansp;
}

// ---------------------------------------------------------------------------
// do_rfc1035_name（util.c:294）：把内部转义名字编码为 wire 格式
// ---------------------------------------------------------------------------
/// 返回名字之后的位置（相对 dst 的偏移）；失败返回 null
pub fn doRfc1035Name(dst: []u8, sval_in: []const u8) ?usize {
    var p: usize = 0;
    // 对应 C: limit = min(p + MAXDNAME, dst 末尾)
    const limit: usize = @min(dst.len, protocol.MAXDNAME);
    var sval = sval_in;

    while (sval.len != 0) {
        const cp = p;
        p += 1;
        if (p > limit) return null;

        var l: usize = 0;
        while (sval.len != 0 and sval[0] != '.') {
            if (p + 1 > limit) return null;
            if (sval[0] == protocol.NAME_ESCAPE) {
                sval = sval[1..];
                if (sval.len == 0) return null;
                dst[p] = sval[0] -% 1;
            } else {
                dst[p] = sval[0];
            }
            p += 1;
            sval = sval[1..];
            l += 1;
        }

        if (l == 0 or l > protocol.MAXLABEL) return null;
        dst[cp] = @truncate(l);

        if (sval.len != 0 and sval[0] == '.') sval = sval[1..];
    }

    if (p + 1 > limit) return null;
    dst[p] = 0;
    return p + 1;
}

/// 把 wire 格式名字解析出来（返回新分配的内部转义字符串）
pub fn extractNameAlloc(
    allocator: std.mem.Allocator,
    header: []u8,
    plen: usize,
    start: usize,
    name_buf: []u8,
) ?[]u8 {
    var p = start;
    if (extractName(header, plen, &p, name_buf, EXTR_NAME_EXTRACT, 0) == 0) return null;
    return allocator.dupe(u8, std.mem.sliceTo(name_buf, 0)) catch null;
}

// ---------------------------------------------------------------------------
// 名字合法性检查（util.c:135 check_name / 214 legal_hostname / 243 canonicalise）
// ---------------------------------------------------------------------------
/// 返回 0 = 非法，1 = 合法，2 = 需要 IDN 处理。会就地去掉末尾的点。
pub fn checkName(in: []u8) u8 {
    var l = in.len;
    if (l == 0) return 0;

    if (in[l - 1] == '.') {
        l -= 1;
        in[l] = 0;
    }

    var wiresize: usize = 0;
    var dotgap: usize = 0;

    var i: usize = 0;
    while (i < l) : (i += 1) {
        const c = in[i];
        if (c == '.') {
            wiresize += dotgap + 1;
            dotgap = 0;
        } else if (dotgap + 1 > protocol.MAXLABEL) {
            dotgap += 1;
            return 0;
        } else {
            dotgap += 1;
            if (c < 0x80 and (c < 0x20 or c == 0x7f)) return 0; // 控制字符
            if (c >= 0x80) return 0; // 未编译 IDN 支持
        }
    }

    // 末尾 label 与终止符
    if (wiresize + dotgap + 2 > protocol.MAXDNAME) return 0;
    return 1;
}

/// 主机名合法字符：a-z A-Z 0-9 - _ （只检查第一段）
pub fn legalHostname(name: []const u8) bool {
    var buf: [protocol.MAXDNAMESTR + 1]u8 = undefined;
    if (name.len > protocol.MAXDNAMESTR) return false;
    @memcpy(buf[0..name.len], name);
    buf[name.len] = 0;
    if (checkName(buf[0..name.len]) == 0) return false;

    for (name, 0..) |c, i| {
        if ((c >= 'A' and c <= 'Z') or (c >= 'a' and c <= 'z') or (c >= '0' and c <= '9')) continue;
        if (i != 0 and (c == '-' or c == '_')) continue;
        if (c == '.') return true;
        return false;
    }
    return true;
}

/// 规范化域名：去尾点 + 校验。返回新分配的字符串（不含终止符），失败返回 null。
pub fn canonicalise(allocator: std.mem.Allocator, in: []const u8) ?[]u8 {
    if (in.len == 0 or in.len > protocol.MAXDNAMESTR) return null;

    var tmp: [protocol.MAXDNAMESTR + 1]u8 = undefined;
    @memcpy(tmp[0..in.len], in);
    tmp[in.len] = 0;

    if (checkName(tmp[0..in.len]) == 0) return null;

    const len = std.mem.indexOfScalar(u8, tmp[0 .. in.len + 1], 0) orelse in.len;
    if (len == 0) return null;
    return allocator.dupe(u8, tmp[0..len]) catch null;
}

// ---------------------------------------------------------------------------
// 名字比较（util.c:404-471）
// ---------------------------------------------------------------------------
/// 忽略大小写的字典序比较（不使用 locale）
pub fn hostnameOrder(a: []const u8, b: []const u8) i32 {
    var i: usize = 0;
    while (true) : (i += 1) {
        var c1: u32 = if (i < a.len) a[i] else 0;
        var c2: u32 = if (i < b.len) b[i] else 0;

        if (c1 >= 'A' and c1 <= 'Z') c1 += 'a' - 'A';
        if (c2 >= 'A' and c2 <= 'Z') c2 += 'a' - 'A';

        if (c1 < c2) return -1;
        if (c1 > c2) return 1;
        if (c1 == 0) break;
    }
    return 0;
}

pub fn hostnameIsEqual(a: []const u8, b: []const u8) bool {
    return a.len == b.len and hostnameOrder(a, b) == 0;
}

/// b 与 a 相同返回 2，b 是 a 的子域返回 1，否则 0（对应 util.c: hostname_issubdomain）
pub fn hostnameIsSubdomain(a: []const u8, b_in: []const u8) i32 {
    var b = b_in;
    // 忽略尾点
    if (a.len != 0 and a[a.len - 1] == '.') {
        if (b.len != 0 and b[b.len - 1] == '.') b = b[0 .. b.len - 1];
        return hostnameIsSubdomain(a[0 .. a.len - 1], b);
    }

    if (a.len == 0) return if (b.len == 0) 2 else 1;
    if (b.len < a.len) return 0;

    var ai = a.len;
    var bi = b.len;
    while (ai > 0) {
        ai -= 1;
        bi -= 1;
        var c1: u32 = b[bi];
        var c2: u32 = a[ai];
        if (c1 >= 'A' and c1 <= 'Z') c1 += 'a' - 'A';
        if (c2 >= 'A' and c2 <= 'Z') c2 += 'a' - 'A';
        if (c1 != c2) return 0;
    }

    if (bi == 0) return 2;
    bi -= 1;
    if (b[bi] == '.') return 1;
    return 0;
}

// ---------------------------------------------------------------------------
// in_arpa_name_2_addr（rfc1035.c:200）
// ---------------------------------------------------------------------------
/// 解析 in-addr.arpa / ip6.arpa 名字为地址，返回 F_IPV4 / F_IPV6 / 0（对应 C 的返回值）
pub fn inArpaName2Addr(namein: []const u8, addrp: *addr.AllAddr) u32 {
    var name: [MAXARPANAME + 1]u8 = undefined;
    var lastchunk: ?usize = null;
    var penchunk: ?usize = null;
    var j: u32 = 1;

    if (namein.len > MAXARPANAME) return 0;

    addrp.* = .{ .none = {} };

    // 把名字切成一系列以 0 结尾的段
    var cp1: usize = 0;
    for (namein) |c| {
        if (c == '.') {
            penchunk = lastchunk;
            lastchunk = cp1 + 1;
            name[cp1] = 0;
            cp1 += 1;
            j += 1;
        } else {
            name[cp1] = c;
            cp1 += 1;
        }
    }
    name[cp1] = 0;

    if (j < 3) return 0;

    const last = name[(lastchunk orelse 0)..];
    const pen = if (penchunk) |p| name[p..] else null;

    const last_z = std.mem.sliceTo(last, 0);
    const pen_z = if (pen) |p| std.mem.sliceTo(p, 0) else @as([]const u8, "");

    if (hostnameIsEqual(last_z, "arpa") and hostnameIsEqual(pen_z, "in-addr")) {
        // IPv4 反查
        var out: [4]u8 = [_]u8{0} ** 4;
        var i: usize = 0;
        const end = penchunk orelse 0;
        while (i < end) {
            const chunk = std.mem.sliceTo(name[i..], 0);
            for (chunk) |c| {
                if (!std.ascii.isDigit(c)) return 0;
            }
            out[3] = out[2];
            out[2] = out[1];
            out[1] = out[0];
            const v = std.fmt.parseInt(u8, chunk, 10) catch return 0;
            out[0] = v;
            i += chunk.len + 1;
        }
        addrp.* = .{ .ip4 = @bitCast(out) };
        return protocol.F_IPV4;
    } else if (hostnameIsEqual(pen_z, "ip6") and
        (hostnameIsEqual(last_z, "int") or hostnameIsEqual(last_z, "arpa")))
    {
        var out: [16]u8 = [_]u8{0} ** 16;

        if (name[0] == '\\' and name[1] == '[' and (name[2] == 'x' or name[2] == 'X')) {
            var k: usize = 0;
            var idx: usize = 3;
            while (k < 32 and name[idx] != 0 and std.ascii.isHex(name[idx])) : ({
                idx += 1;
                k += 1;
            }) {
                const d = hexDigit(name[idx]);
                if (k % 2 == 1) {
                    out[k / 2] |= d;
                } else {
                    out[k / 2] = d << 4;
                }
            }
            if (name[idx] == '/' and k == 32) {
                addrp.* = .{ .ip6 = out };
                return protocol.F_IPV6;
            }
            return 0;
        }

        const end = penchunk orelse 0;
        var i: usize = 0;
        while (i < end) {
            const chunk = std.mem.sliceTo(name[i..], 0);
            if (name[i + 1] != 0 or chunk.len != 1 or !std.ascii.isHex(chunk[0])) return 0;
            var k: usize = @sizeOf([16]u8) - 1;
            while (k > 0) : (k -= 1) {
                out[k] = (out[k] >> 4) | (out[k - 1] << 4);
            }
            out[0] = (out[0] >> 4) | (hexDigit(chunk[0]) << 4);
            i += chunk.len + 1;
        }
        addrp.* = .{ .ip6 = out };
        return protocol.F_IPV6;
    }

    return 0;
}

fn hexDigit(c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => 0,
    };
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------
test "extract name simple" {
    // 报文：header(12) + 3www 7example 3com 0 + type/class
    var pkt: [64]u8 = [_]u8{0} ** 64;
    protocol.setQdcount(&pkt, 1);
    var off: usize = 12;
    off += doRfc1035Name(pkt[off..], "www.example.com").?;
    protocol.putShort(&pkt, off, protocol.T_A);
    off += 2;
    protocol.putShort(&pkt, off, protocol.C_IN);
    off += 2;

    var name: [protocol.MAXDNAMESTR + 1]u8 = undefined;
    var p: usize = 12;
    try std.testing.expectEqual(@as(i32, 1), extractName(&pkt, off, &p, &name, EXTR_NAME_EXTRACT, 4));
    try std.testing.expectEqualStrings("www.example.com", std.mem.sliceTo(&name, 0));
    try std.testing.expectEqual(@as(usize, off - 4), p);
    try std.testing.expectEqual(@as(usize, off), skipQuestions(&pkt, off).?);
}

test "extract name compression" {
    var pkt: [64]u8 = [_]u8{0} ** 64;
    protocol.setQdcount(&pkt, 2);
    var off: usize = 12;
    off += doRfc1035Name(pkt[off..], "example.com").?;
    protocol.putShort(&pkt, off, protocol.T_A);
    off += 2;
    protocol.putShort(&pkt, off, protocol.C_IN);
    off += 2;
    // 第二个问题的名字用压缩指针指回 12
    const ptr_off = off;
    protocol.putShort(&pkt, off, 0xC000 | 12);
    off += 2;
    protocol.putShort(&pkt, off, protocol.T_AAAA);
    off += 2;
    protocol.putShort(&pkt, off, protocol.C_IN);
    off += 2;

    var name: [protocol.MAXDNAMESTR + 1]u8 = undefined;

    // 直接解析第一个问题：游标停在名字之后
    var p: usize = 12;
    try std.testing.expectEqual(@as(i32, 1), extractName(&pkt, off, &p, &name, EXTR_NAME_EXTRACT, 4));
    try std.testing.expectEqualStrings("example.com", std.mem.sliceTo(&name, 0));
    try std.testing.expectEqual(ptr_off - 4, p);

    // 解析压缩指针：名字相同，游标返回跳转点（指针之后）
    var q: usize = ptr_off;
    try std.testing.expectEqual(@as(i32, 1), extractName(&pkt, off, &q, &name, EXTR_NAME_EXTRACT, 4));
    try std.testing.expectEqualStrings("example.com", std.mem.sliceTo(&name, 0));
    try std.testing.expectEqual(ptr_off + 2, q);

    // skip_questions 应跳过两个问题
    try std.testing.expectEqual(off, skipQuestions(&pkt, off).?);
}

test "name compare modes" {
    var pkt: [64]u8 = [_]u8{0} ** 64;
    const off = doRfc1035Name(pkt[12..], "ExAmple.COM").? + 12;

    var buf: [64]u8 = undefined;
    @memcpy(buf[0..11], "example.com");
    buf[11] = 0;
    var p: usize = 12;
    // 大小写不敏感比较应匹配
    try std.testing.expectEqual(@as(i32, 1), extractName(&pkt, off, &p, &buf, EXTR_NAME_COMPARE, 0));

    var p2: usize = 12;
    // 大小写敏感比较应报 3（仅大小写不同）
    try std.testing.expectEqual(@as(i32, 3), extractName(&pkt, off, &p2, &buf, EXTR_NAME_NOCASE, 0));

    @memcpy(buf[0..7], "example");
    buf[7] = 0;
    var p3: usize = 12;
    try std.testing.expectEqual(@as(i32, 2), extractName(&pkt, off, &p3, &buf, EXTR_NAME_COMPARE, 0));
}

test "do_rfc1035_name round trip with escapes" {
    var wire: [128]u8 = undefined;
    const n = doRfc1035Name(&wire, "a\\001b.example").?;
    var back: [protocol.MAXDNAMESTR + 1]u8 = undefined;
    var p: usize = 0;
    try std.testing.expectEqual(@as(i32, 1), extractName(&wire, n, &p, &back, EXTR_NAME_EXTRACT, 0));
    try std.testing.expectEqualStrings("a\\001b.example", std.mem.sliceTo(&back, 0));
}

test "hostname compare helpers" {
    try std.testing.expect(hostnameIsEqual("Example.COM", "example.com"));
    try std.testing.expectEqual(@as(i32, 2), hostnameIsSubdomain("example.com", "example.com"));
    try std.testing.expectEqual(@as(i32, 1), hostnameIsSubdomain("example.com", "www.example.com"));
    try std.testing.expectEqual(@as(i32, 0), hostnameIsSubdomain("example.com", "notexample.com"));
    try std.testing.expectEqual(@as(i32, 1), hostnameIsSubdomain("", "anything"));
    try std.testing.expectEqual(@as(i32, 0), hostnameIsSubdomain("example.com", "example.org"));
}

test "in_arpa_name_2_addr" {
    var a: addr.AllAddr = .{ .none = {} };
    try std.testing.expectEqual(protocol.F_IPV4, inArpaName2Addr("1.0.168.192.in-addr.arpa", &a));
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("192.168.0.1", addr.writeIp4(&buf, a.ip4));

    try std.testing.expectEqual(protocol.F_IPV4, inArpaName2Addr("1.0.1.in-addr.arpa", &a));
    try std.testing.expectEqualStrings("1.0.1.0", addr.writeIp4(&buf, a.ip4));

    try std.testing.expectEqual(protocol.F_IPV6, inArpaName2Addr("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa", &a));
    try std.testing.expectEqual(@as(u8, 0x20), a.ip6[0]);
    try std.testing.expectEqual(@as(u8, 0x01), a.ip6[1]);
    try std.testing.expectEqual(@as(u8, 0x0d), a.ip6[2]);
    try std.testing.expectEqual(@as(u8, 0xb8), a.ip6[3]);
    try std.testing.expectEqual(@as(u8, 0x01), a.ip6[15]);

    // 名字过长（> MAXARPANAME）应被拒绝
    try std.testing.expectEqual(@as(u32, 0), inArpaName2Addr("0." ** 40 ++ "ip6.arpa", &a));

    try std.testing.expectEqual(@as(u32, 0), inArpaName2Addr("example.com", &a));
}

test "legal hostname and canonicalise" {
    try std.testing.expect(legalHostname("host1.example.com"));
    try std.testing.expect(!legalHostname("-bad.example.com"));
    try std.testing.expect(!legalHostname(""));

    const allocator = std.testing.allocator;
    const c = canonicalise(allocator, "Example.com.").?;
    defer allocator.free(c);
    try std.testing.expectEqualStrings("Example.com", c);
    try std.testing.expect(canonicalise(allocator, "") == null);
    const long_label = "a" ** 64;
    try std.testing.expect(canonicalise(allocator, long_label) == null);
}
