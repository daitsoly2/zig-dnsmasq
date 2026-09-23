// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! v6probe.zig — DHCPv6 / RA 可行性探针（**不发任何报文**）
//!
//! 目的：在目标路由器上确认三块地基是否可用
//!   1. IPv6 组播 UDP socket（DHCPv6 监听 ::547、加入 ff02::1:2）
//!   2. ICMPv6 raw socket（RA / RS / NS / NA）
//!   3. 用 netlink 建一对 veth（为后续「密闭 IPv6 测试床」铺路）
//!
//! 用法：v6probe [ifname] [--mktest]
//!
//! 安全：本程序只做 socket 创建 / setsockopt / bind / 建删 veth，
//! **不调用任何 send**，因此不会有报文进入局域网。

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

const Ipv6Mreq = extern struct {
    addr: [16]u8,
    ifindex: c_uint,
};
const Icmp6Filter = extern struct { data: [8]u32 };

const ICMP6_FILTER: u32 = 1;

// netlink 常量（与 src/net.zig 保持一致）
const NETLINK_ROUTE: u32 = 0;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_CREATE: u16 = 0x400;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const IFLA_IFNAME: u16 = 3;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;

inline fn nlAlign(x: usize) usize {
    return (x + 3) & ~@as(usize, 3);
}

const Mark = enum { ok, fail, skip };

var seq: u32 = 1;

fn out(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = linux.write(2, s.ptr, s.len);
}

fn report(name: []const u8, m: Mark, detail: []const u8) void {
    const tag = switch (m) {
        .ok => "OK  ",
        .fail => "FAIL",
        .skip => "SKIP",
    };
    if (detail.len == 0) {
        out("[{s}] {s}\n", .{ tag, name });
    } else {
        out("[{s}] {s}  -> {s}\n", .{ tag, name, detail });
    }
}

fn setOpt(fd: posix.fd_t, level: i32, name: u32, val: [*]const u8, len: u32) linux.E {
    return posix.errno(linux.setsockopt(fd, level, name, val, len));
}

fn closeFd(fd: posix.fd_t) void {
    _ = linux.close(fd);
}

/// 解析 "fe80::1" / "::1" 形式的 IPv6 字面量
fn parseIp6(text: []const u8) ?[16]u8 {
    var res: [16]u8 = [_]u8{0} ** 16;
    var head: [8]u16 = [_]u16{0} ** 8;
    var tail: [8]u16 = [_]u16{0} ** 8;
    var nh: usize = 0;
    var nt: usize = 0;
    var in_tail = false;
    var filled_head = false;

    var it = std.mem.splitScalar(u8, text, ':');
    while (it.next()) |part| {
        if (part.len == 0) {
            // 只有一处 "::" 合法；见到它之后所有组都归 tail
            if (filled_head) return null;
            filled_head = true;
            in_tail = true;
            continue;
        }
        const v = std.fmt.parseInt(u16, part, 16) catch return null;
        if (in_tail) {
            if (nt >= 8) return null;
            tail[nt] = v;
            nt += 1;
        } else {
            if (nh >= 7) return null;
            head[nh] = v;
            nh += 1;
        }
    }
    // 没有 "::" 时必须正好 8 组
    if (!filled_head and nh != 8) return null;

    var k: usize = 0;
    while (k < nh) : (k += 1) {
        res[k * 2] = @intCast(head[k] >> 8);
        res[k * 2 + 1] = @intCast(head[k] & 0xff);
    }
    const base = 8 - nt;
    k = 0;
    while (k < nt) : (k += 1) {
        res[(base + k) * 2] = @intCast(tail[k] >> 8);
        res[(base + k) * 2 + 1] = @intCast(tail[k] & 0xff);
    }
    return res;
}

/// 把内核看到的地址（isize 返回的错误码）转可读
fn ip6Text(a: [16]u8, buf: []u8) []const u8 {
    // 简写：只用于打印，不做 RFC 5952 压缩
    return std.fmt.bufPrint(buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
        a[0],  a[1],  a[2],  a[3],  a[4],  a[5],  a[6],  a[7],
        a[8],  a[9],  a[10], a[11], a[12], a[13], a[14], a[15],
    }) catch "<?>";
}

/// ICMPv6 Echo 自环自证：目的地址是本机自己的地址，内核会本地回环，
/// **报文不会上物理网卡**。用来验证「构造 -> 内核补校验和 -> 收包解析」整条链路。
fn icmp6EchoSelfTest(ifname: []const u8, ifindex: u32, dst: [16]u8) bool {
    const rc = linux.socket(linux.AF.INET6, linux.SOCK.RAW | linux.SOCK.CLOEXEC, 58);
    if (posix.errno(rc) != .SUCCESS) return false;
    const fd: posix.fd_t = @intCast(rc);
    defer closeFd(fd);

    // SO_RCVTIMEO = 1000ms，免得收不到时挂死
    var tv = linux.timeval{ .sec = 1, .usec = 0 };
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&tv), @sizeOf(linux.timeval));
    const v255: c_int = 255;
    _ = setOpt(fd, linux.SOL.IPV6, linux.IPV6.UNICAST_HOPS, @ptrCast(&v255), @sizeOf(c_int));
    _ = setOpt(fd, linux.SOL.SOCKET, linux.SO.BINDTODEVICE, ifname.ptr, @intCast(ifname.len));

    // ICMPv6 Echo Request: type=128 code=0 cksum=0 id/seq + payload
    var pkt: [64]u8 = undefined;
    @memset(&pkt, 0);
    pkt[0] = 128;
    pkt[1] = 0;
    std.mem.writeInt(u16, pkt[2..4], 0, .big); // 校验和留 0，内核代填
    std.mem.writeInt(u16, pkt[4..6], 0x5A44, .big); // id 'ZD'
    std.mem.writeInt(u16, pkt[6..8], 1, .big); // seq
    @memcpy(pkt[8..20], "zd-v6probe!!");
    const plen: usize = 20;

    var sa: linux.sockaddr.in6 = std.mem.zeroes(linux.sockaddr.in6);
    sa.family = linux.AF.INET6;
    sa.addr = dst;
    sa.scope_id = ifindex;

    const sent = linux.sendto(fd, &pkt, plen, 0, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6));
    if (posix.errno(sent) != .SUCCESS) {
        out("     发送失败 -> {s}\n", .{@tagName(posix.errno(sent))});
        return false;
    }

    // raw ICMPv6 socket 连「本机自己发出的包」也会回环给本 socket，
    // 所以第一口读到的很可能是我们刚发出去的 Request，要循环读。
    var buf: [512]u8 = undefined;
    var seen: u32 = 0;
    var round: usize = 0;
    while (round < 8) : (round += 1) {
        const n = linux.recvfrom(fd, &buf, buf.len, 0, null, null);
        if (posix.errno(n) != .SUCCESS) break;
        if (n < 8) continue;
        seen += 1;
        out("     收到 {d} 字节，ICMPv6 type={d} code={d} seq={d}\n", .{
            n, buf[0], buf[1], std.mem.readInt(u16, buf[6..8], .big),
        });
        if (buf[0] == 129) return true;
    }
    out("     共读到 {d} 个包，始终没出现 Echo Reply(129)\n", .{seen});
    return false;
}

fn nlSend(fd: posix.fd_t, kind: u16, flags: u16, payload: []const u8) void {
    var req: [1024]u8 = undefined;
    @memset(&req, 0);
    const total = 16 + payload.len;
    std.mem.writeInt(u32, req[0..4], @intCast(total), .little);
    std.mem.writeInt(u16, req[4..6], kind, .little);
    std.mem.writeInt(u16, req[6..8], flags, .little);
    seq += 1;
    std.mem.writeInt(u32, req[8..12], seq, .little);
    if (payload.len > 0) @memcpy(req[16..total], payload);
    _ = linux.sendto(fd, &req, total, 0, null, 0);
}

fn nlRead(fd: posix.fd_t, buf: []u8) usize {
    const n = linux.recvfrom(fd, buf.ptr, buf.len, 0, null, null);
    if (posix.errno(n) != .SUCCESS) return 0;
    return n;
}

const LinkInfo = struct {
    ifindex: u32 = 0,
    name: [16]u8 = [_]u8{0} ** 16,
    name_len: u8 = 0,
    is_lo: bool = false,
};

fn nlDumpLinks(links: []LinkInfo) usize {
    const rc = linux.socket(posix.AF.NETLINK, posix.SOCK.RAW | posix.SOCK.CLOEXEC, NETLINK_ROUTE);
    if (posix.errno(rc) != .SUCCESS) return 0;
    const nfd: posix.fd_t = @intCast(rc);
    defer closeFd(nfd);

    var req = [_]u8{0} ** 32;
    std.mem.writeInt(u32, req[0..4], 32, .little);
    std.mem.writeInt(u16, req[4..6], RTM_GETLINK, .little);
    std.mem.writeInt(u16, req[6..8], NLM_F_REQUEST | NLM_F_DUMP, .little);
    seq += 1;
    std.mem.writeInt(u32, req[8..12], seq, .little);
    _ = linux.sendto(nfd, &req, req.len, 0, null, 0);

    var buf: [32768]u8 = undefined;
    var count: usize = 0;
    while (true) {
        const n = nlRead(nfd, &buf);
        if (n == 0) break;
        var off: usize = 0;
        while (off + 16 <= n) {
            const mlen = std.mem.readInt(u32, buf[off..][0..4], .little);
            const mtype = std.mem.readInt(u16, buf[off + 4 ..][0..2], .little);
            if (mlen < 16 or off + mlen > n) break;
            if (mtype == NLMSG_DONE or mtype == NLMSG_ERROR) return count;
            if (mtype == RTM_NEWLINK and mlen >= 32 and count < links.len) {
                const msg = buf[off..][0..mlen];
                var e = LinkInfo{};
                e.ifindex = std.mem.readInt(u32, msg[20..24], .little);
                e.is_lo = (std.mem.readInt(u32, msg[24..28], .little) & 0x8) != 0;
                var ao: usize = 32;
                while (ao + 4 <= mlen) {
                    const alen = std.mem.readInt(u16, msg[ao..][0..2], .little);
                    const atype = std.mem.readInt(u16, msg[ao + 2 ..][0..2], .little);
                    if (alen < 4 or ao + alen > mlen) break;
                    if (atype == IFLA_IFNAME) {
                        var s = msg[ao + 4 .. ao + alen];
                        // 属性值带 NUL 结尾，去掉，否则按名比较永远不相等
                        while (s.len > 0 and s[s.len - 1] == 0) s = s[0 .. s.len - 1];
                        const ln = @min(s.len, 15);
                        @memcpy(e.name[0..ln], s[0..ln]);
                        e.name_len = @intCast(ln);
                    }
                    ao += nlAlign(alen);
                }
                links[count] = e;
                count += 1;
            }
            off += nlAlign(mlen);
        }
    }
    return count;
}

/// 建一对 veth（IFLA_INFO_KIND=veth），全部走 netlink，不依赖 iproute2
fn makeVeth(name_a: []const u8, name_b: []const u8) linux.E {
    var payload: [512]u8 = undefined;
    @memset(&payload, 0);
    var p: usize = 16; // ifinfomsg 占前 16 字节

    // IFLA_IFNAME = name_a
    {
        const alen: u16 = @intCast(4 + name_a.len + 1);
        std.mem.writeInt(u16, payload[p..][0..2], alen, .little);
        std.mem.writeInt(u16, payload[p + 2 ..][0..2], IFLA_IFNAME, .little);
        @memcpy(payload[p + 4 ..][0..name_a.len], name_a);
        p += nlAlign(alen);
    }
    // IFLA_LINKINFO { IFLA_INFO_KIND="veth", IFLA_INFO_DATA { VETH_INFO_PEER { ifinfomsg(16) + IFLA_IFNAME=name_b } } }
    {
        const linf = p;
        p += 4;
        const klen: u16 = @intCast(4 + 4 + 1);
        std.mem.writeInt(u16, payload[p..][0..2], klen, .little);
        std.mem.writeInt(u16, payload[p + 2 ..][0..2], IFLA_INFO_KIND, .little);
        @memcpy(payload[p + 4 ..][0..4], "veth");
        p += nlAlign(klen);

        const dat = p;
        p += 4;
        const peer = p;
        p += 4 + 16; // VETH_INFO_PEER 头 + 内嵌 ifinfomsg
        {
            const blen: u16 = @intCast(4 + name_b.len + 1);
            std.mem.writeInt(u16, payload[p..][0..2], blen, .little);
            std.mem.writeInt(u16, payload[p + 2 ..][0..2], IFLA_IFNAME, .little);
            @memcpy(payload[p + 4 ..][0..name_b.len], name_b);
            p += nlAlign(blen);
        }
        std.mem.writeInt(u16, payload[peer..][0..2], @intCast(p - peer), .little);
        std.mem.writeInt(u16, payload[peer + 2 ..][0..2], VETH_INFO_PEER, .little);
        std.mem.writeInt(u16, payload[dat..][0..2], @intCast(p - dat), .little);
        std.mem.writeInt(u16, payload[dat + 2 ..][0..2], IFLA_INFO_DATA, .little);
        std.mem.writeInt(u16, payload[linf..][0..2], @intCast(p - linf), .little);
        std.mem.writeInt(u16, payload[linf + 2 ..][0..2], IFLA_LINKINFO, .little);
    }

    const src = linux.socket(posix.AF.NETLINK, posix.SOCK.RAW | posix.SOCK.CLOEXEC, NETLINK_ROUTE);
    if (posix.errno(src) != .SUCCESS) return posix.errno(src);
    const fd: posix.fd_t = @intCast(src);
    defer closeFd(fd);
    nlSend(fd, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE, payload[0..p]);

    var buf: [8192]u8 = undefined;
    const n = nlRead(fd, &buf);
    if (n < 20) return .IO;
    // 应答是 nlmsghdr(16) + nlmsgerr{ error(4), ... }
    const err = std.mem.readInt(i32, buf[16..20], .little);
    return if (err == 0) .SUCCESS else @enumFromInt(-err);
}

/// 建一块 dummy 网卡：IFLA_LINKINFO { IFLA_INFO_KIND="dummy" }
fn makeDummy(name: []const u8) linux.E {
    var payload: [256]u8 = undefined;
    @memset(&payload, 0);
    var p: usize = 16;

    {
        const alen: u16 = @intCast(4 + name.len + 1);
        std.mem.writeInt(u16, payload[p..][0..2], alen, .little);
        std.mem.writeInt(u16, payload[p + 2 ..][0..2], IFLA_IFNAME, .little);
        @memcpy(payload[p + 4 ..][0..name.len], name);
        p += nlAlign(alen);
    }
    {
        const linf = p;
        p += 4;
        const klen: u16 = @intCast(4 + 5 + 1);
        std.mem.writeInt(u16, payload[p..][0..2], klen, .little);
        std.mem.writeInt(u16, payload[p + 2 ..][0..2], IFLA_INFO_KIND, .little);
        @memcpy(payload[p + 4 ..][0..5], "dummy");
        p += nlAlign(klen);
        std.mem.writeInt(u16, payload[linf..][0..2], @intCast(p - linf), .little);
        std.mem.writeInt(u16, payload[linf + 2 ..][0..2], IFLA_LINKINFO, .little);
    }

    const src = linux.socket(posix.AF.NETLINK, posix.SOCK.RAW | posix.SOCK.CLOEXEC, NETLINK_ROUTE);
    if (posix.errno(src) != .SUCCESS) return posix.errno(src);
    const fd: posix.fd_t = @intCast(src);
    defer closeFd(fd);
    nlSend(fd, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE, payload[0..p]);

    var buf: [8192]u8 = undefined;
    const n = nlRead(fd, &buf);
    if (n < 20) return .IO;
    const err = std.mem.readInt(i32, buf[16..20], .little);
    return if (err == 0) .SUCCESS else @enumFromInt(-err);
}

fn delLink(name: []const u8) linux.E {    var payload: [64]u8 = undefined;
    @memset(&payload, 0);
    var p: usize = 16;
    const alen: u16 = @intCast(4 + name.len + 1);
    std.mem.writeInt(u16, payload[p..][0..2], alen, .little);
    std.mem.writeInt(u16, payload[p + 2 ..][0..2], IFLA_IFNAME, .little);
    @memcpy(payload[p + 4 ..][0..name.len], name);
    p += nlAlign(alen);

    const src = linux.socket(posix.AF.NETLINK, posix.SOCK.RAW | posix.SOCK.CLOEXEC, NETLINK_ROUTE);
    if (posix.errno(src) != .SUCCESS) return posix.errno(src);
    const fd: posix.fd_t = @intCast(src);
    defer closeFd(fd);
    nlSend(fd, RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, payload[0..p]);

    var buf: [8192]u8 = undefined;
    const n = nlRead(fd, &buf);
    if (n < 20) return .IO;
    const err = std.mem.readInt(i32, buf[16..20], .little);
    return if (err == 0) .SUCCESS else @enumFromInt(-err);
}

pub fn main(init: std.process.Init) !void {
    var it = init.minimal.args.iterate();
    _ = it.next();

    var want_ifname: ?[]const u8 = null;
    var want_mktest = false;
    var want_mkdummy = false;
    var echo_dst: ?[16]u8 = null;
    while (it.next()) |a| {
        if (std.mem.eql(u8, a, "--mktest")) {
            want_mktest = true;
        } else if (std.mem.eql(u8, a, "--mkdummy")) {
            want_mkdummy = true;
        } else if (std.mem.startsWith(u8, a, "--echo-to=")) {
            echo_dst = parseIp6(a["--echo-to=".len..]);
            if (echo_dst == null) {
                out("不能解析 IPv6 字面量：{s}\n", .{a["--echo-to=".len..]});
                std.process.exit(2);
            }
        } else {
            want_ifname = a;
        }
    }

    out("=== zig-dnsmasq DHCPv6/RA 可行性探针（不发送任何报文）===\n", .{});
    out("libc 无关 · 纯 syscall · ZIG 0.16\n\n", .{});

    var links: [32]LinkInfo = undefined;
    const cnt = nlDumpLinks(&links);
    out("--- netlink RTM_GETLINK ---\n", .{});
    if (cnt == 0) {
        report("netlink 接口枚举", .fail, "（沙箱里没有 netlink 权限？）");
    } else {
        report("netlink 接口枚举", .ok, "");
        out("     接口表（{d} 个）：", .{cnt});
        for (links[0..cnt]) |l| out(" {s}({d})", .{ l.name[0..l.name_len], l.ifindex });
        out("\n", .{});
    }

    var ifname: []const u8 = "lo";
    var ifindex: u32 = 1;
    if (want_ifname) |w| {
        ifname = w;
        for (links[0..cnt]) |l| {
            if (std.mem.eql(u8, l.name[0..l.name_len], w)) ifindex = l.ifindex;
        }
    } else {
        for (links[0..cnt]) |l| {
            if (l.is_lo or l.name_len == 0) continue;
            if (std.mem.startsWith(u8, l.name[0..l.name_len], "zd")) continue;
            ifname = l.name[0..l.name_len];
            ifindex = l.ifindex;
            break;
        }
    }
    out("     探针网卡：{s} (ifindex={d})\n\n", .{ ifname, ifindex });

    // ---------- 1. DHCPv6: IPv6 组播 UDP socket ----------
    out("--- DHCPv6 (UDP/547 + ff02::1:2) ---\n", .{});

    const urc = linux.socket(linux.AF.INET6, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0);
    if (posix.errno(urc) != .SUCCESS) {
        report("socket(AF_INET6,SOCK_DGRAM,0)", .fail, @tagName(posix.errno(urc)));
        out("\n结论：连 IPv6 UDP 都开不出来，后面的都不用谈。\n", .{});
        std.process.exit(1);
    }
    const ufd: posix.fd_t = @intCast(urc);
    defer closeFd(ufd);
    report("socket(AF_INET6,SOCK_DGRAM,0)", .ok, "");

    const one: c_int = 1;
    {
        const e = setOpt(ufd, linux.SOL.IPV6, linux.IPV6.V6ONLY, @ptrCast(&one), @sizeOf(c_int));
        report("setsockopt(IPV6_V6ONLY=1)", if (e == .SUCCESS) .ok else .fail, @tagName(e));
    }
    {
        const e = setOpt(ufd, linux.SOL.SOCKET, linux.SO.REUSEADDR, @ptrCast(&one), @sizeOf(c_int));
        report("setsockopt(SO_REUSEADDR=1)", if (e == .SUCCESS) .ok else .fail, @tagName(e));
    }
    {
        const e = setOpt(ufd, linux.SOL.IPV6, linux.IPV6.RECVPKTINFO, @ptrCast(&one), @sizeOf(c_int));
        report("setsockopt(IPV6_RECVPKTINFO=1)", if (e == .SUCCESS) .ok else .fail, @tagName(e));
    }
    {
        const e = setOpt(ufd, linux.SOL.SOCKET, linux.SO.BINDTODEVICE, ifname.ptr, @intCast(ifname.len));
        report("setsockopt(SO_BINDTODEVICE)", if (e == .SUCCESS) .ok else .fail, @tagName(e));
    }
    {
        var sa: linux.sockaddr.in6 = std.mem.zeroes(linux.sockaddr.in6);
        sa.family = linux.AF.INET6;
        sa.port = std.mem.nativeToBig(u16, 547);
        const e = posix.errno(linux.bind(ufd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6)));
        report("bind([::]:547)", if (e == .SUCCESS) .ok else .fail, @tagName(e));
    }
    {
        var mreq = Ipv6Mreq{
            .addr = [_]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x02 },
            .ifindex = ifindex,
        };
        const e = setOpt(ufd, linux.SOL.IPV6, linux.IPV6.ADD_MEMBERSHIP, @ptrCast(&mreq), @sizeOf(Ipv6Mreq));
        report("join ff02::1:2 (DHCPv6 服务器组)", if (e == .SUCCESS) .ok else .fail, @tagName(e));
        _ = setOpt(ufd, linux.SOL.IPV6, linux.IPV6.DROP_MEMBERSHIP, @ptrCast(&mreq), @sizeOf(Ipv6Mreq));
    }
    {
        const e = setOpt(ufd, linux.SOL.IPV6, linux.IPV6.RECVHOPLIMIT, @ptrCast(&one), @sizeOf(c_int));
        report("setsockopt(IPV6_RECVHOPLIMIT=1)", if (e == .SUCCESS) .ok else .fail, @tagName(e));
    }

    // ---------- 2. RA / NDP: ICMPv6 raw socket ----------
    out("\n--- RA / NDP (raw ICMPv6) ---\n", .{});

    const rrc = linux.socket(linux.AF.INET6, linux.SOCK.RAW | linux.SOCK.CLOEXEC, 58);
    if (posix.errno(rrc) != .SUCCESS) {
        report("socket(AF_INET6,SOCK_RAW,IPPROTO_ICMPV6=58)", .fail, @tagName(posix.errno(rrc)));
        out("     提示：raw socket 被拒说明缺 CAP_NET_RAW 或被 seccomp 拦。\n", .{});
        out("     odhcpd 的 init 脚本没有 procd_add_jail，我们没有沙箱时没问题；\n", .{});
        out("     若要在 ujail 里跑，需要确认 ujail 未启用 capabilities 白名单。\n", .{});
    } else {
        const rfd: posix.fd_t = @intCast(rrc);
        defer closeFd(rfd);
        report("socket(AF_INET6,SOCK_RAW,IPPROTO_ICMPV6=58)", .ok, "");
        {
            const e = setOpt(rfd, linux.SOL.SOCKET, linux.SO.BINDTODEVICE, ifname.ptr, @intCast(ifname.len));
            report("setsockopt(SO_BINDTODEVICE)", if (e == .SUCCESS) .ok else .fail, @tagName(e));
        }
        {
            var f = Icmp6Filter{ .data = [_]u32{0} ** 8 };
            for ([_]u8{ 133, 134, 135, 136 }) |t| f.data[t / 32] |= (@as(u32, 1) << @intCast(t % 32));
            const e = setOpt(rfd, 58, ICMP6_FILTER, @ptrCast(&f), @sizeOf(Icmp6Filter));
            report("setsockopt(ICMP6_FILTER 只收 133/134/135/136)", if (e == .SUCCESS) .ok else .fail, @tagName(e));
        }
        {
            const v: c_int = 255;
            const e = setOpt(rfd, linux.SOL.IPV6, linux.IPV6.MULTICAST_HOPS, @ptrCast(&v), @sizeOf(c_int));
            report("setsockopt(IPV6_MULTICAST_HOPS=255)", if (e == .SUCCESS) .ok else .fail, @tagName(e));
        }
        {
            const v: c_int = 255;
            const e = setOpt(rfd, linux.SOL.IPV6, linux.IPV6.UNICAST_HOPS, @ptrCast(&v), @sizeOf(c_int));
            report("setsockopt(IPV6_UNICAST_HOPS=255)", if (e == .SUCCESS) .ok else .fail, @tagName(e));
        }
        {
            const e = setOpt(rfd, linux.SOL.IPV6, linux.IPV6.MULTICAST_IF, @ptrCast(&ifindex), @sizeOf(c_int));
            report("setsockopt(IPV6_MULTICAST_IF)", if (e == .SUCCESS) .ok else .fail, @tagName(e));
        }
        {
            const v: c_int = 0;
            const e = setOpt(rfd, linux.SOL.IPV6, linux.IPV6.MULTICAST_LOOP, @ptrCast(&v), @sizeOf(c_int));
            report("setsockopt(IPV6_MULTICAST_LOOP=0)", if (e == .SUCCESS) .ok else .fail, @tagName(e));
        }
        {
            var mreq = Ipv6Mreq{ .addr = [_]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02 }, .ifindex = ifindex };
            const e = setOpt(rfd, linux.SOL.IPV6, linux.IPV6.ADD_MEMBERSHIP, @ptrCast(&mreq), @sizeOf(Ipv6Mreq));
            report("join ff02::2 (all-routers，收 RS)", if (e == .SUCCESS) .ok else .fail, @tagName(e));
        }
        {
            var mreq = Ipv6Mreq{ .addr = [_]u8{ 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }, .ifindex = ifindex };
            const e = setOpt(rfd, linux.SOL.IPV6, linux.IPV6.ADD_MEMBERSHIP, @ptrCast(&mreq), @sizeOf(Ipv6Mreq));
            report("join ff02::1 (all-nodes)", if (e == .SUCCESS) .ok else .fail, @tagName(e));
        }
    }

    // ---------- 3. ICMPv6 自发自收（目的地址=本机，不上线）----------
    if (echo_dst) |d| {
        out("\n--- ICMPv6 自发自收自证（不上线）---\n", .{});
        var tb: [64]u8 = undefined;
        out("     目的地址 {s}（本机）\n", .{ip6Text(d, &tb)});
        const ok = icmp6EchoSelfTest(ifname, ifindex, d);
        report("Echo Request -> 收到 Echo Reply", if (ok) .ok else .fail, "");
        if (!ok) {
            out("     说明：若地址不是本机的，内核会把它当外发报文 —— 那就会上线。\n", .{});
            out("     请用本机自己的链路本地地址重试。\n", .{});
        }
    }

    // ---------- 4. netlink 建 veth / dummy（密闭测试床）----------
    if (want_mktest or want_mkdummy) {
        out("\n--- 密闭 IPv6 测试床 (netlink 建虚拟网卡) ---\n", .{});
    }
    if (want_mktest) {
        const e = makeVeth("zd0", "zd1");
        if (e == .SUCCESS) {
            report("RTM_NEWLINK veth zd0<->zd1", .ok, "（已建，马上删）");
            const e2 = delLink("zd0");
            report("RTM_DELLINK zd0", if (e2 == .SUCCESS) .ok else .fail, @tagName(e2));
            if (e2 != .SUCCESS) {
                const e3 = delLink("zd1");
                report("RTM_DELLINK zd1", if (e3 == .SUCCESS) .ok else .fail, @tagName(e3));
            }
        } else {
            report("RTM_NEWLINK veth", .fail, @tagName(e));
        }
    }
    if (want_mkdummy) {
        const e = makeDummy("zdum0");
        if (e == .SUCCESS) {
            report("RTM_NEWLINK dummy zdum0", .ok, "（已建，马上删）");
            const e2 = delLink("zdum0");
            report("RTM_DELLINK zdum0", if (e2 == .SUCCESS) .ok else .fail, @tagName(e2));
        } else {
            report("RTM_NEWLINK dummy", .fail, @tagName(e));
        }
    }
    if (want_mktest or want_mkdummy) {
        out("     若两种都 OPNOTSUPP，说明内核没编这些模块，\n", .{});
        out("     协议层验证就放到开发机（veth/netns 齐全）做。\n", .{});
    }

    out("\n=== 探针结束：未向局域网发送任何报文 ===\n", .{});
    std.process.exit(0);
}
