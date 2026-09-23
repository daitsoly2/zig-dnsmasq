// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! rs_probe.zig — 在 LAN 里实测 RA / DHCPv6 服务的**主动**探针。
//!
//! 用法（在 192.168.0.2 上跑，对 .1 的 odhcpd 移植做端到端验证）：
//!   rs_probe ra   [ifname]   发 RS(ff02::2) → 等 RA，打印 PIO/RDNSS/DNSSL/MTU
//!   rs_probe dh6  [ifname]   发 INFORMATION-REQUEST(ff02::1:2:547) → 等 REPLY，
//!                            打印 server-id/DNS/域名
//!
//! RS 用未指定源（RFC 4861 允许），不带 SLLA 选项；RA 会发到 ff02::1，
//! 所以探针要加入 ff02::1 组。全程只发 1 个报文，风险可控。

const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

const IPPROTO_ICMPV6: i32 = 58;
const ICMP6_FILTER: u32 = 1;
const IPV6_ADD_MEMBERSHIP = 20;

const Ipv6Mreq = extern struct { multiaddr: [16]u8, ifindex: u32 };

var seq: u32 = 0;
/// 当前模式，供 printRA 判断拿到 RA 后是退出（ra）还是继续等（sniff）。
var mode_global: []const u8 = "ra";

fn out(comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = linux.write(1, s.ptr, s.len);
}

fn die(comptime fmt: []const u8, args: anytype) noreturn {
    out("ERR: " ++ fmt ++ "\n", args);
    linux.exit(1);
}

const AllNodes: [16]u8 = .{ 0xFF, 2 } ++ [_]u8{0} ** 13 ++ .{1};
const AllRouters: [16]u8 = .{ 0xFF, 2 } ++ [_]u8{0} ** 13 ++ .{2};
const AllDhcp: [16]u8 = .{ 0xFF, 2 } ++ [_]u8{0} ** 10 ++ .{ 0, 1, 0, 2 }; // ff02::1:2

fn ifindexOf(name: []const u8) u32 {
    var pathbuf: [128]u8 = undefined;
    const path = std.fmt.bufPrintZ(&pathbuf, "/sys/class/net/{s}/ifindex", .{name}) catch unreachable;
    const fd: i32 = @intCast(linux.open(path, .{ .ACCMODE = .RDONLY }, 0));
    if (fd < 0) die("打不开 {s}", .{path});
    var buf: [32]u8 = undefined;
    const n = linux.read(fd, &buf, buf.len);
    _ = linux.close(fd);
    if (n <= 0) die("读 ifindex 失败", .{});
    return std.fmt.parseInt(u32, std.mem.trim(u8, buf[0..n], " \n"), 10) catch 0;
}

fn macOf(name: []const u8) [6]u8 {
    var pathbuf: [128]u8 = undefined;
    const path = std.fmt.bufPrintZ(&pathbuf, "/sys/class/net/{s}/address", .{name}) catch unreachable;
    const fd: i32 = @intCast(linux.open(path, .{ .ACCMODE = .RDONLY }, 0));
    if (fd < 0) return .{ 0, 0, 0, 0, 0, 0 };
    var buf: [64]u8 = undefined;
    const n = linux.read(fd, &buf, buf.len);
    _ = linux.close(fd);
    var m: [6]u8 = undefined;
    var got: usize = 0;
    var hi: ?u8 = null;
    for (buf[0..n]) |c| {
        const v: u8 = switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            else => continue,
        };
        if (hi) |h| {
            if (got < 6) {
                m[got] = h << 4 | v;
                got += 1;
            }
            hi = null;
        } else hi = v;
    }
    return m;
}

fn openIcmp() i32 {
    const fd = linux.socket(linux.AF.INET6, linux.SOCK.RAW, IPPROTO_ICMPV6);
    if (fd < 0) die("raw ICMPv6 socket 失败", .{});
    return @intCast(fd);
}

fn join(fd: i32, group: [16]u8, ifindex: u32) void {
    const mr = std.mem.toBytes(Ipv6Mreq{ .multiaddr = group, .ifindex = ifindex });
    const rc = linux.setsockopt(fd, linux.IPPROTO.IPV6, IPV6_ADD_MEMBERSHIP, &mr, mr.len);
    if (rc != 0) out("WARN: join 失败 rc={d}\n", .{rc});
}

fn sendRaw(fd: i32, pkt: []const u8, dst: [16]u8, ifindex: u32) void {
    var sa: linux.sockaddr.in6 = .{
        .family = linux.AF.INET6,
        .port = 0,
        .flowinfo = 0,
        .addr = dst,
        .scope_id = ifindex,
    };
    const rc = linux.sendto(fd, pkt.ptr, pkt.len, 0, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6));
    if (rc < 0) die("sendto 失败 errno={d}", .{@as(i32, @intCast(rc)) * -1});
    out("已发送 {d} 字节\n", .{pkt.len});
}

fn nowSecs() i64 {
    var ts: posix.timespec = undefined;
    _ = posix.system.clock_gettime(posix.CLOCK.REALTIME, &ts);
    return @intCast(ts.sec);
}

fn recvLoop(fd: i32, seconds: u32, comptime handle: fn (pkt: []const u8) void) void {
    const deadline = nowSecs() + seconds;
    var buf: [1500]u8 = undefined;
    while (nowSecs() <= deadline) {
        var pfd = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
        const n = linux.poll(&pfd, 1, 500);
        if (n <= 0) continue;
        const r = linux.read(fd, &buf, buf.len);
        if (r <= 0) continue;
        const pkt = buf[0..@intCast(r)];
        // raw socket 会收到自己 TX 的包（比如模式无关的 RS 自环），跳过
        if (pkt.len > 0 and pkt[0] != 134 and pkt[0] != 7) {
            out("（忽略自环/无关包 type={d}）\n", .{pkt[0]});
            continue;
        }
        handle(pkt);
        return;
    }
    out("TIMEOUT: {d}s 内没等到报文\n", .{seconds});
}

// ---------------------------------------------------------------- RA 模式

fn printRA(pkt: []const u8) void {
    if (pkt.len < 16 or pkt[0] != 134) {
        out("收到非 RA 包 type={d} len={d}\n", .{ if (pkt.len > 0) pkt[0] else 0, pkt.len });
        return;
    }
    out("<<< RA 收到！hoplimit={d} M={d} O={d} lifetime={d}s\n", .{
        pkt[4], pkt[5] >> 7 & 1, pkt[5] >> 6 & 1, std.mem.readInt(u16, pkt[6..8], .big),
    });
    var i: usize = 16;
    while (i + 8 <= pkt.len) {
        const otype = pkt[i];
        const olen: usize = @as(usize, pkt[i + 1]) * 8;
        if (olen == 0) break;
        switch (otype) {
            1 => out("  [SrcLLA] {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}\n", .{
                pkt[i + 2], pkt[i + 3], pkt[i + 4], pkt[i + 5], pkt[i + 6], pkt[i + 7],
            }),
            3 => {
                if (i + 32 <= pkt.len) {
                    const plen = pkt[i + 2];
                    const valid = std.mem.readInt(u32, pkt[i + 4 ..][0..4], .big);
                    const pref = std.mem.readInt(u32, pkt[i + 8 ..][0..4], .big);
                    const p = pkt[i + 16 ..][0..16];
                    out("  [PIO] {x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}::/{d} valid={d}s preferred={d}s A={d} L={d}\n", .{
                        p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], plen, valid, pref, pkt[i + 3] >> 6 & 1, pkt[i + 3] >> 7 & 1,
                    });
                }
            },
            5 => out("  [MTU] {d}\n", .{std.mem.readInt(u32, pkt[i + 4 ..][0..4], .big)}),
            25 => {
                const n_addrs = (olen - 8) / 16;
                var k: usize = 0;
                while (k < n_addrs and i + 8 + (k + 1) * 16 <= pkt.len) : (k += 1) {
                    const a = pkt[i + 8 + k * 16 ..][0..16];
                    out("  [RDNSS] {x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2} (lifetime={d}s)\n", .{
                        a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
                        std.mem.readInt(u32, pkt[i + 4 ..][0..4], .big),
                    });
                }
            },
            31 => out("  [DNSSL] {d} 字节\n", .{olen}),
            else => out("  [opt {d}] {d} 字节\n", .{ otype, olen }),
        }
        i += olen;
    }
    // sniff 模式下要接着等下一轮 RA，不能退出；ra 模式等到了就该退出。
    if (std.mem.eql(u8, mode_global, "sniff")) {
        out("  [RA 解码结束，继续监听]\n", .{});
        return;
    }
    linux.exit(0);
}

// ------------------------------------------------------------ DHCPv6 模式

fn printDH6(pkt: []const u8) void {
    if (pkt.len < 4) return;
    const names = [_][]const u8{ "", "SOLICIT", "ADVERTISE", "REQUEST", "CONFIRM", "RENEW", "REBIND", "REPLY", "RELEASE", "DECLINE", "RECONF", "INFO-REQ", "RELAY-FW", "RELAY-RE" };
    const mt = pkt[0];
    out("<<< DHCPv6 收到！type={d}({s})\n", .{ mt, if (mt < names.len) names[mt] else "?" });
    var i: usize = 4;
    while (i + 4 <= pkt.len) {
        const code = std.mem.readInt(u16, pkt[i..][0..2], .big);
        const len = std.mem.readInt(u16, pkt[i + 2 ..][0..2], .big);
        if (i + 4 + len > pkt.len) break;
        const body = pkt[i + 4 ..][0..len];
        switch (code) {
            1 => out("  [client-id] {x}\n", .{body}),
            2 => out("  [server-id] {x}\n", .{body}),
            23 => {
                var k: usize = 0;
                while (k + 16 <= len) : (k += 16) {
                    const a = body[k..][0..16];
                    out("  [DNS] {x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}\n", .{ a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7] });
                }
            },
            24 => out("  [域名] {d} 字节: {x}\n", .{ len, body }),
            13 => out("  [status] code={d}\n", .{if (len >= 2) std.mem.readInt(u16, body[0..2], .big) else 0xFFFF}),
            3 => out("  [IA_NA] {d} 字节\n", .{len}),
            else => out("  [opt {d}] {d} 字节\n", .{ code, len }),
        }
        i += 4 + len;
    }
    linux.exit(0);
}

pub fn main(init: std.process.Init) !void {
    var it = init.minimal.args.iterate();
    _ = it.next(); // argv[0]
    const mode = it.next() orelse "ra";
    mode_global = mode;
    const ifname = it.next() orelse "eth0";
    const ifindex = ifindexOf(ifname);
    const mac = macOf(ifname);
    out("探针：模式={s} 接口={s}({d}) mac={x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}\n", .{
        mode, ifname, ifindex, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
    });

    if (std.mem.eql(u8, mode, "diag")) {
        // 逐步复现 odhcpd 服务端的 socket 序列，打印每一步 errno
        const fd: i32 = @intCast(linux.socket(linux.AF.INET6, linux.SOCK.RAW, 58));
        out("1 socket raw={d}\n", .{fd});
        var one: c_int = 1;
        var rc = linux.setsockopt(fd, 41, 49, @ptrCast(&one), 4); // IPV6_RECVPKTINFO
        out("2 RECVPKTINFO rc={d}\n", .{rc});
        var hops: c_int = 255;
        rc = linux.setsockopt(fd, 41, 16, @ptrCast(&hops), 4);
        out("3 UNICAST_HOPS rc={d}\n", .{rc});
        rc = linux.setsockopt(fd, 41, 18, @ptrCast(&hops), 4);
        out("4 MULTICAST_HOPS rc={d}\n", .{rc});
        var zero: c_int = 0;
        rc = linux.setsockopt(fd, 41, 19, @ptrCast(&zero), 4);
        out("5 MULTICAST_LOOP rc={d}\n", .{rc});
        var f = [_]u8{0xFF} ** 32;
        f[133 / 8] &= ~(@as(u8, 1) << @intCast(133 % 8));
        f[135 / 8] &= ~(@as(u8, 1) << @intCast(135 % 8));
        f[136 / 8] &= ~(@as(u8, 1) << @intCast(136 % 8));
        rc = linux.setsockopt(fd, 58, 1, @ptrCast(&f), 32);
        out("6 ICMP6_FILTER rc={d}\n", .{rc});
        var nbuf: [16]u8 = undefined;
        const nm = std.fmt.bufPrintZ(&nbuf, "{s}", .{ifname}) catch unreachable;
        rc = linux.setsockopt(fd, 1, 25, @ptrCast(nm.ptr), @intCast(nm.len)); // SO_BINDTODEVICE
        out("7 BINDTODEVICE rc={d}\n", .{rc});
        var sa: linux.sockaddr.in6 = .{
            .family = linux.AF.INET6,
            .port = 0,
            .flowinfo = 0,
            .addr = [_]u8{0} ** 16,
            .scope_id = 0,
        };
        rc = linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6));
        out("8 bind(::) rc={d}\n", .{rc});
        const mr = std.mem.toBytes(Ipv6Mreq{ .multiaddr = AllRouters, .ifindex = ifindex });
        rc = linux.setsockopt(fd, 41, 20, @ptrCast(&mr), 20);
        out("9 JOIN ff02::2 if={d} rc={d}\n", .{ ifindex, rc });
        // RA 长度的假包（校验和 0 内核会填，仅测 sendto 是否接受）
        var fake = [_]u8{0} ** 72;
        fake[0] = 134;
        var dsa: linux.sockaddr.in6 = .{
            .family = linux.AF.INET6,
            .port = 0,
            .flowinfo = 0,
            .addr = AllNodes,
            .scope_id = ifindex,
        };
        rc = linux.sendto(fd, &fake, 72, 0, @ptrCast(&dsa), @sizeOf(linux.sockaddr.in6));
        out("10 sendto ff02::1 rc={d}（>0 即成功）\n", .{rc});
        // 对比：不带 BINDTODEVICE 的新 socket 再 join 一次
        const fd2: i32 = @intCast(linux.socket(linux.AF.INET6, linux.SOCK.RAW, 58));
        const mr2 = std.mem.toBytes(Ipv6Mreq{ .multiaddr = AllRouters, .ifindex = ifindex });
        rc = linux.setsockopt(fd2, 41, 20, @ptrCast(&mr2), 20);
        out("11 JOIN(无BINDTODEVICE) rc={d}\n", .{rc});
        linux.exit(0);
    }

    if (std.mem.eql(u8, mode, "sniff")) {
        // 嗅探本机收到的所有 ICMPv6（raw 默认 pass-all，无需 join）
        const fd = openIcmp();
        out("嗅探 {s} 30s（raw 收一切入站 ICMPv6，RA 会整包解码）\n", .{ifname});
        var buf: [1500]u8 = undefined;
        const deadline = nowSecs() + 30;
        while (nowSecs() <= deadline) {
            var pfd = [_]linux.pollfd{.{ .fd = fd, .events = linux.POLL.IN, .revents = 0 }};
            if (linux.poll(&pfd, 1, 500) <= 0) continue;
            const r = linux.read(fd, &buf, buf.len);
            if (r <= 0) continue;
            const pkt = buf[0..@intCast(r)];
            // RA 包（type 134）直接整包解码 —— 这是被动验证 RDNSS 的正道：
            // 不必发 RS 去打扰网络，等路由器周期性 RA 即可。
            if (pkt.len > 0 and pkt[0] == 134) {
                out("  [RA] 完整解码：\n", .{});
                printRA(pkt);
            }
            // raw ICMPv6 socket 在 Linux 上只交 ICMP 体（不含 IPv6 头），
            // 所以这里拿不到源地址 —— 只报长度，源地址靠 type 判断即可。
            out("  len={d}\n", .{pkt.len});
        }
        linux.exit(0);
    }

    if (std.mem.eql(u8, mode, "ra")) {
        const fd = openIcmp();
        join(fd, AllNodes, ifindex);
        // RS：type 133 code 0 cksum 0（内核填）+ 4 字节保留，未指定源、无选项
        const rs = [_]u8{ 133, 0, 0, 0, 0, 0, 0, 0 };
        sendRaw(fd, &rs, AllRouters, ifindex);
        out("等待 RA（15s）...\n", .{});
        recvLoop(fd, 15, printRA);
    } else if (std.mem.eql(u8, mode, "na")) {
        // SOLICIT + IA_NA + RapidCommit —— 触发一次真实的 IA_NA 分配
        const fd: i32 = @intCast(linux.socket(linux.AF.INET6, linux.SOCK.DGRAM, linux.IPPROTO.UDP));
        var sa: linux.sockaddr.in6 = .{
            .family = linux.AF.INET6,
            .port = std.mem.nativeToBig(u16, 546),
            .flowinfo = 0,
            .addr = [_]u8{0} ** 16,
            .scope_id = 0,
        };
        if (linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6)) != 0) die("bind 546 失败", .{});
        var pkt: [128]u8 = undefined;
        var off: usize = 0;
        pkt[off] = 1; // SOLICIT
        off += 1;
        pkt[off] = 0xAA;
        pkt[off + 1] = 0x55;
        pkt[off + 2] = 0x01;
        off += 3;
        // client-id (DUID-LL)
        std.mem.writeInt(u16, pkt[off..][0..2], 1, .big);
        std.mem.writeInt(u16, pkt[off + 2 ..][0..2], 10, .big);
        off += 4;
        const duid = [_]u8{ 0, 3, 0, 1 } ++ mac;
        @memcpy(pkt[off..][0..10], &duid);
        off += 10;
        // IA_NA：iaid + T1=0 + T2=0
        std.mem.writeInt(u16, pkt[off..][0..2], 3, .big);
        std.mem.writeInt(u16, pkt[off + 2 ..][0..2], 12, .big);
        off += 4;
        std.mem.writeInt(u32, pkt[off..][0..4], 0x1111, .big); // IAID
        std.mem.writeInt(u32, pkt[off + 4 ..][0..4], 0, .big);
        std.mem.writeInt(u32, pkt[off + 8 ..][0..4], 0, .big);
        off += 12;
        // rapid commit
        std.mem.writeInt(u16, pkt[off..][0..2], 14, .big);
        std.mem.writeInt(u16, pkt[off + 2 ..][0..2], 0, .big);
        off += 4;
        var dsa: linux.sockaddr.in6 = .{
            .family = linux.AF.INET6,
            .port = std.mem.nativeToBig(u16, 547),
            .flowinfo = 0,
            .addr = AllDhcp,
            .scope_id = ifindex,
        };
        const rc = linux.sendto(fd, pkt[0..off].ptr, off, 0, @ptrCast(&dsa), @sizeOf(linux.sockaddr.in6));
        if (rc < 0) die("SOLICIT sendto 失败", .{});
        out("已发 SOLICIT+IA_NA（{d} 字节），等 REPLY（5s）...\n", .{off});
        recvLoop(fd, 5, printDH6);
    } else if (std.mem.eql(u8, mode, "dh6")) {
        const fd: i32 = @intCast(linux.socket(linux.AF.INET6, linux.SOCK.DGRAM, linux.IPPROTO.UDP));
        if (fd < 0) die("UDPv6 socket 失败", .{});
        // 绑 ::546
        var sa: linux.sockaddr.in6 = .{
            .family = linux.AF.INET6,
            .port = std.mem.nativeToBig(u16, 546),
            .flowinfo = 0,
            .addr = [_]u8{0} ** 16,
            .scope_id = 0,
        };
        if (linux.bind(fd, @ptrCast(&sa), @sizeOf(linux.sockaddr.in6)) != 0) die("bind 546 失败", .{});
        // INFORMATION-REQUEST + client-id(DUID-LL) + ORO(23,24)
        var pkt: [64]u8 = undefined;
        var off: usize = 0;
        pkt[off] = 11; // INFORMATION-REQUEST
        off += 1;
        pkt[off] = 0x5A;
        pkt[off + 1] = 0xA5;
        pkt[off + 2] = 0x01;
        off += 3;
        // client-id
        std.mem.writeInt(u16, pkt[off..][0..2], 1, .big);
        std.mem.writeInt(u16, pkt[off + 2 ..][0..2], 10, .big);
        off += 4;
        const duid = [_]u8{ 0, 3, 0, 1 } ++ mac;
        @memcpy(pkt[off..][0..10], &duid);
        off += 10;
        // ORO = [23, 24]
        std.mem.writeInt(u16, pkt[off..][0..2], 6, .big);
        std.mem.writeInt(u16, pkt[off + 2 ..][0..2], 4, .big);
        off += 4;
        std.mem.writeInt(u16, pkt[off..][0..2], 23, .big);
        std.mem.writeInt(u16, pkt[off + 2 ..][0..2], 24, .big);
        off += 4;
        var dsa: linux.sockaddr.in6 = .{
            .family = linux.AF.INET6,
            .port = std.mem.nativeToBig(u16, 547),
            .flowinfo = 0,
            .addr = AllDhcp,
            .scope_id = ifindex,
        };
        const rc = linux.sendto(fd, pkt[0..off].ptr, off, 0, @ptrCast(&dsa), @sizeOf(linux.sockaddr.in6));
        if (rc < 0) die("DHCPv6 sendto 失败", .{});
        out("已发 INFORMATION-REQUEST（{d} 字节），等 REPLY（5s）...\n", .{off});
        recvLoop(@intCast(fd), 5, printDH6);
    } else {
        die("用法: rs_probe [ra|dh6] [ifname]", .{});
    }
    _ = &seq;
}
