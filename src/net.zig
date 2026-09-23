// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! net.zig — 对应 C 源码 network.c 的 socket 基础部分
//!
//! 说明：Zig 0.16 的 std.Io.net 提供了较高层的 UDP/TCP 封装，但 dnsmasq 需要
//! IP_PKTINFO、SO_REUSEADDR、随机源端口等底层能力，因此这里直接使用
//! std.posix.system（Linux 原始系统调用）实现，与 C 版本一一对应。
//!
//! 未移植部分（见 README 的进度表）：
//!   * enumerate_interfaces / iface_check：接口枚举与过滤（依赖 netlink.c）
//!   * IP_PKTINFO 源地址选择：目前依赖内核路由选择源地址
//!   * multicast / TFTP / DBus / ipset / nftset / conntrack

const std = @import("std");
const builtin = @import("builtin");
const addr = @import("addr.zig");

const posix = std.posix;
const system = posix.system;

pub const fd_t = posix.fd_t;
pub const SockAddr = addr.SockAddr;

/// 把原始系统调用返回值转为 errno
pub inline fn errno(rc: usize) system.E {
    return posix.errno(rc);
}

pub const NetError = error{
    AddressInUse,
    AddressNotAvailable,
    BadFileDescriptor,
    AccessDenied,
    TooManyOpenFiles,
    NoBufferSpace,
    NotSupported,
    InvalidArgument,
    Unexpected,
    WouldBlock,
    Interrupted,
    MessageTooBig,
    ConnectionRefused,
};

/// 对应 network.c: make_sock() 的第一步
pub fn socketCreate(family: u16, sock_type: u32, protocol: u32) NetError!fd_t {
    const rc = system.socket(family, sock_type | system.SOCK.CLOEXEC, protocol);
    switch (errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .AFNOSUPPORT => return error.NotSupported,
        .MFILE => return error.TooManyOpenFiles,
        .NFILE => return error.TooManyOpenFiles,
        .NOBUFS, .NOMEM => return error.NoBufferSpace,
        .ACCES => return error.AccessDenied,
        .INVAL => return error.InvalidArgument,
        else => return error.Unexpected,
    }
}

pub fn close(fd: fd_t) void {
    _ = system.close(fd);
}

/// 对应 network.c 中设置 SO_REUSEADDR/非阻塞
/// 设为非阻塞（对应 fcntl(F_SETFL, O_NONBLOCK)）
pub fn setNonBlock(fd: fd_t) NetError!void {
    const rc = system.fcntl(fd, system.F.GETFL, 0);
    if (errno(rc) != .SUCCESS) return error.Unexpected;
    const cur: u32 = @truncate(@as(usize, rc));
    // O 是 packed struct，O_NONBLOCK 对应其中的 NONBLOCK 位
    const nonblock: u32 = @bitCast(system.O{ .NONBLOCK = true });
    const rc2 = system.fcntl(fd, system.F.SETFL, @as(usize, cur | nonblock));
    if (errno(rc2) != .SUCCESS) return error.Unexpected;
}

pub fn setReuseAddr(fd: fd_t) NetError!void {
    const one: c_int = 1;
    const bytes = std.mem.toBytes(one);
    const rc = system.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &bytes, @sizeOf(c_int));
    if (errno(rc) != .SUCCESS) return error.Unexpected;
}

// ---------------------------------------------------------------------------
// netlink 事件订阅：用来「等接口就绪」，而不是靠定时轮询硬碰
// ---------------------------------------------------------------------------
/// netlink 多播组（按 `sockaddr.nl.groups` 的位掩码使用）。
/// 只列本项目用得到的几个。
pub const RTNLGRP_LINK: u32 = 0x1; // 接口 up/down、增删、改名、MTU 变化
pub const RTNLGRP_NEIGH: u32 = 0x4;
pub const RTNLGRP_IPV4_IFADDR: u32 = 0x10;
pub const RTNLGRP_IPV4_ROUTE: u32 = 0x40;
pub const RTNLGRP_IPV6_IFADDR: u32 = 0x100;
pub const RTNLGRP_IPV6_ROUTE: u32 = 0x400;

/// 打开一个接收内核 netlink 事件的 socket，并订阅给定的多播组。
///
/// socket 设为**非阻塞**：事件是突发式的，读取必须能在主循环里一次排干，
/// 绝不能阻塞住转发/应答路径。
///
/// 失败返回 -1，调用方应退化为定时轮询而不是放弃启动。
pub fn openRtnlEventSocket(groups: u32, who: []const u8) fd_t {
    const log = @import("log.zig");
    const fd = socketCreate(posix.AF.NETLINK, system.SOCK.RAW | system.SOCK.NONBLOCK, 0) catch |e| {
        log.warning("{s}：netlink 事件 socket 建立失败（{s}），退化为定时轮询", .{ who, @errorName(e) });
        return -1;
    };
    var sa = system.sockaddr.nl{ .pid = 0, .groups = groups };
    const rc = system.bind(fd, @ptrCast(&sa), @sizeOf(system.sockaddr.nl));
    if (errno(rc) != .SUCCESS) {
        log.warning("{s}：netlink 事件 bind 失败，退化为定时轮询", .{who});
        close(fd);
        return -1;
    }
    return fd;
}

/// 排干 netlink 事件。返回是否收到了**接口（LINK）**事件。
///
/// 只关心「有没有」，不逐个解析 —— 真正的处理在调用方的 tick 里合并做
/// （一次 up 会连带好几个事件，逐个处理只会白干几遍）。
pub fn drainRtnlEvents(fd: fd_t) RtnlBatch {
    var out = RtnlBatch{};
    var buf: [65536]u8 = undefined;
    while (true) {
        const n = recv(fd, &buf, std.posix.MSG.DONTWAIT) catch |e| switch (e) {
            error.WouldBlock => return out,
            else => return out,
        };
        if (n == 0) return out;
        // NLMSG_DONE 是 3；NLMSG_ERROR 是 2（这里不细究，交给调用方按标记去重处理）
        var off: usize = 0;
        while (off + 16 <= n) {
            const mlen: usize = std.mem.readInt(u32, buf[off..][0..4], .little);
            const mtype = std.mem.readInt(u16, buf[off + 4 ..][0..2], .little);
            if (mlen < 16 or off + mlen > n) break;
            if (mtype == RTM_NEWLINK or mtype == RTM_DELLINK) out.link = true;
            if (mtype == RTM_NEWADDR or mtype == RTM_DELADDR) out.addr = true;
            if (mtype == RTM_NEWROUTE or mtype == RTM_DELROUTE) out.route = true;
            off += (mlen + 3) & ~@as(usize, 3);
        }
        if (@as(usize, @intCast(n)) < buf.len) return out;
    }
}

pub const RtnlBatch = struct {
    link: bool = false,
    addr: bool = false,
    route: bool = false,
};

// RTM_NEWLINK / RTM_NEWADDR 在文件后段的 netlink dump 里已有定义，直接复用；
// 这里只补上还没有的几个报文类型。
pub const RTM_DELLINK: u16 = 17;
pub const RTM_DELADDR: u16 = 21;
pub const RTM_NEWROUTE: u16 = 24;
pub const RTM_DELROUTE: u16 = 25;

/// 设置 SO_REUSEPORT：多线程模型里每个线程各自 bind 同一个端口，避免惊群
pub fn setReusePort(fd: fd_t) NetError!void {
    const one: c_int = 1;
    const bytes = std.mem.toBytes(one);
    const rc = system.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEPORT, &bytes, @sizeOf(c_int));
    if (errno(rc) != .SUCCESS) return error.Unexpected;
}

/// IPv6 只监听 v6（对应 network.c: 避免 v4-mapped 重复）
pub fn setIpv6Only(fd: fd_t) NetError!void {
    const one: c_int = 1;
    const bytes = std.mem.toBytes(one);
    const rc = system.setsockopt(fd, posix.IPPROTO.IPV6, posix.IPV6.V6ONLY, &bytes, @sizeOf(c_int));
    if (errno(rc) != .SUCCESS) return error.Unexpected;
}

pub fn setBroadcast(fd: fd_t) void {
    const one: c_int = 1;
    const bytes = std.mem.toBytes(one);
    _ = system.setsockopt(fd, posix.SOL.SOCKET, posix.SO.BROADCAST, &bytes, @sizeOf(c_int));
}

/// 监听套接字接收缓冲的目标大小。
///
/// 内核默认值（net.core.rmem_max，很多路由器上只有 208 KiB）在突发流量下
/// 会溢出丢包 —— 实机压测里 /proc/net/snmp 的 Udp.RcvbufErrors 持续增长，
/// 丢掉的查询客户端只能超时重传，等于白白浪费一次往返。
/// 本移植是「主线程收包 + 工作线程处理」的队列模型，收包与处理之间有一段
/// 延迟，比 C 版的单线程直处理更需要缓冲来吸收突发。
pub const RECV_BUF_BYTES: c_int = 1 << 20; // 1 MiB

/// 增大套接字接收缓冲区。
///
/// 优先用 SO_RCVBUFFORCE：它允许持有 CAP_NET_ADMIN 的进程突破
/// net.core.rmem_max 的限制（普通 SO_RCVBUF 会被内核截到 rmem_max，
/// 而默认值本来就已经是 rmem_max，设了等于没设）。失败则退回 SO_RCVBUF。
pub fn setRecvBuf(fd: fd_t, size: c_int) void {
    const bytes = std.mem.toBytes(size);

    if (builtin.os.tag == .linux) {
        // SO_RCVBUFFORCE 没有出现在 std.posix.SO 中，Linux 上恒为 32
        const SO_RCVBUFFORCE: u32 = 32;
        if (errno(system.setsockopt(fd, posix.SOL.SOCKET, SO_RCVBUFFORCE, &bytes, @sizeOf(c_int))) == .SUCCESS)
            return;
    }

    _ = system.setsockopt(fd, posix.SOL.SOCKET, posix.SO.RCVBUF, &bytes, @sizeOf(c_int));
}

pub fn bind(fd: fd_t, sa: *const SockAddr) NetError!void {
    const rc = system.bind(fd, sa.ptr(), sa.len);
    switch (errno(rc)) {
        .SUCCESS => return,
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .ACCES => return error.AccessDenied,
        .INVAL => return error.InvalidArgument,
        .AFNOSUPPORT => return error.NotSupported,
        else => return error.Unexpected,
    }
}

pub fn listen(fd: fd_t, backlog: u32) NetError!void {
    const rc = system.listen(fd, backlog);
    if (errno(rc) != .SUCCESS) return error.Unexpected;
}

pub fn accept(fd: fd_t) NetError!fd_t {
    const rc = system.accept4(fd, null, null, system.SOCK.CLOEXEC);
    switch (errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .AGAIN => return error.WouldBlock,
        .INTR => return error.Interrupted,
        .MFILE, .NFILE => return error.TooManyOpenFiles,
        .NOBUFS, .NOMEM => return error.NoBufferSpace,
        else => return error.Unexpected,
    }
}

pub fn recvfrom(fd: fd_t, buf: []u8, from: ?*SockAddr, flags: u32) NetError!usize {
    var sa: system.sockaddr.storage = undefined;
    var slen: system.socklen_t = @sizeOf(system.sockaddr.storage);
    const rc = system.recvfrom(fd, buf.ptr, buf.len, flags, @ptrCast(&sa), &slen);
    switch (errno(rc)) {
        .SUCCESS => {
            if (from) |f| {
                f.store = sa;
                f.len = slen;
            }
            return rc;
        },
        .AGAIN => return error.WouldBlock,
        .INTR => return error.Interrupted,
        .CONNREFUSED => return error.ConnectionRefused,
        .MSGSIZE => return error.MessageTooBig,
        .BADF => return error.BadFileDescriptor,
        else => return error.Unexpected,
    }
}

/// `to` 为 null 时表示 socket 已 connect，走 sendto(NULL) 语义
pub fn sendto(fd: fd_t, buf: []const u8, to: ?*const SockAddr, flags: u32) NetError!usize {
    const rc = if (to) |t|
        system.sendto(fd, buf.ptr, buf.len, flags, t.ptr(), t.len)
    else
        system.sendto(fd, buf.ptr, buf.len, flags, null, 0);
    switch (errno(rc)) {
        .SUCCESS => return rc,
        .AGAIN => return error.WouldBlock,
        .INTR => return error.Interrupted,
        .CONNREFUSED => return error.ConnectionRefused,
        .MSGSIZE => return error.MessageTooBig,
        .ACCES => return error.AccessDenied,
        .BADF => return error.BadFileDescriptor,
        else => return error.Unexpected,
    }
}

pub fn recv(fd: fd_t, buf: []u8, flags: u32) NetError!usize {
    const rc = system.recvfrom(fd, buf.ptr, buf.len, flags, null, null);
    switch (errno(rc)) {
        .SUCCESS => return rc,
        .AGAIN => return error.WouldBlock,
        .INTR => return error.Interrupted,
        .BADF => return error.BadFileDescriptor,
        else => return error.Unexpected,
    }
}

/// 完整写出一段数据（TCP 用，对应 util.c: read_write）
pub fn writeAll(fd: fd_t, buf: []const u8) NetError!void {
    var off: usize = 0;
    while (off < buf.len) {
        const rc = system.sendto(fd, buf.ptr + off, buf.len - off, system.MSG.NOSIGNAL, null, 0);
        switch (errno(rc)) {
            .SUCCESS => {
                if (rc == 0) return error.Unexpected;
                off += rc;
            },
            .INTR => continue,
            .AGAIN => {
                waitWritable(fd) catch return error.WouldBlock;
            },
            .CONNREFUSED, .CONNRESET => return error.ConnectionRefused,
            else => return error.Unexpected,
        }
    }
}

pub fn connect(fd: fd_t, sa: *const SockAddr) NetError!void {
    const rc = system.connect(fd, sa.ptr(), sa.len);
    switch (errno(rc)) {
        .SUCCESS => return,
        .INPROGRESS => return error.WouldBlock,
        .CONNREFUSED => return error.ConnectionRefused,
        .ACCES => return error.AccessDenied,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        else => return error.Unexpected,
    }
}

/// 对应 poll.c: poll_check / network.c 的事件循环单步
pub fn poll(fds: []posix.pollfd, timeout_ms: i32) NetError!usize {
    if (fds.len == 0) return 0;
    const rc = system.poll(fds.ptr, @intCast(fds.len), timeout_ms);
    switch (errno(rc)) {
        .SUCCESS => return rc,
        .INTR => return error.Interrupted,
        else => return error.Unexpected,
    }
}

fn waitWritable(fd: fd_t) NetError!void {
    var fds = [_]posix.pollfd{.{ .fd = fd, .events = posix.POLL.OUT, .revents = 0 }};
    _ = try poll(&fds, 1000);
}

/// 生成随机源端口（对应 forward.c: random_sock / randport）
pub fn randomPort() u16 {
    const util = @import("util.zig");
    // 避开 0 与特权端口，范围与 dnsmasq 的 min_port/max_port 默认值一致
    return 1024 + @as(u16, @truncate(util.rand32() % 64000));
}

/// 便捷：构造通配地址
pub fn anyAddr(family_enum: addr.Af, port_num: u16) SockAddr {
    return switch (family_enum) {
        .ip4 => SockAddr.fromIp4(addr.ANY_IP4, port_num),
        .ip6 => SockAddr.fromIp6(addr.ANY_IP6, port_num, 0),
    };
}

// ---------------------------------------------------------------------------
// 接口枚举（对应 network.c: enumerate_interfaces / iface_check）
//
// 为什么必须有：`--interface=br-lan` 在 dnsmasq 里的语义是「只在这个网卡上
// 提供服务」。没有这套枚举时，`interface=` 会被完整忽略、退化成绑定通配地址
// 0.0.0.0 —— 装在路由器上就等于把递归解析器暴露到 WAN，是实打实的安全问题
// （实机 192.168.0.1 上验出来：日志里明写 "开始监听 0.0.0.0#5354"）。
//
// 实现取舍：
//   * 「网卡名 -> 索引」走 netlink RTM_GETLINK 一次性 dump，**不读 /sys**。
//     这一点很关键：procd 的 ujail 沙箱默认只挂载白名单文件，除非显式加
//     `-s` 否则沙箱里根本看不到 /sys；而原版 C 的 iface_enumerate() 全程用
//     netlink 从不碰 /sys，所以它在沙箱里安然无恙。早期版本图省事读了
//     /sys/class/net/<name>/ifindex，结果一装到路由器的 ujail 里就退化成
//     「只监听回环」——表现为「服务起得来，但客户端一律解析失败」。
//   * 「索引/地址」用 netlink RTM_GETADDR 一次性 dump，纯系统调用、不需要
//     链接 libc（本移植是静态 musl，用不了 getifaddrs）。
//   * 两个 dump 失败时才兜底读 /sys，保证在 netlink 被策略禁掉的环境下不会
//     比改造前更差。
// ---------------------------------------------------------------------------

/// 恒为 ::1 的回环地址
pub const LOOPBACK_IP6: [16]u8 = [_]u8{0} ** 15 ++ [_]u8{1};

/// 一条接口地址。`ifindex` 用于按网卡名过滤；`sa` 的端口为 0。
pub const IfaceAddr = struct {
    ifindex: u32,
    sa: SockAddr,
    /// RTM_GETADDR 的 `ifaddrmsg.prefixlen`。IPv4 下就是掩码位数
    /// （DHCP 侧要由它还原 option 1，见 `ifaddr.zig`）。IPv6 无意义。
    prefixlen: u8 = 0,
    /// IFA_CACHEINFO 的 `ifa_prefered`（**剩余秒数**，不是绝对时刻）。
    /// 0 表示内核没给这个属性（IPv4 通常不给）或已过期；
    /// 0xFFFFFFFF 表示 forever。odhcpd 用它做 RDNSS 优选的打分项，
    /// 见 `odhcpd.c:odhcpd_get_interface_dns_addr6`。
    preferred: u32 = 0,
    /// IFA_CACHEINFO 的 `ifa_valid`（**剩余秒数**）。0 = 未提供或已失效。
    valid: u32 = 0,
};

pub fn ifaceIndex(name: []const u8) ?u32 {
    var pathbuf: [128]u8 = undefined;
    const path = std.fmt.bufPrint(&pathbuf, "/sys/class/net/{s}/ifindex", .{name}) catch return null;
    const fd = posix.openat(
        posix.AT.FDCWD,
        path,
        posix.O{ .ACCMODE = .RDONLY, .CLOEXEC = true },
        0,
    ) catch return null;
    defer _ = system.close(fd);

    var nbuf: [32]u8 = undefined;
    const n = posix.read(fd, &nbuf) catch return null;
    const s = std.mem.trim(u8, nbuf[0..n], " \t\r\n");
    return std.fmt.parseInt(u32, s, 10) catch null;
}

/// 把一组网卡名解析成 ifindex 集合，写入 `out`。解析不到的网卡名会打日志。
pub fn resolveIfaceIndexes(
    allocator: std.mem.Allocator,
    names: []const []const u8,
    out: *std.ArrayListUnmanaged(u32),
    what: []const u8,
) !void {
    // 先做一次 RTM_GETLINK dump。这里刻意不读 /sys：ujail 沙箱里通常看不到
    // /sys（要让 ujail 挂载它得显式传 -s，而 dnsmasq 的 init 脚本历来没传），
    // 一走 /sys 就会在真实路由器上把 --interface= 全部解析失败 —— 表现为
    // 「进程活着但客户端一律解析不了」。原版 C 不走 /sys，正是为此。
    var links: std.ArrayListUnmanaged(IfaceLink) = .empty;
    const via_netlink = blk: {
        listIfaceLinks(allocator, &links) catch break :blk false;
        break :blk true;
    };
    defer {
        for (links.items) |l| allocator.free(l.name);
        links.deinit(allocator);
    }

    const log = @import("log.zig");
    for (names) |nm| {
        if (via_netlink) {
            if (findIfaceLink(links.items, nm)) |idx| {
                try out.append(allocator, idx);
                continue;
            }
        }
        // netlink 不可用或没查到时兜底读 /sys，保证不比改造前更差
        if (ifaceIndex(nm)) |idx| {
            try out.append(allocator, idx);
        } else {
            log.warning("--{s}={s}：找不到该网卡（netlink 与 /sys 下均无此项），已忽略", .{ what, nm });
        }
    }
}

const NETLINK_ROUTE: u32 = 0;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const RTM_NEWADDR: u16 = 20;
const RTM_GETADDR: u16 = 22;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const IFLA_IFNAME: u16 = 3;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
/// `struct ifa_cacheinfo`：{ ifa_prefered, ifa_valid, cstamp, tstamp }，全 u32 LE。
/// 前两个是**剩余有效秒数**（0xFFFFFFFF = forever）—— 经 .1 实测确认：
/// 内核回传 176456，同时 `ip -6 addr` 显示 `valid_lft 176447sec`，两者同步递减，
/// 所以是相对量而非绝对墙钟。RDNSS 优选要用它。
/// （注意：上游 odhcpd 把它当绝对时刻与 now 比较（odhcpd.c:378），
/// 那是上游在这类内核上的一个隐患；本移植按剩余秒数的真实语义处理。）
const IFA_CACHEINFO: u16 = 6;

inline fn nlAlign(x: usize) usize {
    return (x + 3) & ~@as(usize, 3);
}

/// dump 出内核当前所有接口地址。调用方负责按 ifindex 过滤。
pub fn listIfaceAddrs(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(IfaceAddr),
) !void {
    const fd = try socketCreate(posix.AF.NETLINK, posix.SOCK.RAW, NETLINK_ROUTE);
    defer close(fd);

    // 请求 = nlmsghdr(16) + ifaddrmsg(8)，family 留 AF_UNSPEC 表示「全都要」
    var req = [_]u8{0} ** 24;
    std.mem.writeInt(u32, req[0..4], 24, .little); // nlmsg_len
    std.mem.writeInt(u16, req[4..6], RTM_GETADDR, .little);
    std.mem.writeInt(u16, req[6..8], NLM_F_REQUEST | NLM_F_DUMP, .little);
    std.mem.writeInt(u32, req[8..12], 1, .little); // nlmsg_seq
    _ = try sendto(fd, &req, null, 0);

    var buf: [32768]u8 = undefined;
    while (true) {
        const n = recv(fd, &buf, 0) catch |e| switch (e) {
            error.Interrupted => continue,
            else => return e,
        };
        if (n == 0) return;

        var off: usize = 0;
        while (off + 16 <= n) {
            const mlen: usize = std.mem.readInt(u32, buf[off..][0..4], .little);
            const mtype = std.mem.readInt(u16, buf[off + 4 ..][0..2], .little);
            if (mlen < 16 or off + mlen > n) return;

            switch (mtype) {
                NLMSG_DONE, NLMSG_ERROR => return,
                RTM_NEWADDR => try parseIfaddr(allocator, buf[off..][0..mlen], out),
                else => {},
            }
            off += nlAlign(mlen);
        }
    }
}

fn parseIfaddr(
    allocator: std.mem.Allocator,
    msg: []const u8,
    out: *std.ArrayListUnmanaged(IfaceAddr),
) !void {
    // nlmsghdr 16 + ifaddrmsg 的 family/prefixlen/flags/scope/index 共 8
    if (msg.len < 24) return;
    const family = msg[16];
    const prefixlen = msg[17];
    const ifindex = std.mem.readInt(u32, msg[20..24], .little);

    var a4: ?u32 = null; // IFA_ADDRESS（IPv4：对端/本端）
    var l4: ?u32 = null; // IFA_LOCAL（IPv4：本端，点对点场景下才是我们要的）
    var a6: ?[16]u8 = null;
    // IFA_CACHEINFO：优先/有效生命周期（绝对墙钟秒）。RDNSS 优选要用。
    var preferred: u32 = 0;
    var valid: u32 = 0;

    var off: usize = 24;
    while (off + 4 <= msg.len) {
        const alen: usize = std.mem.readInt(u16, msg[off..][0..2], .little);
        const atype = std.mem.readInt(u16, msg[off + 2 ..][0..2], .little);
        if (alen < 4 or off + alen > msg.len) break;
        const data = msg[off + 4 .. off + alen];

        if (family == posix.AF.INET and data.len >= 4) {
            const v = std.mem.readInt(u32, data[0..4], .little);
            if (atype == IFA_LOCAL) l4 = v;
            if (atype == IFA_ADDRESS) a4 = v;
        } else if (family == posix.AF.INET6 and data.len >= 16) {
            if (atype == IFA_ADDRESS) a6 = data[0..16].*;
        }
        if (atype == IFA_CACHEINFO and data.len >= 8) {
            preferred = std.mem.readInt(u32, data[0..4], .little);
            valid = std.mem.readInt(u32, data[4..8], .little);
        }
        off += nlAlign(alen);
    }

    // forever（0xFFFFFFFF）的语义是「永不过期」，由 pickRdnsAddr 特判；
    // 这里只做长度校验，不做归一化（0 保留原值 = 已过期/未提供）。
    if (family == posix.AF.INET) {
        // IPv4 优先用 IFA_LOCAL（本端地址）；没有就退回 IFA_ADDRESS
        const v = l4 orelse a4 orelse return;
        try out.append(allocator, .{
            .ifindex = ifindex,
            .sa = SockAddr.fromIp4(v, 0),
            .prefixlen = prefixlen,
            .preferred = preferred,
            .valid = valid,
        });
    } else if (family == posix.AF.INET6) {
        const v = a6 orelse return;
        // 链路本地地址必须带 scope_id（= ifindex），否则 bind 会 ADDRNOTAVAIL
        const scope: u32 = if (v[0] == 0xfe and (v[1] & 0xc0) == 0x80) ifindex else 0;
        try out.append(allocator, .{
            .ifindex = ifindex,
            .sa = SockAddr.fromIp6(v, 0, scope),
            .prefixlen = prefixlen,
            .preferred = preferred,
            .valid = valid,
        });
    }
}

/// 一条网卡链路记录。等价于原版 C 里 iface_enumerate() 回调给出的
/// (name, index) 二元组。`name` 由 listIfaceLinks 分配，调用方负责释放。
pub const IfaceLink = struct {
    name: []const u8,
    index: u32,
};

/// dump 出内核当前所有网卡的 (名字, ifindex)。
///
/// 对应原版 C 基于 RTM_GETLINK 的 iface_enumerate()。相比逐个读
/// `/sys/class/net/<name>/ifindex`，这样做有两个好处：
///   1. 一次系统调用拿全部网卡，不用按名字逐个 open/read；
///   2. **完全不依赖 /sys**。ujail 沙箱默认只挂载白名单文件，`/sys` 常常
///      不在其中（要让 ujail 挂 /sys 得显式传 `-s`，而 dnsmasq 的 init 脚本
///      历来没传）。早期实现走了 /sys，于是装到路由器上后 `--interface=`
///      全部解析失败，解析器退守回环 —— 现象是「进程活着、日志正常，
///      但所有客户端都解析不了」。
///
/// 调用方负责：先释放每条记录的 `name`，再 `deinit`。
pub fn listIfaceLinks(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(IfaceLink),
) !void {
    const fd = try socketCreate(posix.AF.NETLINK, posix.SOCK.RAW, NETLINK_ROUTE);
    defer close(fd);

    // 请求 = nlmsghdr(16) + ifinfomsg(16)，family 留 AF_UNSPEC 表示「全都要」
    var req = [_]u8{0} ** 32;
    std.mem.writeInt(u32, req[0..4], 32, .little); // nlmsg_len
    std.mem.writeInt(u16, req[4..6], RTM_GETLINK, .little);
    std.mem.writeInt(u16, req[6..8], NLM_F_REQUEST | NLM_F_DUMP, .little);
    std.mem.writeInt(u32, req[8..12], 1, .little); // nlmsg_seq
    _ = try sendto(fd, &req, null, 0);

    var buf: [32768]u8 = undefined;
    while (true) {
        const n = recv(fd, &buf, 0) catch |e| switch (e) {
            error.Interrupted => continue,
            else => return e,
        };
        if (n == 0) return;

        var off: usize = 0;
        while (off + 16 <= n) {
            const mlen: usize = std.mem.readInt(u32, buf[off..][0..4], .little);
            const mtype = std.mem.readInt(u16, buf[off + 4 ..][0..2], .little);
            if (mlen < 16 or off + mlen > n) return;

            switch (mtype) {
                NLMSG_DONE, NLMSG_ERROR => return,
                RTM_NEWLINK => try parseIflink(allocator, buf[off..][0..mlen], out),
                else => {},
            }
            off += nlAlign(mlen);
        }
    }
}

fn parseIflink(
    allocator: std.mem.Allocator,
    msg: []const u8,
    out: *std.ArrayListUnmanaged(IfaceLink),
) !void {
    // nlmsghdr(16) + ifinfomsg(16)；属性区从第 32 字节开始。
    // ifinfomsg 布局：family(1) pad(1) type(2) index(4) flags(4) change(4)
    if (msg.len < 32) return;
    const ifindex = std.mem.readInt(u32, msg[20..24], .little);

    var off: usize = 32;
    while (off + 4 <= msg.len) {
        const alen: usize = std.mem.readInt(u16, msg[off..][0..2], .little);
        const atype = std.mem.readInt(u16, msg[off + 2 ..][0..2], .little);
        if (alen < 4 or off + alen > msg.len) break;

        if (atype == IFLA_IFNAME) {
            const data = msg[off + 4 .. off + alen];
            // 内核给的是 NUL 结尾的字符串，去掉尾部的 \0
            const raw = if (data.len > 0 and data[data.len - 1] == 0)
                data[0 .. data.len - 1]
            else
                data;
            const owned = try allocator.dupe(u8, raw);
            try out.append(allocator, .{ .name = owned, .index = ifindex });
            return;
        }
        off += nlAlign(alen);
    }
}

/// 在 listIfaceLinks 的结果里按网卡名查 ifindex
pub fn findIfaceLink(links: []const IfaceLink, name: []const u8) ?u32 {
    for (links) |l| {
        if (std.mem.eql(u8, l.name, name)) return l.index;
    }
    return null;
}

test "ifaceIndex 与 listIfaceAddrs 至少能看到本机回环" {
    const t = std.testing;
    const allocator = t.allocator;

    // lo 在任何 Linux 上都必须存在
    try t.expect(ifaceIndex("lo") != null);
    try t.expect(ifaceIndex("这个网卡名肯定不存在") == null);

    var list: std.ArrayListUnmanaged(IfaceAddr) = .empty;
    defer list.deinit(allocator);
    try listIfaceAddrs(allocator, &list);

    const lo_idx = ifaceIndex("lo").?;
    var saw_loopback = false;
    for (list.items) |it| {
        if (it.ifindex == lo_idx) {
            const p = it.sa.port();
            _ = p;
            saw_loopback = true;
        }
    }
    try t.expect(saw_loopback);
}

test "listIfaceLinks 不依赖 /sys 即可枚举网卡" {
    const t = std.testing;
    const allocator = t.allocator;

    var links: std.ArrayListUnmanaged(IfaceLink) = .empty;
    defer {
        for (links.items) |l| allocator.free(l.name);
        links.deinit(allocator);
    }
    try listIfaceLinks(allocator, &links);

    // 至少要能枚举到回环，且名字与 /sys 读到的索引一致
    try t.expect(links.items.len > 0);
    try t.expectEqual(ifaceIndex("lo").?, findIfaceLink(links.items, "lo").?);
    try t.expect(findIfaceLink(links.items, "这个网卡名肯定不存在") == null);

    // 每条记录都应解析出了非空名字
    for (links.items) |l| {
        try t.expect(l.name.len > 0);
    }
}

test "socket create/bind/send/recv loopback" {
    var a = SockAddr.fromIp4(addr.LOOPBACK_IP4, 0);
    const fd = try socketCreate(posix.AF.INET, posix.SOCK.DGRAM, posix.IPPROTO.UDP);
    defer close(fd);
    try setReuseAddr(fd);
    try bind(fd, &a);

    // 取回内核分配的端口
    var slen: system.socklen_t = @sizeOf(system.sockaddr.storage);
    const rc = system.getsockname(fd, a.mutPtr(), &slen);
    try std.testing.expectEqual(system.E.SUCCESS, errno(rc));
    a.len = slen;

    const payload = "hello dns";
    try std.testing.expectEqual(payload.len, try sendto(fd, payload, &a, 0));

    var buf: [64]u8 = undefined;
    var from: SockAddr = undefined;
    const n = try recvfrom(fd, &buf, &from, 0);
    try std.testing.expectEqualStrings(payload, buf[0..n]);
    try std.testing.expectEqual(a.port(), from.port());
}

// ---------------------------------------------------------------------------
// 接口状态查询 + IPv6 发送（对齐上游 odhcpd.c:245-285 的发送语义）
// ---------------------------------------------------------------------------

/// linux/if.h 的 IFF_RUNNING：接口处于可工作状态（对网桥而言 =
/// 至少一个端口进入 forwarding）。**冷启动问题的核心信号**：
/// br-lan 在 STP listening 阶段它未置位，直到端口 forwarding 才有。
pub const IFF_UP: u16 = 0x1;
pub const IFF_RUNNING: u16 = 0x40;

/// SIOCGIFFLAGS（linux/sockios.h）
pub const SIOCGIFFLAGS: u32 = 0x8913;

/// 读网卡 flags。`ctl_fd` 是任意 socket（上游用一个 AF_INET/DGRAM 常驻
/// ioctl_sock；我们的 DHCP socket 就满足）。失败返回 null。
pub fn getIfFlags(ctl_fd: fd_t, name: []const u8) ?u16 {
    if (ctl_fd < 0) return null;
    // struct ifreq：前 16 字节是 ifr_name，紧随其后的 short 是 ifr_flags
    var req = [_]u8{0} ** 40;
    const n = @min(name.len, 15);
    @memcpy(req[0..n], name[0..n]);
    const rc = system.ioctl(ctl_fd, SIOCGIFFLAGS, @intFromPtr(&req));
    if (errno(rc) != .SUCCESS) return null;
    return @bitCast(std.mem.readInt(i16, req[16..18], .little));
}

/// IPv6 发送结果：成功带字节数，失败带 **errno 名**。
///
/// 之前用 `@errorName` 且 else 兜底成 Unexpected，冷启动时 RA 发送失败
/// 只能看到一句「Unexpected」，根因（ENETUNREACH/EADDRNOTAVAIL，因为
/// br-lan 还在 STP listening、IPv6 栈未就绪）完全看不出来。
pub const Send6Result = union(enum) {
    sent: usize,
    failed: [:0]const u8,
};

/// IPv6 发送：`IPV6_PKTINFO` 指定出口接口 + `MSG_DONTWAIT`（非阻塞）。
///
/// 与上游 `odhcpd_send_with_src()`（odhcpd.c:245-285）对齐：
///   * 用 cmsg 的 `ipi6_ifindex` 指定出口接口，而不是只靠 sin6_scope_id；
///   * 非阻塞 —— 事件循环里绝不能被发送卡住；
///   * 失败时保留 errno 名。
pub fn sendMsg6(fd: fd_t, dest: *const SockAddr, data: []const u8, ifindex: u32) Send6Result {
    const In6Pktinfo = extern struct { addr: [16]u8, ifindex: u32 };
    // NLMSG/CMSG 对齐（内核要求 cmsg 长度按 8/机器字对齐）
    const cmsgAlign = struct {
        fn f(n: usize) usize {
            return (n + 3) & ~@as(usize, 3);
        }
    }.f;

    var iov = [1]posix.iovec_const{.{ .base = data.ptr, .len = data.len }};
    var control: [80]u8 align(@alignOf(usize)) = [_]u8{0} ** 80;
    var msg = system.msghdr_const{
        .name = @ptrCast(&dest.store),
        .namelen = dest.len,
        .iov = &iov,
        .iovlen = 1,
        .control = null,
        .controllen = 0,
        .flags = 0,
    };
    if (ifindex != 0) {
        const c: *system.cmsghdr = @ptrCast(@alignCast(&control));
        c.level = posix.IPPROTO.IPV6;
        c.type = system.IPV6.PKTINFO;
        c.len = cmsgAlign(@sizeOf(system.cmsghdr)) + @sizeOf(In6Pktinfo);
        const pi: *In6Pktinfo = @ptrCast(@alignCast(&control[cmsgAlign(@sizeOf(system.cmsghdr))]));
        pi.* = .{ .addr = [_]u8{0} ** 16, .ifindex = ifindex };
        msg.control = &control;
        msg.controllen = c.len;
    }

    const rc = system.sendmsg(fd, &msg, system.MSG.DONTWAIT);
    if (errno(rc) == .SUCCESS) return .{ .sent = @intCast(rc) };
    return .{ .failed = @tagName(errno(rc)) };
}
