// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! server.zig — 监听、线程池与查询处理
//!
//! 对应 C 源码：
//!   * src/network.c  —— create_listeners() / enumerate_interfaces() 的 socket 部分
//!   * src/dnsmasq.c  —— main() 的事件循环（poll + 超时任务 + 信号）
//!   * src/forward.c  —— receive_query()（UDP 侧）与 tcp_request()（TCP 侧）
//!
//! ## 与 C 版本的设计差异（重要）
//!
//! C 版是单线程 poll 循环，UDP / TCP / 上游应答全部在一个线程里处理。
//! 本移植按需求改成 **fixed-size 线程池 + 同步阻塞查询**：
//!
//!   * 主线程只做 poll（UDP 监听 fd + TCP 监听 fd + 信号自管道），
//!     收到报文后把「一个查询」打包成 Job 丢进队列就回去 poll；
//!   * 工作线程从队列取 Job，同步完成「本地应答 or 上游转发」后直接回包；
//!   * UDP 回包用 `sendto` 在监听 fd 上直接发（同一 fd 多线程 sendto 是安全的），
//!     因此只有 TCP 连接是有状态的、需要整个连接交给一个线程处理。
//!
//! 这样把 C 版里最重的部分（上游等待）并行化了，多核上吞吐随线程数线性提升，
//! 同时保留了 dnsmasq 的全部可观察行为（同一报文格式、同一日志、同一缓存语义）。

const std = @import("std");
const protocol = @import("protocol.zig");
const addr = @import("addr.zig");
const name = @import("name.zig");
const net = @import("net.zig");
const util = @import("util.zig");
const log = @import("log.zig");
const daemon_mod = @import("daemon.zig");
const rfc1035 = @import("rfc1035.zig");
const forward = @import("forward.zig");
const fwdengine = @import("fwdengine.zig");
const hosts = @import("hosts.zig");
const resolv = @import("resolv.zig");
const domain = @import("domain.zig");

const Daemon = daemon_mod.Daemon;
const Server = daemon_mod.Server;
const SockAddr = addr.SockAddr;

/// UDP 侧单个报文的缓冲上限（对应 daemon->packet_buff_sz 的用法）
pub const UDP_PACKET_MAX: usize = 4096;
/// TCP 侧单个报文的缓冲上限（DNS over TCP 的长度字段是 16 位）
pub const TCP_PACKET_MAX: usize = 65535;
/// 一条 TCP 连接上最多处理多少个查询（对应 config.h: TCP_MAX_QUERIES）
pub const TCP_MAX_QUERIES: usize = 100;

// ---------------------------------------------------------------------------
// TCP 连接
// ---------------------------------------------------------------------------
/// 一条已接受的 TCP 连接。对应 C 版里 fork/线程处理的 confd。
pub const TcpConn = struct {
    fd: net.fd_t,
    client: SockAddr,
    /// 已处理的查询数（对应 C 版 tcp_request 的循环计数）
    queries: usize = 0,
};

// ---------------------------------------------------------------------------
// 任务队列
// ---------------------------------------------------------------------------
pub const Job = union(enum) {
    /// UDP 查询：报文 + 客户端 + 回包用的监听 fd
    udp: struct {
        packet: []u8,
        len: usize,
        client: SockAddr,
        reply_fd: net.fd_t,
        /// 查询到达的本地 IPv4 地址 / 掩码（见 daemon.Listener.local4）。
        /// 对应 IP_PKTINFO 的 ipi_addr + 目的接口掩码。
        local4: u32 = 0,
        netmask4: u32 = 0,
    },
    /// 整条 TCP 连接（worker 负责读循环、回包与收尾关闭）
    tcp: *TcpConn,
    /// 退出哨兵（对应 shutdown 时给每个 worker 一个）
    stop,
};

/// 线程池 + 队列。对应 C 版「主循环 + 在途查询表」的组合。
pub const Pool = struct {
    allocator: std.mem.Allocator = std.heap.page_allocator,
    io: std.Io = undefined,

    mutex: std.Io.Mutex = .init,
    /// 队列非空信号（对应 poll 唤醒）
    sem: std.Io.Semaphore = .{},
    queue: std.ArrayListUnmanaged(Job) = .empty,
    /// 队首下标。取任务用 `items[head]` 后 head += 1，
    /// 而不是 orderedRemove(0) —— 后者每取一个任务都要把后面所有元素前移，
    /// 队列一长就是 O(n²) 的内存搬运（压测热缓存路径上是主要开销之一）。
    queue_head: usize = 0,

    /// UDP 报文缓冲池：4KB 缓冲的分配/释放比报文本身处理还贵，
    /// 回收复用后热路径上几乎没有 alloc/free。
    /// 独立于队列锁，避免与入队/出队互相争抢。
    pkt_mutex: std.Io.Mutex = .init,
    pkt_pool: std.ArrayListUnmanaged([]u8) = .empty,
    pkt_pool_cap: usize = 1024,

    threads: std.ArrayListUnmanaged(std.Thread) = .empty,
    /// 当前在途（已入队未完成）的查询数，用于 --dns-forward-max 限流
    inflight: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    shutdown: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

/// 单次 poll 唤醒最多从同一 socket 收走的报文数。
/// 一次 poll 只取一个报文时，每个报文都要付一次 poll 系统调用，
/// 这里是热缓存吞吐最大的瓶颈。
pub const UDP_BATCH_MAX: usize = 64;

pub var pool: Pool = .{};

/// 取一个 UDP 报文缓冲：优先从池里拿，池空则新建
fn pktGet(alloc: std.mem.Allocator) ?[]u8 {
    pool.pkt_mutex.lockUncancelable(pool.io);
    const cached = pool.pkt_pool.pop();
    pool.pkt_mutex.unlock(pool.io);
    if (cached) |b| return b;
    return alloc.alloc(u8, UDP_PACKET_MAX) catch null;
}

/// 归还 UDP 报文缓冲
fn pktPut(alloc: std.mem.Allocator, buf: []u8) void {
    if (buf.len != UDP_PACKET_MAX) {
        alloc.free(buf);
        return;
    }
    pool.pkt_mutex.lockUncancelable(pool.io);
    if (pool.pkt_pool.items.len >= pool.pkt_pool_cap) {
        pool.pkt_mutex.unlock(pool.io);
        alloc.free(buf);
        return;
    }
    pool.pkt_pool.append(alloc, buf) catch {
        pool.pkt_mutex.unlock(pool.io);
        alloc.free(buf);
        return;
    };
    pool.pkt_mutex.unlock(pool.io);
}

fn queuePush(job: Job) void {
    pool.mutex.lockUncancelable(pool.io);
    pool.queue.append(pool.allocator, job) catch {
        pool.mutex.unlock(pool.io);
        // 入队失败：直接把报文丢掉（对应 C 版丢包）
        switch (job) {
            .udp => |u| pktPut(pool.allocator, u.packet),
            .tcp => |c| {
                net.close(c.fd);
                pool.allocator.destroy(c);
            },
            .stop => {},
        }
        return;
    };
    pool.mutex.unlock(pool.io);
    pool.sem.post(pool.io);
}

fn queuePop() ?Job {
    pool.mutex.lockUncancelable(pool.io);
    defer pool.mutex.unlock(pool.io);
    if (pool.queue_head >= pool.queue.items.len) return null;
    const job = pool.queue.items[pool.queue_head];
    pool.queue_head += 1;
    // 全部取完后整体复位，避免下标无限增长
    if (pool.queue_head == pool.queue.items.len) {
        pool.queue.clearRetainingCapacity();
        pool.queue_head = 0;
    } else if (pool.queue_head >= 1024 and pool.queue_head * 2 >= pool.queue.items.len) {
        // 队首残留过多时压缩一次（摊还成本 O(1)）
        const rest = pool.queue.items.len - pool.queue_head;
        std.mem.copyForwards(Job, pool.queue.items[0..rest], pool.queue.items[pool.queue_head..]);
        pool.queue.shrinkRetainingCapacity(rest);
        pool.queue_head = 0;
    }
    return job;
}

// ---------------------------------------------------------------------------
// 监听 socket（对应 network.c: create_listeners()）
// ---------------------------------------------------------------------------
/// 为一组地址建立 UDP + TCP 监听 socket，写入 d.listeners。
///
/// 查 IPv4 地址 `addr4`（网络序）所在接口的掩码（网络序）。
///
/// 用 RTM_GETADDR dump 拿到 `prefixlen` 再换算成掩码 —— 对应 C 在
/// `receive_query()` 里「找到地址等于 dst_addr 的那个 interface，取其 netmask」
/// （forward.c:1796-1810）。查不到（地址已消失 / 非本机地址）返回 0，
/// 此时 `sameNet4` 恒真 = 不做过滤，与 C 在掩码未知时的表现一致。
fn resolveNetmask4(alloc: std.mem.Allocator, addr4: u32) u32 {
    var list: std.ArrayListUnmanaged(net.IfaceAddr) = .empty;
    defer list.deinit(alloc);
    net.listIfaceAddrs(alloc, &list) catch return 0;
    for (list.items) |ia| {
        if (ia.sa.store.family != std.posix.AF.INET) continue;
        if (ia.sa.asIn().addr != addr4) continue;
        var mb: [4]u8 = .{0} ** 4;
        var i: u8 = 0;
        while (i < ia.prefixlen and i < 32) : (i += 1)
            mb[i / 8] |= @as(u8, 0x80) >> @intCast(i % 8);
        return @bitCast(mb);
    }
    return 0;
}

/// 监听地址的来源优先级（对应 network.c: create_listeners 的
/// daemon->if_addrs / daemon->if_names 两条路径）：
///   1. `--listen-address`（已填进 d.listen_addrs）
///   2. `--interface=<网卡名>` —— 展开成该网卡的所有地址，并且**总要补上回环**
///      （C 版 network.c:501 的注释：If we are restricting the set of interfaces
///      to use, make sure that loopback interfaces are in that set）
///   3. 都没配 —— 监听通配地址
pub fn createListeners(d: *Daemon) !void {
    if (d.listen_addrs.items.len == 0 and d.interfaces.items.len != 0) {
        try resolveInterfaceListenAddrs(d);
    }

    if (d.listen_addrs.items.len == 0) {
        try addListener(d, addr.Af.ip4, SockAddr.fromIp4(addr.ANY_IP4, d.port));
        // IPv6 通配可能因为内核未启用 IPv6 而失败，失败不算致命
        addListener(d, addr.Af.ip6, SockAddr.fromIp6(addr.ANY_IP6, d.port, 0)) catch |e| {
            log.warning("无法监听 IPv6 通配地址，跳过: {s}", .{@errorName(e)});
        };
        // 高1：通配绑定下拿不到「查询到达的具体地址」（C 靠 IP_PKTINFO，本移植刻意
        // 不绑通配），--localise-queries 会静默失效 —— 明确告警而不是悄悄不生效。
        if (d.option(protocol.OPT_LOCALISE))
            log.warning("--localise-queries 在通配绑定下无法确定查询到达的地址，将不生效；" ++
                "请用 --listen-address 指定具体地址（例如网关地址）", .{});
        return;
    }
    for (d.listen_addrs.items) |*a| {
        var sa = a.*;
        sa.setPort(d.port);
        try addListener(d, if (sa.isIp6()) addr.Af.ip6 else addr.Af.ip4, sa);
    }

    if (d.option(protocol.OPT_LOCALISE)) {
        for (d.listeners.items) |l| {
            if (l.family == std.posix.AF.INET and l.local4 == 0) {
                log.warning("--localise-queries：有监听项没有具体 IPv4 地址，该监听上的 localise 不生效", .{});
                break;
            }
        }
    }
}

/// 把 `--interface=` / `--except-interface=` 解析成具体的监听地址。
///
/// 无法解析出任何 `interface=` 地址时**不会**退回通配地址：那会把
/// 「只在内网网卡上服务」悄悄变成「在所有网卡上服务」，正是配置想避免的事。
/// 此时只保留回环，并打一条醒目的错误日志 —— 本机（路由器自己的
/// /etc/resolv.conf 指向 127.0.0.1）仍可解析，WAN 侧绝不暴露。
fn resolveInterfaceListenAddrs(d: *Daemon) !void {
    var want: std.ArrayListUnmanaged(u32) = .empty;
    defer want.deinit(d.allocator);
    var deny: std.ArrayListUnmanaged(u32) = .empty;
    defer deny.deinit(d.allocator);

    try net.resolveIfaceIndexes(d.allocator, d.interfaces.items, &want, "interface");
    try net.resolveIfaceIndexes(d.allocator, d.except_interfaces.items, &deny, "except-interface");

    // 回环**总是**保留：C 版 network.c:501 的注释说得很明确 ——
    //   If we are restricting the set of interfaces to use, make sure that
    //   loopback interfaces are in that set.
    // 少了这一步，路由器自己的 /etc/resolv.conf（nameserver 127.0.0.1）
    // 就没人应答了：整机 DNS 看着正常、本机解析却全挂。
    // 唯一的例外是显式写了 --except-interface=lo。
    const lo_idx = net.ifaceIndex("lo");
    var lo_excluded = false;
    if (lo_idx) |idx| {
        for (deny.items) |dn| {
            if (dn == idx) {
                lo_excluded = true;
                break;
            }
        }
    }

    var picked: usize = 0;
    var all_addrs: std.ArrayListUnmanaged(net.IfaceAddr) = .empty;
    defer all_addrs.deinit(d.allocator);
    net.listIfaceAddrs(d.allocator, &all_addrs) catch |e| {
        log.err("枚举接口地址失败（{s}），只监听回环", .{@errorName(e)});
        all_addrs.clearRetainingCapacity();
    };

    for (all_addrs.items) |ia| {
        var ok = false;
        for (want.items) |w| {
            if (w == ia.ifindex) {
                ok = true;
                break;
            }
        }
        if (!ok and !lo_excluded) {
            if (lo_idx) |idx| {
                if (ia.ifindex == idx) ok = true;
            }
        }
        if (!ok) continue;
        for (deny.items) |dn| {
            if (dn == ia.ifindex) {
                ok = false;
                break;
            }
        }
        if (!ok) continue;

        var sa = ia.sa;
        sa.setPort(d.port);
        try d.listen_addrs.append(d.allocator, sa);
        picked += 1;
    }

    if (picked == 0) {
        log.err(
            "按 --interface 找不到任何可监听地址（网卡是否还没 up？），退守回环 127.0.0.1/::1；" ++
                "注意此时不监听通配地址，以免把解析器暴露到 WAN",
            .{},
        );
        try d.listen_addrs.append(d.allocator, SockAddr.fromIp4(addr.LOOPBACK_IP4, d.port));
        try d.listen_addrs.append(d.allocator, SockAddr.fromIp6(net.LOOPBACK_IP6, d.port, 0));
        return;
    }

    log.info("--interface 解析出 {d} 个监听地址（已排除 --except-interface 指定的网卡）", .{picked});
}

fn addListener(d: *Daemon, family_enum: addr.Af, sa_in: SockAddr) !void {
    const fam: u16 = switch (family_enum) {
        .ip4 => std.posix.AF.INET,
        .ip6 => std.posix.AF.INET6,
    };

    var sa = sa_in;

    // 先建 TCP：端口为 0（仅测试会这样用）时，由内核分配后让 UDP 复用同一端口，
    // 否则 UDP / TCP 会各自拿到不同的临时端口。
    const tcp = try net.socketCreate(fam, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    errdefer net.close(tcp);
    try net.setReuseAddr(tcp);
    if (family_enum == .ip6) net.setIpv6Only(tcp) catch {};
    try net.bind(tcp, &sa);
    try net.listen(tcp, 32);

    // 取回内核分配的实际地址
    var out = sa;
    var slen: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
    {
        const rc = std.posix.system.getsockname(tcp, out.mutPtr(), &slen);
        if (std.posix.errno(rc) != .SUCCESS) return error.Unexpected;
        out.len = slen;
    }
    if (sa.port() == 0) sa.setPort(out.port());

    const udp = try net.socketCreate(fam, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP);
    errdefer net.close(udp);
    // 大接收缓冲：突发流量下不丢包（内核默认值在压测中确实溢出了）
    net.setRecvBuf(udp, net.RECV_BUF_BYTES);
    try net.setReuseAddr(udp);
    if (family_enum == .ip6) net.setIpv6Only(udp) catch {};
    try net.bind(udp, &sa);

    // 高1/高3：记录「查询到达的本地地址」及其网段掩码。
    // 本移植每个具体地址单独绑 socket，所以目的地址必然等于绑定地址 —— 这正是
    // IP_PKTINFO 的 ipi_addr 会告诉我们的东西；同时回包也在这个 socket 上发，
    // 源地址天然就是该地址（IP_PKTINFO 源地址选择要达到的效果）。
    // 通配绑定时 local4 = 0，--localise-queries 自然失效（见 createListeners 里的告警）。
    var local4: u32 = 0;
    var netmask4: u32 = 0;
    if (family_enum == .ip4) {
        local4 = out.asIn().addr;
        netmask4 = resolveNetmask4(d.allocator, local4);
    }

    try d.listeners.append(d.allocator, .{
        .fd = udp,
        .tcpfd = tcp,
        .family = fam,
        .port = out.port(),
        .bound = out,
        .local4 = local4,
        .netmask4 = netmask4,
    });

    var buf: [128]u8 = undefined;
    log.info("开始监听 {s} (UDP/TCP)", .{out.writeTo(&buf)});
}

/// 关闭所有监听 socket
pub fn closeListeners(d: *Daemon) void {
    for (d.listeners.items) |l| {
        if (l.fd >= 0) net.close(l.fd);
        if (l.tcpfd >= 0) net.close(l.tcpfd);
    }
    d.listeners.clearRetainingCapacity();
}

// ---------------------------------------------------------------------------
// 查询处理
// ---------------------------------------------------------------------------
/// UDP 的一轮完整处理：本地应答 -> 上游转发 -> SERVFAIL
pub fn handleUdpQuery(
    d: *Daemon,
    packet: []u8,
    len: usize,
    client: SockAddr,
    reply_fd: net.fd_t,
    local4: u32,
    netmask4: u32,
) void {
    const now = util.dnsmasqTime();

    // 总查询计数（对应 dnsmasq 的 METRIC_DNS_QUERIES）。
    // 之前漏了这一步，SIGUSR1 统计里的 "queries total" 永远是 0。
    _ = d.query_count.fetchAdd(1, .monotonic);

    var namebuf: [rfc1035.MAXNAMEBUF]u8 = undefined;
    var req = rfc1035.extractRequest(packet, len, &namebuf) orelse {
        // 无法解析：对应 C 版直接丢包
        log.warning("收到无法解析的报文，丢弃", .{});
        return;
    };

    // 高1/高3：把「查询到达的本地地址」带给应答逻辑（等价 IP_PKTINFO 的 ipi_addr）。
    req.local4 = local4;
    req.netmask4 = netmask4;

    log.logQuery(protocol.F_QUERY | req.flags, req.name, client.toAllAddr(), null, req.qtype);

    // 客户端通告的 UDP 负载大小决定应答上限（无 EDNS0 时为 512）
    const client_limit: usize = if (req.has_edns0)
        @min(@as(usize, req.edns_pktsz), UDP_PACKET_MAX)
    else
        protocol.PACKETSZ;
    const limit = @min(client_limit, packet.len);

    // 1) 本地应答（缓存 / hosts / --address / local 域 ...）
    const ans = rfc1035.answerRequest(d, packet, len, limit, now, req, &client);
    if (ans.len != 0) {
        logAnswer(req, ans, packet, ans.len);
        sendUdp(reply_fd, packet[0..ans.len], &client, limit);
        return;
    }

    // 2) 转上游 —— 交给异步引擎，本线程立刻回到池子里接下一个查询。
    //
    // 这里是整个改造的关键点：以前本线程会同步阻塞等上游应答（最多 10 秒），
    // 并发度被线程数死死限制。现在只是把查询拷进引擎的队列就返回。
    if (fwdengine.submitUdp(d, packet, len, req, &client, reply_fd, limit, now)) return;

    // 3) 引擎不可用（未启动 / 队列满）时退回同步阻塞路径，行为与旧版一致
    forwardSync(d, packet, len, req, &client, reply_fd, limit, now);
}

/// 同步兜底路径：引擎不可用时使用，行为与改造前完全一致。
fn forwardSync(
    d: *Daemon,
    packet: []u8,
    len: usize,
    req: rfc1035.Request,
    client: *const SockAddr,
    reply_fd: net.fd_t,
    limit: usize,
    now: i64,
) void {
    var fr = forward.Frec{
        .packet = packet,
        .len = len,
        .qlen = len,
        .source = client.*,
        .qname = req.name,
        .qtype = req.qtype,
        .qclass = req.qclass,
        .client_edns0 = req.has_edns0,
        .flags = req.flags,
    };
    // 先把原始查询拷进 frec 自带缓冲：接下来 forwardQuery 会就地覆写 packet
    forward.saveOriginal(&fr, packet, len);
    const fres = forward.forwardQuery(d, packet, len, &fr, now);

    if (fres.len != 0) {
        log.logQuery(protocol.F_UPSTREAM, req.name, null, null, req.qtype);
        sendUdp(reply_fd, packet[0..fres.len], client, limit);
        return;
    }

    // 全部上游失败 -> SERVFAIL（对应 C 版 return_reply 里的 STATUS 处理）
    const qlen = name.skipQuestions(packet, len) orelse len;
    rfc1035.setupReply(packet, protocol.F_RCODE, -1);
    protocol.setRcode(&packet[protocol.OFF_HB4], protocol.SERVFAIL);
    protocol.setAncount(packet, 0);
    protocol.setNscount(packet, 0);
    protocol.setArcount(packet, 0);
    protocol.setId(packet, protocol.headerId(packet));
    const out = @min(qlen, packet.len);
    log.warning("上游全部失败，返回 SERVFAIL: {s}", .{req.name});
    _ = net.sendto(reply_fd, packet[0..out], client, 0) catch {};
}

/// 发送 UDP 应答；超过客户端通告的大小时按 RFC 1035 截断并置 TC 位。
///
/// 公开给 fwdengine.zig 使用 —— 异步引擎收到上游应答后走同一条回包逻辑，
/// 保证两条路径的截断/TC 语义完全一致。
pub fn sendUdp(
    fd: net.fd_t,
    reply: []u8,
    client: *const SockAddr,
    limit: usize,
) void {
    var out_len = reply.len;
    if (out_len > limit) {
        // 截断到「头部 + 问题区」并置 TC 位，让客户端改走 TCP
        const qlen = name.skipQuestions(reply, reply.len) orelse protocol.HEADER_SIZE;
        if (qlen <= limit) {
            reply[protocol.OFF_HB3] |= protocol.HB3_TC;
            protocol.setAncount(reply, 0);
            protocol.setNscount(reply, 0);
            protocol.setArcount(reply, 0);
            out_len = qlen;
        } else {
            out_len = limit;
        }
    }
    _ = net.sendto(fd, reply[0..out_len], client, 0) catch |e| {
        log.debug("UDP 回包失败: {s}", .{@errorName(e)});
    };
}

/// 按 dnsmasq 的日志规则输出本地应答（cached / hosts / config ...）
fn logAnswer(req: rfc1035.Request, ans: rfc1035.AnswerResult, packet: []u8, len: usize) void {
    if (!ans.from_cache) {
        // 配置类应答（--address / local=/dom/ / domain-needed ...）
        log.logQuery(protocol.F_CONFIG, req.name, null, null, req.qtype);
        return;
    }

    // 从应答里取出第一段地址用于日志（对应 C 版 log_query 里传 &crecp->addr）
    var a: ?addr.AllAddr = null;
    var p = name.skipQuestions(packet, len) orelse return;
    var namebuf: [rfc1035.MAXNAMEBUF]u8 = undefined;
    const np = name.skipName(packet, p, len, 10) orelse return;
    p = np;
    if (p + 10 <= len) {
        const rr_type = protocol.getShort(packet, p);
        const rdlen = protocol.getShort(packet, p + 8);
        const rd = p + 10;
        if (rd + rdlen <= len) {
            if (rr_type == protocol.T_A and rdlen == 4) {
                a = .{ .ip4 = @bitCast(packet[rd..][0..4].*) };
            } else if (rr_type == protocol.T_AAAA and rdlen == 16) {
                a = .{ .ip6 = packet[rd..][0..16].* };
            }
        }
    }
    _ = &namebuf;
    log.logQuery(protocol.F_FORWARD, req.name, a, null, req.qtype);
}

/// 一条 TCP 连接上的完整处理（对应 forward.c: tcp_request()）
pub fn handleTcpConn(d: *Daemon, conn: *TcpConn) void {
    // 注意：必须合并成一个 defer —— 否则 LIFO 顺序会让 destroy 先于 close 执行，
    // close(conn.fd) 就读到了已释放内存。
    defer {
        net.close(conn.fd);
        pool.allocator.destroy(conn);
    }

    const buf = pool.allocator.alloc(u8, TCP_PACKET_MAX) catch return;
    defer pool.allocator.free(buf);

    while (conn.queries < TCP_MAX_QUERIES) {
        // 读长度前缀（对应 C 版 `read_write(confd, &tcp_len, 2, RW_READ)`）。
        //
        // ★ 跨 TCP 段的 DNS 消息重组：readTimeout() 会**循环 recv 直到填满整个
        //   缓冲区**才返回，所以下面这两次读取本身就把「长度前缀」与「正文」
        //   各自拼装完整了 —— 客户端把长度前缀/正文拆成多个 TCP 段（甚至分多次
        //   send、中间带延迟）发送时也能正确组装。C 的 read_write() 同样是
        //   「读满 len 字节才返回」的语义，两边行为一致。
        if (!readTimeout(conn.fd, buf[0..2], protocol.TCP_TIMEOUT_MS)) return;
        const plen = protocol.getShort(buf, 0);
        // 长度为 0 属客户端异常：C 是 `!(size = ntohs(tcp_len))` → break（关连接）
        if (plen == 0) return;
        // 短于 DNS 头：C 用 `continue` 跳过这一条并**保留连接**继续读下一条
        if (plen < protocol.HEADER_SIZE) continue;

        if (!readTimeout(conn.fd, buf[0..plen], protocol.TCP_TIMEOUT_MS)) return;
        // 只处理查询报文；QR=1（应答）C 也是 `continue` 跳过
        // （对应 C：`if (size < sizeof(struct dns_header) || (header->hb3 & HB3_QR)) continue;`）
        if ((buf[protocol.OFF_HB3] & protocol.HB3_QR) != 0) continue;
        conn.queries += 1;
        // TCP 上的每个查询同样计入总查询数（与 UDP 的处理保持一致）
        _ = d.query_count.fetchAdd(1, .monotonic);

        const now = util.dnsmasqTime();
        var namebuf: [rfc1035.MAXNAMEBUF]u8 = undefined;
        var req = rfc1035.extractRequest(buf, plen, &namebuf) orelse continue;
        // 高1：TCP 上用 getsockname 取本端地址作为「查询到达的本地地址」
        //（等价 IP_PKTINFO 的 ipi_addr；Accepted socket 的本端地址就是监听地址）
        {
            var lsa = SockAddr{ .store = .{ .family = 0 }, .len = 0 };
            var lslen: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
            if (std.posix.errno(std.posix.system.getsockname(conn.fd, lsa.mutPtr(), &lslen)) == .SUCCESS) {
                lsa.len = lslen;
                if (lsa.store.family == std.posix.AF.INET) {
                    req.local4 = lsa.asIn().addr;
                    req.netmask4 = resolveNetmask4(d.allocator, req.local4);
                }
            }
        }
        log.logQuery(protocol.F_QUERY | req.flags, req.name, conn.client.toAllAddr(), null, req.qtype);

        // TCP 不受 512 字节限制，limit 直接给到缓冲区大小
        var out_len: usize = 0;
        const ans = rfc1035.answerRequest(d, buf, plen, TCP_PACKET_MAX, now, req, &conn.client);
        if (ans.len != 0) {
            out_len = ans.len;
        } else {
            var fr = forward.Frec{
                .packet = buf,
                .len = plen,
                .qlen = plen,
                .source = conn.client,
                .qname = req.name,
                .qtype = req.qtype,
                .qclass = req.qclass,
                .client_edns0 = req.has_edns0,
                .flags = req.flags,
            };
            forward.saveOriginal(&fr, buf, plen);
            const fres = forward.forwardQuery(d, buf, plen, &fr, now);
            if (fres.len != 0) {
                out_len = fres.len;
            } else {
                const qlen = name.skipQuestions(buf, plen) orelse plen;
                rfc1035.setupReply(buf, protocol.F_RCODE, -1);
                protocol.setRcode(&buf[protocol.OFF_HB4], protocol.SERVFAIL);
                protocol.setAncount(buf, 0);
                protocol.setNscount(buf, 0);
                protocol.setArcount(buf, 0);
                out_len = qlen;
            }
        }

        // 写：2 字节长度 + 报文
        var lenbuf: [2]u8 = undefined;
        protocol.putShort(&lenbuf, 0, @intCast(out_len));
        writeTimeout(conn.fd, &lenbuf) catch return;
        writeTimeout(conn.fd, buf[0..out_len]) catch return;
    }
}

fn readTimeout(fd: net.fd_t, buf: []u8, timeout_ms: i32) bool {
    var got: usize = 0;
    const deadline = util.monoMillis() + timeout_ms;
    while (got < buf.len) {
        const remain = deadline - util.monoMillis();
        if (remain <= 0) return false;
        var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
        const r = net.poll(&fds, @intCast(@min(remain, 1000))) catch return false;
        if (r == 0) continue;
        const n = net.recv(fd, buf[got..], 0) catch return false;
        if (n == 0) return false;
        got += n;
    }
    return true;
}

fn writeTimeout(fd: net.fd_t, buf: []const u8) !void {
    var off: usize = 0;
    while (off < buf.len) {
        var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 }};
        _ = net.poll(&fds, 5000) catch return error.Timeout;
        const n = net.sendto(fd, buf[off..], null, 0) catch return error.WriteFailed;
        if (n == 0) return error.WriteFailed;
        off += n;
    }
}

// ---------------------------------------------------------------------------
// 线程池
// ---------------------------------------------------------------------------
/// 启动 N 个工作线程（N 由 --threads 决定，0 表示按 CPU 数推算）
///
/// 注意：改造为异步转发后，工作线程**只负责本地应答**（缓存/hosts/配置），
/// 这是纯 CPU 负载，因此按 CPU 数开线程就是最优的。
/// 旧版之所以要开到 CPU×2，是因为转发要同步阻塞等上游、IO 密集；那条路径
/// 现在归 fwdengine.zig 的单事件循环了，这里不再需要超额线程。
pub fn startPool(d: *Daemon) !void {
    pool.allocator = d.allocator;
    pool.io = d.io;

    var n = d.threads;
    if (n == 0) {
        const cpus = std.Thread.getCpuCount() catch 2;
        if (d.sync_forward) {
            // 同步转发：线程同时承担本地应答与「阻塞等上游」，IO 密集。
            // 实测 2 核路由器上默认 2 线程时冷查询只有 46 qps、p50 594ms；
            // 开到 8 线程吞吐翻倍、尾延迟降到 350ms。所以要超额开。
            n = cpus * 2;
            if (n < 4) n = 4;
            if (n > 16) n = 16;
        } else {
            // 异步转发：工作线程只做纯 CPU 的本地应答，按 CPU 数开就是最优
            n = cpus;
            if (n < 2) n = 2;
            if (n > 8) n = 8;
        }
    }
    if (n < 1) n = 1;

    var i: usize = 0;
    while (i < n) : (i += 1) {
        const t = try std.Thread.spawn(.{}, workerMain, .{});
        try pool.threads.append(pool.allocator, t);
    }
    log.notice("已启动 {d} 个本地应答线程", .{n});
}

pub fn stopPool() void {
    pool.shutdown.store(true, .monotonic);
    for (pool.threads.items) |_| queuePush(.stop);
    for (pool.threads.items) |t| t.join();
    pool.threads.deinit(pool.allocator);
    pool.queue.deinit(pool.allocator);
    // 释放报文缓冲池
    for (pool.pkt_pool.items) |b| pool.allocator.free(b);
    pool.pkt_pool.deinit(pool.allocator);
    pool.queue_head = 0;
}

/// 处理一个任务；返回 true 表示 worker 应当退出
fn handleJob(job: Job) bool {
    switch (job) {
        .stop => return true,
        .udp => |u| {
            defer pktPut(pool.allocator, u.packet);
            _ = pool.inflight.fetchSub(1, .monotonic);
            handleUdpQuery(daemon_mod.get(), u.packet, u.len, u.client, u.reply_fd, u.local4, u.netmask4);
        },
        .tcp => |c| {
            _ = pool.inflight.fetchSub(1, .monotonic);
            handleTcpConn(daemon_mod.get(), c);
        },
    }
    return false;
}

fn workerMain() void {
    const io = pool.io;
    while (true) {
        // 快路径：队列里还有活就直接接着干。
        // 原来每次都先 sem.wait 再取任务，即使队列里堆积了大量任务，
        // 每个查询也要付一次 futex 唤醒；这里改成「能取到就不睡」。
        if (queuePop()) |job| {
            if (handleJob(job)) return;
            continue;
        }
        pool.sem.waitUncancelable(io);
        // 醒来后由下一轮 queuePop 取任务；信号量多出的许可只会带来一次空转
    }
}

// ---------------------------------------------------------------------------
// 信号（对应 dnsmasq.c 的信号处理）
// ---------------------------------------------------------------------------
/// 自管道：信号处理器只写一个字节，主循环 poll 该 fd，避免在信号里做重活
pub var sig_pipe: [2]net.fd_t = .{ -1, -1 };

fn signalHandler(sig: std.posix.SIG) callconv(.c) void {
    // 只往自管道写一个字节（信号编号），主循环负责解释
    const b: [1]u8 = .{@truncate(@intFromEnum(sig))};
    _ = std.posix.system.write(sig_pipe[1], &b, 1);
}

/// 安装信号处理器。返回 false 表示无法建立自管道。
pub fn installSignals() bool {
    const rc = std.posix.system.pipe2(&sig_pipe, .{ .NONBLOCK = true, .CLOEXEC = true });
    if (std.posix.errno(rc) != .SUCCESS) return false;

    const sigs = [_]std.posix.SIG{ .HUP, .TERM, .INT, .USR1 };
    for (sigs) |s| {
        const act = std.posix.Sigaction{
            .handler = .{ .handler = signalHandler },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(s, &act, null);
    }
    return true;
}

/// 取出自管道里的所有信号字节（返回收到的信号列表，用 out 缓冲）
pub fn drainSignals(out: []std.posix.SIG) usize {
    var n: usize = 0;
    var b: [1]u8 = undefined;
    while (n < out.len) {
        const rc = std.posix.system.read(sig_pipe[0], &b, 1);
        if (std.posix.errno(rc) != .SUCCESS or rc == 0) break;
        out[n] = @enumFromInt(b[0]);
        n += 1;
    }
    return n;
}

// ---------------------------------------------------------------------------
// 主循环（对应 dnsmasq.c: main() 里的 poll 循环）
// ---------------------------------------------------------------------------
pub fn run(d: *Daemon) !void {
    var fds: std.ArrayListUnmanaged(std.posix.pollfd) = .empty;
    defer fds.deinit(d.allocator);

    // 监听 fd 与 listeners 一一对应：先 UDP 后 TCP，索引映射在下面用 offset 算
    try fds.append(d.allocator, .{ .fd = sig_pipe[0], .events = std.posix.POLL.IN, .revents = 0 });
    for (d.listeners.items) |l| {
        try fds.append(d.allocator, .{ .fd = l.fd, .events = std.posix.POLL.IN, .revents = 0 });
    }
    const tcp_base = fds.items.len;
    for (d.listeners.items) |l| {
        try fds.append(d.allocator, .{ .fd = l.tcpfd, .events = std.posix.POLL.IN, .revents = 0 });
    }

    // --hostsdir 的 inotify 监视：目录里的 hosts 文件一变就重载。
    // **必须追加在所有 listener 之后** —— 上面的 UDP/TCP 索引是靠
    // `1 + i` / `tcp_base + i` 算出来的，插在中间会把映射整体挪位。
    var watcher = hosts.DirWatcher{};
    if (watcher.init(d)) {
        log.notice("已监视 {d} 个 --hostsdir 目录，hosts 文件变化即时生效", .{watcher.n_watched});
    }
    defer watcher.deinit();
    const watch_idx: ?usize = if (watcher.fd >= 0) blk: {
        try fds.append(d.allocator, .{ .fd = watcher.fd, .events = std.posix.POLL.IN, .revents = 0 });
        break :blk fds.items.len - 1;
    } else null;

    var last_expire = util.dnsmasqTime();
    // --hostsdir 变化标记：真正的重载在循环里合并做（见下方同名说明）
    var hosts_dirty = false;
    var last_resolv_poll = util.dnsmasqTime();

    // 注意：resolv.conf 的基线快照**不在这里**拍 —— 必须在读 resolv.conf
    // **之前**沉淀（现在由 main.loadHostsAndResolv 调用 snapshotResolvStats）。
    // 在读取之后才拍会把「读的时候文件还空着、读完 netifd 才填上」这个
    // 开机竞态悄悄吸收掉，导致永久停在 0 个上游。详见 snapshotResolvStats 的注释。

    while (d.running.load(.monotonic)) {
        _ = net.poll(fds.items, 1000) catch |e| {
            if (e != error.Interrupted) log.warning("poll 失败: {s}", .{@errorName(e)});
            continue;
        };

        // ---- 信号 ----
        if ((fds.items[0].revents & std.posix.POLL.IN) != 0) {
            var sigs: [16]std.posix.SIG = undefined;
            const n = drainSignals(&sigs);
            for (sigs[0..n]) |s| switch (s) {
                .HUP => {
                    log.notice("收到 SIGHUP，重新读取 hosts 与上游服务器", .{});
                    reload(d);
                },
                .USR1 => {
                    log.notice("收到 SIGUSR1，输出统计", .{});
                    dumpStats(d);
                },
                else => {
                    log.notice("收到信号 {d}，退出", .{@intFromEnum(s)});
                    d.running.store(false, .monotonic);
                },
            };
        }

        // ---- --hostsdir 变化 ----
        // odhcpd 重写了 `odhcpd.hosts.<ifname>` → 重载 hosts，让
        // `<host>.lan` 立刻能解析（不必重启 DNS）。
        //
        // **只置标记，不在这里立即重载**：odhcpd 每次租约变化会写**两个**文件
        // （状态文件 + hosts 文件），于是同一次变化会推来两个 inotify 事件；
        // 在每个事件上都重载一次就会「重载两遍 + 打两行日志」（实测日志里成双出现）。
        // 挪到下面的节拍里做，一秒内的多次事件自然合并成一次。
        if (watch_idx) |wi| {
            if ((fds.items[wi].revents & std.posix.POLL.IN) != 0 and watcher.drain()) {
                hosts_dirty = true;
            }
        }

        // 合并后的 hosts 重载（每轮最多一次）。日志用 debug：这类「后台同步」
        // 属于常态事件，不该占用默认可见的 notice/info 通道 —— 需要时开调试即可。
        if (hosts_dirty) {
            hosts_dirty = false;
            log.debug("--hostsdir 有变化，重新读取 hosts", .{});
            reload(d);
        }

        // ---- UDP ----
        var i: usize = 0;
        while (i < d.listeners.items.len) : (i += 1) {
            const idx = 1 + i;
            if ((fds.items[idx].revents & std.posix.POLL.IN) == 0) continue;
            const l = d.listeners.items[i];

            // 一次 poll 唤醒把该 socket 上已到达的报文尽量收完，
            // 否则每个报文都要付一次 poll 系统调用（热缓存路径上的头号开销）。
            const MSG_DONTWAIT: u32 = @intCast(std.posix.MSG.DONTWAIT);
            var batch: usize = 0;
            while (batch < UDP_BATCH_MAX) : (batch += 1) {
                // 限流：对应 --dns-forward-max 的思路，队列过深就丢包
                if (pool.inflight.load(.monotonic) > d.dns_forward_max * 8) {
                    if (batch == 0) log.warning("查询队列已满，丢弃新报文", .{});
                    var sink: [UDP_PACKET_MAX]u8 = undefined;
                    var from = SockAddr{ .store = .{ .family = 0 }, .len = 0 };
                    _ = net.recvfrom(l.fd, &sink, &from, MSG_DONTWAIT) catch {};
                    break;
                }

                const packet = pktGet(d.allocator) orelse break;
                var from = SockAddr{ .store = .{ .family = 0 }, .len = 0 };
                const n = net.recvfrom(l.fd, packet, &from, MSG_DONTWAIT) catch {
                    pktPut(d.allocator, packet);
                    break; // 本轮已收完（EAGAIN）
                };
                if (n == 0) {
                    pktPut(d.allocator, packet);
                    continue;
                }
                _ = pool.inflight.fetchAdd(1, .monotonic);
                queuePush(.{ .udp = .{
                    .packet = packet,
                    .len = n,
                    .client = from,
                    .reply_fd = l.fd,
                    .local4 = l.local4,
                    .netmask4 = l.netmask4,
                } });
            }
        }

        // ---- TCP ----
        i = 0;
        while (i < d.listeners.items.len) : (i += 1) {
            const idx = tcp_base + i;
            if ((fds.items[idx].revents & std.posix.POLL.IN) == 0) continue;
            const l = d.listeners.items[i];

            const cfd = net.accept(l.tcpfd) catch |e| {
                log.debug("accept 失败: {s}", .{@errorName(e)});
                continue;
            };
            var peer = SockAddr{ .store = .{ .family = 0 }, .len = 0 };
            var plen: std.posix.socklen_t = @sizeOf(std.posix.sockaddr.storage);
            const rc = std.posix.system.getpeername(cfd, peer.mutPtr(), &plen);
            if (std.posix.errno(rc) == .SUCCESS) peer.len = plen;

            // 整条连接交给异步引擎：非阻塞读帧 -> 本地应答 -> 上游异步转发 -> 非阻塞写出。
            // 引擎不可用时退回「一个工作线程包一条连接」的旧模型。
            if (fwdengine.adoptTcpConn(cfd, peer)) continue;

            const conn = d.allocator.create(TcpConn) catch {
                net.close(cfd);
                continue;
            };
            conn.* = .{ .fd = cfd, .client = peer };
            _ = pool.inflight.fetchAdd(1, .monotonic);
            queuePush(.{ .tcp = conn });
        }

        // ---- 周期性任务：缓存过期回收（对应 dnsmasq.c 里每 10 秒的例行工作）----
        const now = util.dnsmasqTime();
        if (now - last_expire >= 10) {
            last_expire = now;
            d.cache.lock(d.io);
            const removed = d.cache.expire(now);
            d.cache.unlock(d.io);
            if (removed != 0) log.debug("缓存回收 {d} 条过期记录", .{removed});
        }

        // ---- --no-poll 关闭时，定期检查 resolv.conf 变化 ----
        if (!d.option(protocol.OPT_NO_POLL) and now - last_resolv_poll >= protocol.FORWARD_TIME) {
            last_resolv_poll = now;
            pollResolv(d);
        }
    }
}

/// SIGHUP 重载：清 hosts 记录 + 重读 hosts 与 resolv.conf + 重建服务器数组
pub fn reload(d: *Daemon) void {
    // 必须先让异步引擎撒手。它手上握着在途查询里的 `*Server` 指针与上游 socket，
    // 而下面的 cleanupServers() 会 `allocator.destroy(s)` —— 不收干净就是一个
    // use-after-free（这个项目已经被同类问题咬过一次）。
    fwdengine.quiesce();
    defer fwdengine.unquiesce();

    d.cache.lock(d.io);
    defer d.cache.unlock(d.io);

    // 保留 config/upstream 记录，只清 hosts 与 resolv 来源的服务器
    domain.markServers(d, protocol.SERV_FROM_FILE | protocol.SERV_FROM_RESOLV);
    domain.cleanupServers(d);

    hosts.cacheReload(&d.cache, d, util.dnsmasqTime());
    resolv.readResolvFiles(d) catch |e| {
        log.warning("重读 resolv 文件失败: {s}", .{@errorName(e)});
    };
    domain.buildServerArray(d) catch |e| {
        log.warning("重建服务器数组失败: {s}", .{@errorName(e)});
    };
}

/// 定期检查 resolv.conf：只有文件真的变了才重建上游列表。
///
/// 对应 C: dnsmasq.c 的 poll_resolv() —— 它用 stat 比对把绝大多数轮询短路
/// 掉，只在 mtime/size 变化时才调 reload_servers()。
///
/// 这里原先的写法是每个轮询周期都无条件 readResolvFiles()，而那个函数是
/// **追加**语义（每读一个 nameserver 就 newServer + addServer）。于是每
/// FORWARD_TIME 秒就多出一组重复上游：resolv.conf 里明明只有 4 条
/// nameserver，跑一小时后服务器数组却涨到几十上百个。后果是每条查询被
/// 摊薄到一堆重复条目上竞速，表现为「刚启动一切正常，跑一阵子后部分
/// 站点开始解析失败」。
fn pollResolv(d: *Daemon) void {
    if (resolvChanged(d)) reloadResolvServers(d);
}

/// 第 i 个 resolv 文件路径；未用 --resolv-file 指定时为默认路径
fn resolvPathAt(d: *const Daemon, i: usize) []const u8 {
    if (d.resolv_files.items.len == 0) return "/etc/resolv.conf";
    return d.resolv_files.items[i];
}

fn resolvFileCount(d: *const Daemon) usize {
    return if (d.resolv_files.items.len == 0) 1 else d.resolv_files.items.len;
}

/// FNV-1a 64：手写而非用 std.hash，只求零依赖、结果稳定
fn hashBytes(b: []const u8) u64 {
    var h: u64 = 0xcbf29ce484222325;
    for (b) |c| {
        h ^= c;
        h *%= 0x100000001b3;
    }
    return h;
}

/// 读整个文件到内存；读不到返回 null（static musl，走裸系统调用）
fn readFileAll(allocator: std.mem.Allocator, path: []const u8) ?[]u8 {
    const fd = std.posix.openat(std.posix.AT.FDCWD, path, std.posix.O{ .ACCMODE = .RDONLY }, 0) catch return null;
    defer _ = std.posix.system.close(fd);

    var buf: std.ArrayList(u8) = .empty;
    var tmp: [4096]u8 = undefined;
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

/// 取第 i 个 resolv 文件的内容快照；读不到文件时返回 valid=false
fn statResolvFile(d: *const daemon_mod.Daemon, i: usize) daemon_mod.ResolvStat {
    const content = readFileAll(d.allocator, resolvPathAt(d, i)) orelse return .{};
    defer d.allocator.free(content);
    return .{ .hash = hashBytes(content), .valid = true };
}

/// 与快照比对：文件个数或内容任一变化即视为变更
fn resolvChanged(d: *Daemon) bool {
    const count = resolvFileCount(d);

    // 文件个数变了（配置改动）：按“已变更”处理，保守但不会漏
    if (d.resolv_stats.items.len != count) {
        refreshResolvStats(d, count);
        return true;
    }

    var changed = false;
    for (0..count) |i| {
        const old = d.resolv_stats.items[i];
        const cur = statResolvFile(d, i);
        if (cur.valid != old.valid or (cur.valid and cur.hash != old.hash)) changed = true;
    }

    if (changed) refreshResolvStats(d, count);
    return changed;
}

/// 沉淀一份 resolv.conf 内容基线（必须在**读取之前**调用）。
///
/// ## ★ 为什么顺序不能反
/// 曾经这个快照是放在 `run()` 里、也就是 `readResolvFiles()` **之后**才拍的。
/// 于是这个开机竞态会被**悄悄吸收**：
///   1. 进程启动时 netifd 还没把 WAN（PPPoE）拉起来 → 读到 0 个 nameserver；
///   2. 等进到 run() 拍快照时，文件已经被填上了 → 基线直接记成「有内容」那版；
///   3. 之后文件内容不再变化 → 每轮轮询都判「没变」→ **永久停在 0 个上游**。
/// 2026-09-21 重启实测：日志里 `resolv.conf 已变更` 出现 **0 次**，同时刷了几万条
/// 「没有可用的上游服务器」，只能手动重启才恢复。
/// 在读取之前拍，则「读完之后才被填上」会体现为基线≠当前 → 下一轮自动重建 ✓
pub fn snapshotResolvStats(d: *Daemon) void {
    refreshResolvStats(d, resolvFileCount(d));
}

/// 强制下一轮轮询重读 resolv.conf（把基线置成「必然与当前不同」的哨兵值）。
///
/// 对应 C dnsmasq 的 `latest->mtime = 0`（dnsmasq.c:1827）：读到 0 个服务器时把
/// mtime 清零，下轮 `st_mtime != res->mtime` 就必然成立，从而实现
/// `no servers found in %s, will retry` 里的 **will retry**。
/// 本移植用 hash 比对，所以哨兵取 `hash=0, valid=true`：
///   * 文件不存在 → 当前是 `valid=false` → 与哨兵的 valid 不同 → 判「变了」✓
///   * 文件存在（哪怕内容为空）→ 当前 hash 一定非 0 → 判「变了」✓
pub fn forceResolvRetry(d: *Daemon) void {
    for (d.resolv_stats.items) |*s| {
        s.hash = 0;
        s.valid = true;
    }
}

fn refreshResolvStats(d: *Daemon, count: usize) void {
    d.resolv_stats.clearRetainingCapacity();
    for (0..count) |i| {
        d.resolv_stats.append(d.allocator, statResolvFile(d, i)) catch {};
    }
}

/// 只重建 resolv.conf 来源的上游：先清掉旧的 SERV_FROM_RESOLV 再重读。
/// 不动配置文件/hosts 来源的服务器，也不清 hosts 缓存（那是 SIGHUP 的职责）。
fn reloadResolvServers(d: *Daemon) void {
    // 同 reload()：引擎手里握着在途查询的 *Server 指针，清理前必须先让它撒手
    fwdengine.quiesce();
    defer fwdengine.unquiesce();

    d.cache.lock(d.io);
    defer d.cache.unlock(d.io);

    domain.markServers(d, protocol.SERV_FROM_RESOLV);
    domain.cleanupServers(d);

    resolv.readResolvFiles(d) catch |e| {
        log.warning("重读 resolv 文件失败: {s}", .{@errorName(e)});
    };
    domain.buildServerArray(d) catch |e| {
        log.warning("重建服务器数组失败: {s}", .{@errorName(e)});
    };
    log.notice("resolv.conf 已变更，上游服务器重建（{d} 个）", .{d.servers.items.len});
}

pub fn dumpStats(d: *Daemon) void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.Writer.fixed(&buf);
    d.dumpStats(&w);
    const text = w.buffered();
    if (text.len == 0) {
        log.notice("尚无上游统计", .{});
        return;
    }
    log.notice("上游服务器统计:\n{s}", .{text});
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------
const testing = std.testing;

test "createListeners 绑定端口 0 并写入 listeners" {
    var d = Daemon{ .allocator = testing.allocator, .port = 0 };
    defer {
        closeListeners(&d);
        d.deinit();
    }
    try createListeners(&d);
    // 至少应该有一个 IPv4 监听
    try testing.expect(d.listeners.items.len >= 1);
    try testing.expect(d.listeners.items[0].fd >= 0);
    try testing.expect(d.listeners.items[0].tcpfd >= 0);
    try testing.expect(d.listeners.items[0].port != 0);
}

test "TCP 查询往返（本地 hosts 应答）" {
    var d = Daemon{ .allocator = testing.allocator, .port = 0 };
    d.cache = try @import("cache.zig").Cache.init(testing.allocator, 64);
    d.cache_ready = true;
    defer {
        closeListeners(&d);
        d.deinit();
    }

    try createListeners(&d);
    const bound = d.listeners.items[0].bound;
    try testing.expect(bound.port() != 0);

    // 往缓存里放一条 hosts 记录
    const ttl = 3600;
    _ = hosts.addHostEntry(&d.cache, "zigtest.local", .{ .ip4 = @bitCast([4]u8{ 10, 1, 2, 3 }) }, ttl, util.dnsmasqTime());

    const pool_mod = @import("forward.zig");
    _ = pool_mod;

    // 起一个客户端连到监听端口
    const cfd = try net.socketCreate(std.posix.AF.INET, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP);
    defer net.close(cfd);
    try net.connect(cfd, &bound);

    // 构造查询
    var pkt: [512]u8 = [_]u8{0} ** 512;
    protocol.setId(&pkt, 0xABCD);
    protocol.setQdcount(&pkt, 1);
    pkt[protocol.OFF_HB3] |= protocol.HB3_RD;
    var off: usize = protocol.HEADER_SIZE;
    off += name.doRfc1035Name(pkt[off..], "zigtest.local").?;
    protocol.putShort(&pkt, off, protocol.T_A);
    protocol.putShort(&pkt, off + 2, protocol.C_IN);
    const qlen = off + 4;

    var lenbuf: [2]u8 = undefined;
    protocol.putShort(&lenbuf, 0, @intCast(qlen));
    _ = net.sendto(cfd, &lenbuf, null, 0) catch |e| return e;
    _ = net.sendto(cfd, pkt[0..qlen], null, 0) catch |e| return e;

    // 服务端：accept 后交给 handleTcpConn 处理
    const sfd = try net.accept(d.listeners.items[0].tcpfd);
    const conn = try testing.allocator.create(TcpConn);
    conn.* = .{ .fd = sfd, .client = bound };

    // 为了不依赖线程池，这里直接在当前线程处理
    pool.allocator = testing.allocator;
    pool.io = testing.io;
    handleTcpConn(&d, conn);

    // 读回：2 字节长度 + 应答
    var rlen: [2]u8 = undefined;
    if (!readTimeout(cfd, &rlen, 2000)) return error.TestUnexpectedResult;
    const resp_len = protocol.getShort(&rlen, 0);
    try testing.expect(resp_len > protocol.HEADER_SIZE);
    var resp: [512]u8 = undefined;
    if (!readTimeout(cfd, resp[0..resp_len], 2000)) return error.TestUnexpectedResult;

    try testing.expectEqual(@as(u16, 0xABCD), protocol.headerId(&resp));
    try testing.expect(protocol.isResponse(protocol.headerHb3(&resp)));
    try testing.expectEqual(@as(u16, 1), protocol.ancount(&resp));

    // 应答里应有 A 记录 10.1.2.3
    const an_start = name.skipQuestions(&resp, resp_len).?;
    var p = an_start;
    var nm: [rfc1035.MAXNAMEBUF]u8 = undefined;
    _ = name.extractName(&resp, resp_len, &p, &nm, name.EXTR_NAME_EXTRACT, 4);
    try testing.expectEqual(protocol.T_A, protocol.getShort(&resp, p));
    const rdlen = protocol.getShort(&resp, p + 8);
    try testing.expectEqual(@as(u16, 4), rdlen);
    try testing.expectEqualSlices(u8, &[_]u8{ 10, 1, 2, 3 }, resp[p + 10 .. p + 14]);
}
