// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! forward.zig — 对应 C 源码 src/forward.c（转发层）
//!
//! ## 与 C 版本的设计差异（重要）
//!
//! C 版 dnsmasq 是**单线程 + poll 事件循环**：所有在途查询放在一个全局
//! `frec` 表里，靠 `reply_query()` 在收到上游应答时按 (server, txid) 反查
//! frec。本移植按需求改成**多线程同步查询**，因此：
//!
//!   * 一个查询 = 一个工作线程 + 一个 `Frec`（栈上对象），不需要全局表，
//!     也不需要 `lookup_frec()` / `pop_and_retry_query()` 那套哈希与链表；
//!   * 上游交互用「阻塞式 socket + poll 超时」代替异步事件驱动，
//!     每个线程独占自己的上游 socket，天然线程安全；
//!   * `resend_query()` 的语义变成「同一个查询在超时后依次尝试其它上游」，
//!     由 `forwardQuery()` 内部的循环完成。
//!
//! 保留下来的 C 版语义：
//!   * 随机事务 ID（`get_id`）与 txid 校验；
//!   * 上游源地址/端口校验（对应 `server_isequal`），防止伪造应答；
//!   * 问题区一致性校验（名字忽略大小写 + qtype + qclass）；
//!   * 超时重试 + 服务器健康度统计（`queries` / `failed_queries` /
//!     `retrys` / `last_reply`），对应 `FORWARD_TEST` / `FORWARD_TIME` 的
//!     「坏服务器降权」；
//!   * `process_reply()` 的关键处理：置 RA 位、清 AD 位、EDNS0 负载通告、
//!     截断（TC）时改用 TCP 重试、把应答写入缓存（`extract_addresses`）、
//!     `--stop-dns-rebind` 的私有地址防护；
//!   * `--strict-order`（OPT_ORDER）与 `--all-servers`（OPT_ALL_SERVERS）
//!     对上游选择的影响。

const std = @import("std");
const protocol = @import("protocol.zig");
const addr = @import("addr.zig");
const name = @import("name.zig");
const net = @import("net.zig");
const util = @import("util.zig");
const log = @import("log.zig");
const daemon_mod = @import("daemon.zig");
const domain = @import("domain.zig");
const rfc1035 = @import("rfc1035.zig");
const cache_mod = @import("cache.zig");
const balancer = @import("balancer.zig");

const Daemon = daemon_mod.Daemon;
const Server = daemon_mod.Server;
const SockAddr = addr.SockAddr;

pub const ForwardError = error{
    NoServer,
    SendFailed,
    Timeout,
    BadReply,
    Truncated,
    SocketFailed,
};

/// 一次转发查询的上下文（对应 struct frec 的简化版，栈上分配）
pub const Frec = struct {
    /// 发往上游的报文（调用者缓冲的一部分，原地改写 id）
    packet: []u8,
    /// 报文有效长度
    len: usize,
    /// 原始查询长度（收到应答后要按此长度恢复问题区计数等）
    qlen: usize,
    /// 本次使用的事务 ID（对应 frec->new_id）
    id: u16 = 0,
    /// 客户端源地址（日志与 EDNS0 校验用）
    source: SockAddr = .{ .store = .{ .family = 0 }, .len = 0 },
    /// 问题区的名字（转义格式）与类型，用于校验应答
    qname: []const u8,
    qtype: u16,
    qclass: u16,
    /// 查询对应的 F_* 标志位（F_IPV4 / F_IPV6 / F_SERVER ...）。
    ///
    /// 这个字段必须由调用者按 qtype 推导后传入，因为 filter_servers() /
    /// lookup_domain() 的依据是它，而不是 qclass。
    /// （曾经把 qclass 当成 flags 传进去 —— qclass 恒为 1，恰好等于
    /// SERV_USE_RESOLV，于是选路 silently 走错了分支。）
    flags: u32 = 0,
    /// 实际选中的服务器（对应 frec->sentto）
    server: ?*Server = null,
    /// 是否因为我们替客户端补了 EDNS0 伪记录（应答里要把它剥掉）
    added_pheader: bool = false,
    /// 客户端原始报文是否带 EDNS0
    client_edns0: bool = false,
    /// 客户端报文里的 do bit
    do_bit: bool = false,
    /// 客户端原始查询报文的**副本**（用于换服务器重试前还原 pkt）。
    ///
    /// 必须是自己持有的缓冲，不能是 pkt 的切片 —— 上游应答会就地覆盖 pkt，
    /// 若切片指向同一块内存，`@memcpy(pkt[0..qlen], orig[0..qlen])` 会因为
    /// 源目标重叠而 panic（"@memcpy arguments alias"）。
    /// 定长即可覆盖整个问题区：12 字节头 + 最长 255 字节名字 + 4 字节类型/类。
    original: [ORIG_MAX]u8 = [_]u8{0} ** ORIG_MAX,
    /// original 中的有效长度（0 表示未保存）
    orig_len: usize = 0,
};

/// 保存原始查询所需的最大长度（头 12 + 名字 255 + qtype/qclass 4）
pub const ORIG_MAX: usize = 12 + 255 + 4;

/// 对应 C 版 frec 里保存原始报文的那一步：把 [0..qlen) 拷进 frec 自带缓冲
pub fn saveOriginal(fr: *Frec, pkt: []const u8, qlen: usize) void {
    const n = @min(qlen, ORIG_MAX);
    @memcpy(fr.original[0..n], pkt[0..n]);
    fr.orig_len = n;
}

pub const ForwardResult = struct {
    /// 应答报文长度（0 表示没有可用应答）
    len: usize = 0,
    /// 是否来自截断后的 TCP 重试
    via_tcp: bool = false,
    /// 上游 rcode
    rcode: u8 = protocol.NOERROR,
    /// 承载应答的服务器
    server: ?*Server = null,
};

// ---------------------------------------------------------------------------
// 事务 ID（对应 forward.c: get_id()）
// ---------------------------------------------------------------------------
/// 对应 get_id()：随机 txid。
/// C 版会顺便把「最近用过的 id」记进哈希做冲突规避（`daemon->rand`），
/// 这里直接用 util 的随机数（内部用 Io 提供的加密随机源播种）。
pub fn getId() u16 {
    return util.rand16();
}

// ---------------------------------------------------------------------------
// 上游选择（对应 forward.c 里 filter_servers / lookup_domain 的调用点）
// ---------------------------------------------------------------------------
/// 从域名匹配出的服务器集合中，按 dnsmasq 的规则挑一个：
///   * --all-servers：返回匹配区间里的第一个（不改语义，仅用于上层并行/轮询）
///   * --strict-order：总是取第一个
///   * 否则按「失败次数少、最近有应答」的服务器优先（对应 server 统计的使用）
///   * 已标记 SERV_GOT_TCP / SERV_LOOP 的服务器跳过
pub fn pickServer(d: *Daemon, dn: []const u8, flags: u32) ?*Server {
    const range = domain.filterServers(d, flags, dn);
    if (range.first == range.last) {
        // 没有域名匹配：退化为「默认上游」（domain == null 的那批）
        return pickDefaultServer(d);
    }

    var best: ?*Server = null;
    var best_score: i64 = std.math.minInt(i64);
    var i = range.first;
    while (i < range.last) : (i += 1) {
        const s = d.serverarray.items[i];
        if (s.isLocal()) continue;
        if ((s.flags & (protocol.SERV_LOOP | protocol.SERV_GOT_TCP)) != 0) continue;

        // --strict-order / --all-servers：直接取第一个可用
        if (d.option(protocol.OPT_ORDER) or d.option(protocol.OPT_ALL_SERVERS)) return s;

        // 健康度打分：失败次数越多越差，最近成功应答的加分
        const failed: i64 = @intCast(s.failed_queries.load(.monotonic));
        const retrys: i64 = @intCast(s.retrys.load(.monotonic));
        const last = s.last_reply.load(.monotonic);
        const now = util.dnsmasqTime();
        var score: i64 = -(failed * 4 + retrys);
        if (last != 0 and now - last < @as(i64, @intCast(protocol.FORWARD_TIME))) score += 8;

        if (best == null or score > best_score) {
            best = s;
            best_score = score;
        }
    }
    return best;
}

/// 默认上游：serverarray 里 domain == null 的服务器（对应 filter_servers 返回 0 长度时的回退）
pub fn pickDefaultServer(d: *Daemon) ?*Server {
    var best: ?*Server = null;
    var best_score: i64 = std.math.minInt(i64);
    for (d.serverarray.items) |s| {
        if (s.domain != null) continue;
        if (s.isLocal()) continue;
        if ((s.flags & (protocol.SERV_LOOP | protocol.SERV_GOT_TCP)) != 0) continue;

        if (d.option(protocol.OPT_ORDER) or d.option(protocol.OPT_ALL_SERVERS)) return s;

        const failed: i64 = @intCast(s.failed_queries.load(.monotonic));
        const retrys: i64 = @intCast(s.retrys.load(.monotonic));
        const last = s.last_reply.load(.monotonic);
        const now = util.dnsmasqTime();
        var score: i64 = -(failed * 4 + retrys);
        if (last != 0 and now - last < @as(i64, @intCast(protocol.FORWARD_TIME))) score += 8;

        if (best == null or score > best_score) {
            best = s;
            best_score = score;
        }
    }
    return best;
}

/// 对应 forward.c: domain_no_rebind()：`--rebind-domain-ok` 里登记的域名豁免
/// rebind 检查（即允许这些域解析到私有地址）。
///
/// 逐字对照 C 的匹配算法（forward.c:145-164）：
///   1. 列表域是名字的**标签边界后缀**才算命中：
///      `dlen >= tlen` 且 `hostname_isequal(域, 名字尾 tlen 字节)` 且
///      （长度相等 或 尾巴前面那个字符是 '.'）—— 保证只匹配整标签，
///      "b.com" 不会命中 "ab.com"；
///   2. 空域（tlen==0）匹配**任何不含点**的单标签名字。
///      （本移植的解析器不会产生空域，此条为对齐 C 语义保留。）
pub fn domainNoRebind(d: *Daemon, domain_name: []const u8) bool {
    const dlen = domain_name.len;
    const has_dot = std.mem.indexOfScalar(u8, domain_name, '.') != null;
    for (d.no_rebind.items) |rbd| {
        const tlen = rbd.len;
        if (dlen >= tlen and
            name.hostnameIsEqual(rbd, domain_name[dlen - tlen ..]) and
            (dlen == tlen or domain_name[dlen - tlen - 1] == '.'))
            return true;
        if (tlen == 0 and !has_dot) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// 上游 socket
// ---------------------------------------------------------------------------
fn serverFamily(s: *const Server) u16 {
    return s.addr.store.family;
}

/// 建立一条连到上游的 UDP socket。
/// 使用 connect() 让内核帮我们过滤「源地址非本服务器」的报文，
/// 这等价于 C 版随机端口 + `server_isequal()` 校验的双保险。
///
/// 注意：asyncfwd.zig 的异步引擎会**长期持有**这条 socket（而不是每查询一开一关），
/// 靠 txid 解复用同一条 socket 上的多份在途查询。
pub fn openUpstreamUdp(s: *const Server) ForwardError!net.fd_t {
    const fam = serverFamily(s);
    const fd = net.socketCreate(fam, std.posix.SOCK.DGRAM, std.posix.IPPROTO.UDP) catch
        return error.SocketFailed;
    errdefer net.close(fd);
    net.setReuseAddr(fd) catch {};
    net.connect(fd, &s.addr) catch return error.SocketFailed;
    return fd;
}

/// 建立一条连到上游的 TCP socket 并完成连接（超时为 TCP_TIMEOUT 秒）。
fn openUpstreamTcp(s: *const Server) ForwardError!net.fd_t {
    const fam = serverFamily(s);
    const fd = net.socketCreate(fam, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP) catch
        return error.SocketFailed;
    errdefer net.close(fd);
    net.setNonBlock(fd) catch {};
    net.connect(fd, &s.addr) catch |e| {
        // EINPROGRESS 属于正常情况，后续用 poll 判可写
        if (e != error.WouldBlock and e != error.InProgress) return error.SocketFailed;
    };
    var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.OUT, .revents = 0 }};
    _ = net.poll(&fds, @as(i32, protocol.TCP_TIMEOUT_MS)) catch return error.SocketFailed;
    if ((fds[0].revents & (std.posix.POLL.OUT | std.posix.POLL.ERR | std.posix.POLL.HUP)) == 0)
        return error.Timeout;
    return fd;
}

// ---------------------------------------------------------------------------
// 应答校验（对应 forward.c: reply_query() 里的检查）
// ---------------------------------------------------------------------------
/// 校验上游应答：
///   1. 是应答（QR=1）
///   2. txid 与发出的一致
///   3. qdcount == 1（严格，对应 C 版 reply_query() 开头的丢弃条件）
///   4. 问题区的名字（忽略大小写）、qtype、qclass 与查询一致
fn checkReply(pkt: []u8, n: usize, fr: *const Frec) bool {
    return checkReplyWith(pkt, n, fr, fr.id);
}

/// checkReply 的显式版本：并发查询时每个上游 socket 用各自独立的事务 ID，
/// 因此校验时必须传入「该 socket 期望的 id」，而不能用 fr.id（它只记录最后一个）。
pub fn checkReplyWith(pkt: []u8, n: usize, fr: *const Frec, want_id: u16) bool {
    if (n < protocol.HEADER_SIZE) return false;
    if (!protocol.isResponse(protocol.headerHb3(pkt))) return false;
    if (protocol.headerId(pkt) != want_id) return false;

    // opcode 必须一致
    if (protocol.opcode(protocol.headerHb3(pkt)) != protocol.OPCODE_QUERY) return false;

    // qdcount 必须为 1 —— 严格复刻 C 版 forward.c: reply_query() 开头那一句：
    //     if (n < sizeof(header) || !(header->hb3 & HB3_QR) ||
    //         ntohs(header->qdcount) != 1)
    //       return;                /* 直接丢弃，不进入后续处理 */
    //
    // 这里**曾经**写成「qd != 1 时只靠 txid 判定、仍然接收」，理由是
    // 「有些上游出错时会把 qdcount 置 0」。实机 A/B 证明这是个祸根：
    // 本路由器上游 119.29.29.29 对**存在**名字的 PTR 查询会回 qd=0 的
    // NXDOMAIN+SOA（TTL 86400）。C 把它当坏包丢掉了，Zig 却收下、回给客户端
    // 并写进负缓存 ——
    //   * 客户端拿到 qd=0 的畸形应答（严格解析器直接判错，本项目的对照脚本
    //     就报 PARSE-ERR）；
    //   * 那条 NXDOMAIN 按「名字不存在」缓存后，该名字的 A/AAAA 全部跟着失败。
    // 对齐 C 后，这类应答在源头就被挡掉，层叠在 extractAddresses 里的 PTR
    // 防护（见 rfc1035.zig 的 nxdomain_cacheable）成为第二道防线。
    if (protocol.qdcount(pkt) != 1) return false;

    var p: usize = protocol.HEADER_SIZE;
    var namebuf: [rfc1035.MAXNAMEBUF]u8 = undefined;
    if (name.extractName(pkt, n, &p, &namebuf, name.EXTR_NAME_EXTRACT, 4) == 0) return false;
    if (!name.hostnameIsEqual(std.mem.sliceTo(&namebuf, 0), fr.qname)) return false;
    if (p + 4 > n) return false;
    if (protocol.getShort(pkt, p) != fr.qtype) return false;
    if (protocol.getShort(pkt, p + 2) != fr.qclass) return false;
    return true;
}

// ---------------------------------------------------------------------------
// process_reply 的核心部分（对应 forward.c: process_reply()）
// ---------------------------------------------------------------------------
/// 对上游应答做后处理 + 写缓存。返回 true 表示该应答可以返回给客户端。
pub fn processReply(
    d: *Daemon,
    fr: *Frec,
    pkt: []u8,
    n: usize,
    now: i64,
    no_cache: bool,
) bool {
    if (n < protocol.HEADER_SIZE) return false;

    // fr.server 为 null 时这里会**在写缓存之前**直接返回，而且没有任何报错 ——
    // 症状是「客户端拿到的应答完全正确，但缓存永远是空的」。
    // 异步引擎曾经漏掉 `p.fr.server = srv`，正是踩了这个坑；加一条显式告警，
    // 让同类错误下次第一时间暴露，而不是靠数上游包数量才发现。
    const srv = fr.server orelse {
        log.warning("processReply: fr.server 为空，应答不回写缓存（调用方漏赋值？）: {s}", .{fr.qname});
        return true;
    };
    const rcode = protocol.rcode(protocol.headerHb4(pkt));

    // 1) EDNS0 伪头部处理（对应 process_reply 里 find_pseudoheader 那段）
    const ph = rfc1035.findPseudoheader(pkt, n);
    if (ph.found) {
        // 扩展 rcode
        const full_rcode = rcode | (ph.ext_rcode << 4);
        if (!ph.is_sign) {
            if (fr.added_pheader) {
                // 客户端本来没发 EDNS0，是我们补的 -> 剥掉再还回去
                var new_n = n;
                _ = rfc1035.rrfilter(pkt, &new_n, .edns0);
            } else {
                // 把我们的接收能力告知客户端（对应 PUTSHORT(daemon->edns_pktsz, sizep)）
                protocol.putShort(pkt, ph.udp_size_off, d.edns_pktsz);
            }
        }
        _ = full_rcode;
    }

    // 2) RFC 4035 §4.6：非 DNSSEC 验证场景一律清 AD 位
    const hb4 = pkt[protocol.OFF_HB4];
    pkt[protocol.OFF_HB4] = hb4 & ~protocol.HB4_AD;

    // 3) 上游不做递归时告警（对应 SERV_WARNED_RECURSIVE）
    if ((hb4 & protocol.HB4_RA) == 0 and rcode == protocol.NOERROR) {
        var buf: [128]u8 = undefined;
        log.warning("上游 {s} 拒绝递归查询（无 RA 位）", .{srv.addrText(&buf)});
    }

    // 4) 给客户端置 RA 位：对应 header->hb4 |= HB4_RA
    pkt[protocol.OFF_HB4] |= protocol.HB4_RA;

    if (protocol.opcode(protocol.headerHb3(pkt)) != protocol.OPCODE_QUERY) return true;

    // 5) 非 NOERROR/NXDOMAIN 的 rcode（SERVFAIL/REFUSED/...）不缓存，原样回传
    if (rcode != protocol.NOERROR and rcode != protocol.NXDOMAIN) {
        const a = addr.AllAddr{ .log = .{ .rcode = rcode } };
        log.logQuery(protocol.F_UPSTREAM | protocol.F_RCODE, "error", a, null, 0);
        return true;
    }

    // 5b) 本地已知的名字被转发后拿到 NXDOMAIN -> 改写成 NODATA（并置 AA）。
    //
    // 严格对应 forward.c:794-804：
    //     if (rcode == NXDOMAIN && extract_name(...) &&
    //         (check_for_local_domain(name, now) ||
    //          lookup_domain(name, F_CONFIG, NULL, NULL)))
    //       { header->hb3 |= HB3_AA; SET_RCODE(header, NOERROR); cache_secure = 0; }
    // 原注释：if we forwarded a query for a locally known name (because it was
    //   for an unknown type) and the answer is NXDOMAIN, convert that to NODATA,
    //   since we know that the domain exists, even if upstream doesn't
    //
    // 为什么这类查询会被转发：像 `localhost MX`、hosts 里主机名的 TXT 查询，
    // 本地只有地址记录，answer_request() 里类型不匹配、不认账，于是转上游。
    // 而各上游对 `localhost`/`ip6-localhost` 这种名字态度并不一致 —— 实测
    // 1.0.0.1 回 NXDOMAIN，61.139.2.69/223.5.5.5/119.29.29.29 回 NODATA；
    // 对 ip6-localhost 更是四家全回 NXDOMAIN。若不改写，客户端就会得到
    // 「localhost 这个名字不存在」的错误结论（本项目的实机 A/B 就抓到 19 组）。
    //
    // 必须放在 extractAddresses 之前：改写后 rcode 已是 NOERROR，负缓存那段
    // 会把它当 NODATA（且只对 A/AAAA 生效）而不会写成 NXDOMAIN —— 否则一个
    // MX 查询就能把整个名字按「不存在」缓存下来。
    if (rcode == protocol.NXDOMAIN) {
        var np: usize = protocol.HEADER_SIZE;
        var nmbuf: [rfc1035.MAXNAMEBUF]u8 = undefined;
        if (name.extractName(pkt, n, &np, &nmbuf, name.EXTR_NAME_EXTRACT, 0) != 0) {
            const nm = std.mem.sliceTo(&nmbuf, 0);
            // check_for_local_domain 要读缓存哈希表（cache_find_non_terminal），
            // 必须持缓存锁。
            d.cache.lock(d.io);
            const local_known = domain.checkForLocalDomain(d, nm);
            d.cache.unlock(d.io);

            // 第二项对应 C 的 lookup_domain(name, F_CONFIG, NULL, NULL)：该名字落在
            // 某个「返回本地 RR」的配置域里（server=/dom/ip、address=/dom/ip 等）。
            // 注意不能直接用 zig 的 lookupDomain() —— 它在域名不匹配时会回退到
            // **默认上游**（matchEmpty），对任何名字都非空，会让改写条件恒真。
            // filterServers(F_CONFIG) 会按「组内存在 SERV_LOCAL_ADDRESS」收窄，
            // 默认上游组不含该标志，因而正确地返回空区间。
            const cfg = domain.filterServers(d, protocol.F_CONFIG, nm);

            if (local_known or cfg.first != cfg.last) {
                pkt[protocol.OFF_HB3] |= protocol.HB3_AA;
                protocol.setRcode(&pkt[protocol.OFF_HB4], protocol.NOERROR);
                log.logQuery(protocol.F_UPSTREAM | protocol.F_NOERR, nm, null, null, fr.qtype);
            }
        }
    }

    // 5c) --alias：把上游返回的 A 记录按掩码改写。对应 forward.c:806
    //     `if (daemon->doctors && do_doctor(header, n, daemon->namebuff)) cache_secure = 0;`
    //     必须放在 extractAddresses 之前 —— 改写后的地址才是写进缓存、发给客户端的内容。
    if (d.doctors.items.len != 0) {
        if (rfc1035.doDoctor(d, pkt, n))
            log.debug("--alias 改写了上游应答里的地址: {s}", .{fr.qname});
    }

    const truncated = (protocol.headerHb3(pkt) & protocol.HB3_TC) != 0;
    if (truncated) {
        // 截断应答不缓存，交给上层走 TCP 重试
        log.logQuery(protocol.F_UPSTREAM, "", null, "truncated", 0);
        return true;
    }

    if (no_cache) return true;

    // 6) --stop-dns-rebind：应答里出现私有地址且不是本地区段时整包丢弃
    if (d.option(protocol.OPT_NO_REBIND) or d.option(protocol.OPT_LOCAL_REBIND)) {
        if (checkRebind(d, pkt, n)) {
            log.warning("丢弃可疑应答（stop-dns-rebind）: {s}", .{fr.qname});
            return false;
        }
    }

    // 7) 写缓存（对应 extract_addresses）
    var namebuf: [rfc1035.MAXNAMEBUF]u8 = undefined;
    var res = rfc1035.extractAddresses(d, pkt, n, now, fr.qname, fr.qtype, fr.qclass, &namebuf);

    // 日志：把解析出的地址按 dnsmasq 的格式打出来
    if (res.cached == 0 and res.nxdomain) {
        log.logQuery(protocol.F_UPSTREAM | protocol.F_NEG | protocol.F_NXDOMAIN, fr.qname, null, null, fr.qtype);
    }
    _ = &res;

    return true;
}

/// 对应 forward.c: domain_no_rebind() 的实际使用处：
/// 应答的 A/AAAA 里出现 RFC1918 / 链路本地等私有地址时视为 rebind 攻击。
fn checkRebind(d: *Daemon, pkt: []u8, n: usize) bool {
    const qend = name.skipQuestions(pkt, n) orelse return false;

    // 名字属于本地区段（--rebind-domain-ok / local 域）则放行
    var namebuf: [rfc1035.MAXNAMEBUF]u8 = undefined;
    var p: usize = protocol.HEADER_SIZE;
    if (name.extractName(pkt, n, &p, &namebuf, name.EXTR_NAME_EXTRACT, 4) != 0) {
        const nm = std.mem.sliceTo(&namebuf, 0);
        if (domain.lookupDomain(d, nm, protocol.F_CONFIG)) |s| {
            if (s.isLocal()) return false;
        }
        if (domainNoRebind(d, nm)) return false;
    }

    var off = qend;
    var i: usize = 0;
    const total = @as(usize, protocol.ancount(pkt)) + @as(usize, protocol.nscount(pkt));
    while (i < total) : (i += 1) {
        if (off >= n) break;
        if (name.extractName(pkt, n, &off, &namebuf, name.EXTR_NAME_EXTRACT, 4) == 0) break;
        if (off + 10 > n) break;
        const rr_type = protocol.getShort(pkt, off);
        const rdlen = protocol.getShort(pkt, off + 8);
        off += 10;
        if (off + rdlen > n) break;

        if (rr_type == protocol.T_A and rdlen == 4) {
            const v: u32 = @bitCast(pkt[off..][0..4].*);
            // 对应 forward.c 里 private_net(addr, 1)：回环/本网段也算
            if (addr.privateNet(v, true)) return true;
        } else if (rr_type == protocol.T_AAAA and rdlen == 16) {
            const v = pkt[off..][0..16].*;
            if (addr.privateNet6(&v, true)) return true;
        }
        off += rdlen;
    }
    return false;
}

// ---------------------------------------------------------------------------
// 单次上游交互
// ---------------------------------------------------------------------------
/// 向一个上游服务器发查询并等应答（UDP）。
/// 返回应答长度；`pkt` 原地被应答覆盖。
fn queryOneServerUdp(
    d: *Daemon,
    fr: *Frec,
    srv: *Server,
    pkt: []u8,
    timeout_ms: i32,
) ForwardError!usize {
    const fd = try openUpstreamUdp(srv);
    defer net.close(fd);

    // 每次查询用新的 txid（对应 frec->new_id = get_id()）
    fr.id = getId();
    protocol.setId(pkt, fr.id);
    fr.server = srv;

    _ = srv.queries.fetchAdd(1, .monotonic);

    // 发送
    var sent_total: usize = 0;
    while (sent_total < fr.len) {
        const w = net.sendto(fd, pkt[sent_total..fr.len], &srv.addr, 0) catch {
            _ = srv.failed_queries.fetchAdd(1, .monotonic);
            return error.SendFailed;
        };
        if (w == 0) {
            _ = srv.failed_queries.fetchAdd(1, .monotonic);
            return error.SendFailed;
        }
        sent_total += w;
    }

    // 日志：forwarded <name> to <server>
    var srvbuf: [128]u8 = undefined;
    log.logQuery(protocol.F_SERVER, fr.qname, null, srv.addrText(&srvbuf), fr.qtype);

    // 等应答：可能收到多份（伪造 / 重复），只接受通过校验的那一份
    const deadline = util.monoMillis() + timeout_ms;
    while (true) {
        const remain = deadline - util.monoMillis();
        if (remain <= 0) {
            _ = srv.failed_queries.fetchAdd(1, .monotonic);
            return error.Timeout;
        }
        var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
        const ready = net.poll(&fds, @intCast(@min(remain, 1000))) catch continue;
        if (ready == 0) continue;

        var from = SockAddr{ .store = .{ .family = 0 }, .len = 0 };
        const n = net.recvfrom(fd, pkt, &from, 0) catch continue;
        if (n == 0) continue;

        if (!checkReply(pkt, n, fr)) {
            log.debug("丢弃不匹配的上游应答（txid/问题区不符），来自 {s}", .{fr.qname});
            continue;
        }
        _ = srv.last_reply.store(util.dnsmasqTime(), .monotonic);
        return n;
    }
    _ = d;
}

/// TCP 重试（对应 forward.c: tcp_from_udp()）：
/// 截断应答时把 2 字节长度前缀 + 报文发给上游，再读回长度前缀 + 应答。
///
/// 这是**阻塞**实现；异步引擎在遇到 TC 位时把它扔给一个一次性线程执行，
/// 从而不让引擎的事件循环停在这里。
pub fn queryOneServerTcp(
    d: *Daemon,
    fr: *Frec,
    srv: *Server,
    pkt: []u8,
    timeout_ms: i32,
) ForwardError!usize {
    _ = d;
    const fd = try openUpstreamTcp(srv);
    defer net.close(fd);

    // 发：2 字节大端长度 + 报文
    var hdr: [2]u8 = undefined;
    protocol.putShort(&hdr, 0, @intCast(fr.len));
    var iov_ok = true;
    net.writeAll(fd, &hdr) catch {
        iov_ok = false;
    };
    if (iov_ok) net.writeAll(fd, pkt[0..fr.len]) catch {
        iov_ok = false;
    };
    if (!iov_ok) {
        _ = srv.failed_queries.fetchAdd(1, .monotonic);
        return error.SendFailed;
    }

    // 读：2 字节长度 + 应答
    const deadline = util.monoMillis() + timeout_ms;
    if (!waitReadable(fd, deadline)) return error.Timeout;

    var lenbuf: [2]u8 = undefined;
    if (!readExactly(fd, &lenbuf, deadline)) return error.BadReply;
    const rlen = protocol.getShort(&lenbuf, 0);
    if (rlen < protocol.HEADER_SIZE or rlen > pkt.len) return error.BadReply;
    if (!readExactly(fd, pkt[0..rlen], deadline)) return error.BadReply;

    if (!checkReply(pkt, rlen, fr)) return error.BadReply;
    _ = srv.last_reply.store(util.dnsmasqTime(), .monotonic);
    return rlen;
}

fn waitReadable(fd: net.fd_t, deadline_ms: i64) bool {
    while (true) {
        const remain = deadline_ms - util.monoMillis();
        if (remain <= 0) return false;
        var fds = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
        const r = net.poll(&fds, @intCast(@min(remain, 1000))) catch continue;
        if (r > 0) return true;
    }
}

fn readExactly(fd: net.fd_t, buf: []u8, deadline_ms: i64) bool {
    var got: usize = 0;
    while (got < buf.len) {
        if (!waitReadable(fd, deadline_ms)) return false;
        const n = net.recv(fd, buf[got..], 0) catch return false;
        if (n == 0) return false;
        got += n;
    }
    return true;
}

// ---------------------------------------------------------------------------
// 对外主入口
// ---------------------------------------------------------------------------
/// 完整的一次转发：选服务器 -> 发查询 -> 等应答 -> 后处理；失败则换服务器重试。
///
/// * `pkt` 必须是可写缓冲，前半部分是客户端原始查询（长度 `qlen`），
///   整个缓冲用于接收上游应答（大小应 >= packet buffer）。
/// * 返回 `.len == 0` 表示所有上游都失败，调用者应回 SERVFAIL。
pub fn forwardQuery(
    d: *Daemon,
    pkt: []u8,
    qlen: usize,
    fr: *Frec,
    now: i64,
) ForwardResult {
    const result = forwardQueryInner(d, pkt, qlen, fr, now);

    // 对应 forward.c:585 —— 发回客户端之前必须把 id 还原成客户端原始查询的 id。
    // 上游看到的是我们随机生成的 new_id（forward.c:388-390），
    // 若原样回给客户端，任何正经解析器都会因为 id 不匹配而丢弃这个应答。
    if (result.len != 0) restoreClientId(pkt, fr);

    return result;
}

/// 还原客户端原始事务 id（存在 fr.original 的头两个字节里）
pub fn restoreClientId(pkt: []u8, fr: *const Frec) void {
    if (fr.orig_len >= 2) {
        protocol.setId(pkt, protocol.getShort(fr.original[0..], protocol.OFF_ID));
    }
}

/// 一次转发查询的完整「选路计划」。
///
/// 同步阻塞路径（forwardQueryInner）与异步事件循环（asyncfwd.zig）共用这段
/// 逻辑，保证两种执行模型下的候选收集、sticky 提权、并发度与超时预算完全一致 ——
/// 否则 A/B 对比看到的差异会来自选路而不是并发模型，量出来的数字没有意义。
pub const Candidates = struct {
    list: [protocol.MAX_FORWARD_CANDIDATES]*Server = undefined,
    n: usize = 0,
    /// filter_servers 得到的区间起点（noteWinner 需要）
    master_idx: usize = 0,
    /// 本组是否处于「全发」周期
    forward_all: bool = false,
    /// 允许的并发度
    conc: usize = 1,
    /// 单台上游单次等待上限（--fast-dns-retry；0 表示第一台吃满总预算）
    per_try_ms: i32 = 0,
    /// 总预算
    budget_ms: i32 = 0,
    /// 阶梯式对冲间隔
    hedge_ms: i32 = 0,
};

/// 选路：定位候选区间 -> 收集排序 -> sticky 提权 -> 决定并发度与超时预算。
///
/// 注意 `shouldForwardAll()` 会推进 master 的 forwardcount/forwardtime，
/// 因此**每个查询只能调用本函数一次**（重复调用会把「全发」周期提前用完）。
/// 「没有可用的上游服务器」的日志窗口（秒）。详见 logNoUpstream 的说明。
const NO_UPSTREAM_LOG_SECS: i64 = 30;

var no_upstream_since: i64 = 0;
var no_upstream_dropped: u32 = 0;

/// 报告「没有可用的上游服务器」，**带限流**。
///
/// 这条告警是**按查询**触发的。上游全挂（典型就是开机早于 netifd 把 WAN
/// 拉起来）时，它会在几秒内写满 logd 的 ring buffer —— 实测日志 628 行里
/// 525 行（84%）都是它，把同一时刻其它服务的启动日志**全部冲掉**，等于亲手
/// 毁掉排障线索（本次就是因为刷屏而看不到 odhcpd 的启动记录）。
///
/// 对照 C dnsmasq（dnsmasq.c:1831）：它只在 poll_resolv 里记**一次**
/// `no servers found in %s, will retry`，然后靠轮询重试，从不按查询刷。
/// 这里保留域名信息（排查有用）但限制成每个窗口最多一条，窗口结束时补报
/// 被压掉了多少条，既不丢信息也不冲日志。
fn logNoUpstream(qname: []const u8) void {
    const now = util.dnsmasqTime();
    if (no_upstream_since != 0 and now - no_upstream_since < NO_UPSTREAM_LOG_SECS) {
        no_upstream_dropped += 1;
        return;
    }
    if (no_upstream_since != 0 and no_upstream_dropped > 0) {
        log.warning("（另有 {d} 条「无可用上游」告警已按 {d}s 限流丢弃）", .{
            no_upstream_dropped, NO_UPSTREAM_LOG_SECS,
        });
    }
    no_upstream_since = now;
    no_upstream_dropped = 0;
    log.warning("没有可用的上游服务器，无法转发 {s}（将持续重试上游列表）", .{qname});
}

pub fn pickCandidates(d: *Daemon, fr: *Frec) Candidates {
    var c = Candidates{};

    var range = domain.filterServers(d, fr.flags, fr.qname);
    if (range.first == range.last) range = defaultServerRange(d);
    if (range.first == range.last) {
        // 限流后输出 —— 不要改回直接 log.warning，理由见 logNoUpstream 的注释
        logNoUpstream(fr.qname);
        return c;
    }
    c.master_idx = range.first;

    const now_ms = util.monoMillis();
    var cand: [protocol.MAX_FORWARD_CANDIDATES]*Server = undefined;
    const picked = balancer.collect(d, range.first, range.last, now_ms, &cand);
    if (picked.n == 0) {
        log.warning("上游候选全部不可用（local/TCP-only），无法转发 {s}", .{fr.qname});
        return c;
    }
    const list = picked.usable(&cand);
    c.n = @min(list.len, protocol.MAX_FORWARD_CANDIDATES);
    @memcpy(c.list[0..c.n], list[0..c.n]);

    if (d.balance_mode == .sticky) reorderSticky(d, range.first, c.list[0..c.n]);

    c.forward_all = shouldForwardAll(d, range.first, util.dnsmasqTime());
    c.conc = planConcurrency(d, c.n, c.forward_all);

    // 超时预算（语义见原来 forwardQueryInner 里的长注释）：
    // TIMEOUT 是「一次查询的总预算」，fast_retry_ms 是「单台上游的等待上限」。
    c.budget_ms = @intCast(protocol.TIMEOUT * 1000);
    c.per_try_ms = if (d.fast_retry_ms > 0) d.fast_retry_ms else c.budget_ms;
    c.hedge_ms = d.hedge_ms;

    return c;
}

/// forwardQuery 的实际实现（返回值里的 id 尚未还原，见上面的包装函数）
fn forwardQueryInner(
    d: *Daemon,
    pkt: []u8,
    qlen: usize,
    fr: *Frec,
    now: i64,
) ForwardResult {
    var result = ForwardResult{};

    // ---- 1~4. 选路（与异步引擎共用同一份实现）----
    var plan = pickCandidates(d, fr);
    if (plan.n == 0) return result;
    const list = plan.list[0..plan.n];
    const max_conc = plan.conc;
    const per_try_ms = plan.per_try_ms;
    const total_budget_ms = plan.budget_ms;

    if (max_conc > 1 and list.len > 1) {
        // ---- 5a. 多上游并发竞速 ----
        const race = raceServers(d, fr, list, pkt, total_budget_ms, max_conc, plan.hedge_ms);
        if (race.len != 0) {
            finishWithWinner(d, fr, pkt, race.len, race.winner.?, race.rtt_us, false, now, &result);
        } else if (race.refused_len != 0) {
            // 所有应答都是 REFUSED：仍然把最后一份还给客户端（对应 C 版
            // forward.c:1271 —— forwardall 用尽后 REFUSED 也算回答）
            finishWithWinner(d, fr, pkt, race.refused_len, race.refused_from.?, race.rtt_us, true, now, &result);
        }
        return result;
    }

    // ---- 5b. 串行尝试 ----
    // 每台只等 per_try_ms 就给下一台机会，整体不超过 total_budget_ms。
    // 这正是 dnsmasq --fast-dns-retry 的语义（forward.c:628 的 fast_retry()：
    // 每 forward_delay 毫秒把还没答复的 frec 重发一次，直到 fast_retry_timeout）。
    const master_idx = plan.master_idx;
    const deadline_ms = util.monoMillis() + total_budget_ms;
    var i: usize = 0;
    while (i < list.len) : (i += 1) {
        const srv = list[i];
        if (i != 0) _ = srv.retrys.fetchAdd(1, .monotonic);

        // 剩余总预算不足时不再开新的一台
        const remain = deadline_ms - util.monoMillis();
        if (remain <= 0) break;
        const try_ms: i32 = @intCast(@min(@as(i64, per_try_ms), remain));

        restoreQuery(pkt, fr, qlen);

        // 在途计数必须在串行路径上也维护：
        //   * in_flight 是 dynamic 打分的核心项（(在途+1)×EWMA）
        //   * beginQuery 顺带记下 probe_seq —— 探索预算靠它判断「这台被冷落了多久」
        // 早先只在并发竞速路径调了这两个函数，于是串行模式下 in_flight 恒为 0、
        // probe_seq 恒为 0，所有上游的打分同时变成 0，排序退化成「按配置顺序」，
        // 表现为第一台上游吃掉 100% 流量、且永远不重适应。
        balancer.beginQuery(srv);
        const sent_at_us = util.monoMicros();
        const n = queryOneServerUdp(d, fr, srv, pkt, try_ms) catch |e| {
            balancer.endQuery(srv);
            balancer.onFailure(srv, d.server_cooldown_ms, util.monoMillis());
            log.debug("上游查询失败({s})，尝试下一个", .{@errorName(e)});
            continue;
        };
        balancer.endQuery(srv);
        const rtt_us: u64 = @intCast(@max(@as(i64, 0), util.monoMicros() - sent_at_us));

        // 截断 -> 走 TCP 重试（对应 forward.c: tcp_from_udp）
        if ((protocol.headerHb3(pkt) & protocol.HB3_TC) != 0) {
            // 与异步路径 fwdengine.zig:switchToTcp 保持完全一致（级别 + 域名）：
            // 同一个事件在两条路径上不能一个 notice 一个 info，否则按级别过滤
            // 日志时同一件事时有时无；域名是排查的关键线索（哪个上游/哪个域名
            // 的大应答需要走 TCP），早先这里缺参数，查日志只能看到一句干巴巴的
            // 「上游应答被截断」。
            // 降为 debug：TC 截断后走 TCP 重试属正常流程（大应答必经），
            // 默认级别下不再记录；需排查时把 log.level 调到 debug。
            log.debug("上游应答被截断，改用 TCP 重试: {s}", .{fr.qname});
            const tcp_len = queryOneServerTcp(d, fr, srv, pkt, @as(i32, protocol.TCP_TIMEOUT_MS) * 2) catch {
                // TCP 也失败：把截断的 UDP 应答原样给客户端（标准行为）
                balancer.onSuccess(srv, rtt_us, util.monoMillis());
                result.len = n;
                result.server = srv;
                result.rcode = protocol.rcode(protocol.headerHb4(pkt));
                noteWinner(d, master_idx, srv, result.rcode);
                return result;
            };
            if (processReply(d, fr, pkt, tcp_len, now, false)) {
                balancer.onSuccess(srv, rtt_us, util.monoMillis());
                result.len = tcp_len;
                result.server = srv;
                result.via_tcp = true;
                result.rcode = protocol.rcode(protocol.headerHb4(pkt));
                noteWinner(d, master_idx, srv, result.rcode);
            }
            return result;
        }

        // UDP 收到合法应答即视为该上游健康（即使 rcode 是 SERVFAIL/NXDOMAIN）
        balancer.onSuccess(srv, rtt_us, util.monoMillis());
        if (processReply(d, fr, pkt, n, now, false)) {
            result.len = n;
            result.server = srv;
            result.rcode = protocol.rcode(protocol.headerHb4(pkt));
            noteWinner(d, master_idx, srv, result.rcode);
        }
        return result;
    }

    return result;
}

/// 默认上游在 serverarray 里的区间：domain == null 的那批。
/// 对应 C 版 filter_servers() 在无域名匹配时的行为（取 F_DOMAINSRV 之外的那组）。
fn defaultServerRange(d: *Daemon) domain.ServerRange {
    const arr = d.serverarray.items;
    var lo: usize = arr.len;
    var hi: usize = 0;
    for (arr, 0..) |s, i| {
        if (s.domain != null) continue;
        if (i < lo) lo = i;
        hi = i + 1;
    }
    if (lo >= hi) return .{ .first = arr.len, .last = arr.len };
    return .{ .first = lo, .last = hi };
}

/// 对应 forward.c:427-436 —— 判断本次是否要「全发」：
///   * --all-servers：永远全发
///   * --strict-order：从不全发（只发排序最前的那台）
///   * 否则：每 FORWARD_TEST 次查询、或距上次全发超过 FORWARD_TIME 秒、
///     或还不知道哪台好（last_server == -1）时，全发一轮做健康复检。
///
/// 只有 sticky 策略沿用 dnsmasq 的原生语义；其它策略下是否并发由
/// planConcurrency() 决定（动态均衡默认单发，靠选路分散流量）。
fn shouldForwardAll(d: *Daemon, master_idx: usize, now: i64) bool {
    if (d.balance_mode != .sticky) return d.option(protocol.OPT_ALL_SERVERS);
    if (d.option(protocol.OPT_ALL_SERVERS)) return true;
    if (d.option(protocol.OPT_ORDER)) return false;
    if (master_idx >= d.serverarray.items.len) return false;

    const master = d.serverarray.items[master_idx];
    const fc = master.forwardcount.fetchAdd(1, .monotonic);
    const ft = master.forwardtime.load(.monotonic);
    if (fc > protocol.FORWARD_TEST or
        now - ft > @as(i64, @intCast(protocol.FORWARD_TIME)) or
        master.last_server.load(.monotonic) < 0)
    {
        master.forwardtime.store(now, .monotonic);
        master.forwardcount.store(0, .monotonic);
        return true;
    }
    return false;
}

/// 本次允许的并发上游数（本移植扩展语义）：
///   * 全发（--all-servers，或 sticky 的周期性探测）-> 候选里能并发的全部
///   * --concurrent-servers=<n> -> 上限 n（0 表示不限制）
///   * --hedge-after=<ms> -> 至少允许补发到 3 台（阶梯式对冲）
/// 最终被 MAX_CONCURRENT_UPSTREAMS 与候选数封顶。
fn planConcurrency(d: *Daemon, list_len: usize, forward_all: bool) usize {
    const allowed = @min(list_len, protocol.MAX_CONCURRENT_UPSTREAMS);
    if (allowed <= 1) return allowed;

    var n: usize = 1;
    if (forward_all) n = allowed;
    if (d.hedge_ms > 0 and n < 2) n = @min(@as(usize, 3), allowed);
    if (d.concurrent_servers > 0) n = @min(d.concurrent_servers, allowed);
    return @max(@as(usize, 1), @min(n, allowed));
}

/// sticky 策略：把本组最近成功应答的那台（master.last_server）提到候选最前。
fn reorderSticky(d: *Daemon, master_idx: usize, list: []*Server) void {
    if (master_idx >= d.serverarray.items.len) return;
    const master = d.serverarray.items[master_idx];
    const idx = master.last_server.load(.monotonic);
    if (idx < 0) return;
    const want: usize = @intCast(idx);
    for (list, 0..) |s, i| {
        if (s.arrayposn == want) {
            if (i != 0) std.mem.rotate(*Server, list, i);
            return;
        }
    }
}

/// 对应 forward.c:1227-1230 —— 记住「刚应答的那台」（非 REFUSED），
/// 若它 REFUSED 过则把它忘掉（置 -1）。
pub fn noteWinner(d: *Daemon, master_idx: usize, winner: *Server, rcode: u8) void {
    // 「胜出」计数放在这里而不是竞速路径里：串行模式下同样该被统计，
    // 否则 SIGUSR1 的 wins 列永远显示 0，看起来像均衡器没在工作。
    if (rcode != protocol.REFUSED) {
        _ = winner.concurrent_wins.fetchAdd(1, .monotonic);
    }

    if (master_idx >= d.serverarray.items.len) return;
    const master = d.serverarray.items[master_idx];
    const pos: i32 = @intCast(winner.arrayposn);
    if (rcode != protocol.REFUSED) {
        master.last_server.store(pos, .monotonic);
    } else if (master.last_server.load(.monotonic) == pos) {
        master.last_server.store(-1, .monotonic);
    }
}

/// 竞速结果
const RaceOutcome = struct {
    /// 有效应答长度（0 表示没有）
    len: usize = 0,
    winner: ?*Server = null,
    rtt_us: u64 = 0,
    /// 收到的最后一份 REFUSED 应答（作为兜底）
    refused_len: usize = 0,
    refused_from: ?*Server = null,
};

/// 多上游并发竞速：把查询同时（或按 `hedge_ms` 阶梯式）发给多台上游，
/// 用 poll 一起等，取**最先通过校验的有效应答**。
///
/// 对应 dnsmasq 的 forwardall 机制（forward.c:511-570）—— dnsmasq 是单线程
/// 事件循环，把查询发给多台后「先回来的先处理」是天然行为；本移植是线程池 +
/// 每查询一线程，因此必须在线程内用 poll 把多个上游 socket 一起等。
///
/// REFUSED 特例：只要还有候选没发、或还有别的上游在等，就继续等而不是立刻采用
/// （对应 forward.c:1271 对 REFUSED 的处理）。
fn raceServers(
    d: *Daemon,
    fr: *Frec,
    list: []*Server,
    pkt: []u8,
    budget_ms: i32,
    max_conc: usize,
    hedge_ms: i32,
) RaceOutcome {
    var out = RaceOutcome{};

    var socks: [protocol.MAX_CONCURRENT_UPSTREAMS]net.fd_t = [_]net.fd_t{-1} ** protocol.MAX_CONCURRENT_UPSTREAMS;
    var ids: [protocol.MAX_CONCURRENT_UPSTREAMS]u16 = [_]u16{0} ** protocol.MAX_CONCURRENT_UPSTREAMS;
    var owners: [protocol.MAX_CONCURRENT_UPSTREAMS]*Server = undefined;
    var sent_at: [protocol.MAX_CONCURRENT_UPSTREAMS]i64 = [_]i64{0} ** protocol.MAX_CONCURRENT_UPSTREAMS;

    var qbuf: [protocol.PACKET_BUFF_SZ]u8 = undefined;
    var rx: [protocol.PACKET_BUFF_SZ]u8 = undefined;

    // 用保存下来的原始查询构造发包（不能直接用 pkt：它会用来接收应答）
    const qlen = @min(fr.qlen, fr.orig_len);
    if (qlen < protocol.HEADER_SIZE) return out;

    var nsock: usize = 0; // 当前在等的 socket 数
    var next_idx: usize = 0; // list 中下一个待发送
    var next_send_at: i64 = 0; // hedge：下次允许补发的时刻
    const deadline = util.monoMillis() + budget_ms;
    const conc_cap = @min(max_conc, protocol.MAX_CONCURRENT_UPSTREAMS);

    while (true) {
        // ---- 补发（首次立即发；hedge_ms > 0 时按阶梯间隔补发）----
        while (next_idx < list.len and nsock < conc_cap) {
            const nowms = util.monoMillis();
            if (nsock != 0 and hedge_ms > 0 and nowms < next_send_at) break;

            const srv = list[next_idx];
            next_idx += 1;

            const fd = openUpstreamUdp(srv) catch {
                balancer.onFailure(srv, d.server_cooldown_ms, nowms);
                continue;
            };

            // 每台上游用各自独立的事务 ID
            @memcpy(qbuf[0..qlen], fr.original[0..qlen]);
            const id = getId();
            protocol.setId(&qbuf, id);

            _ = srv.queries.fetchAdd(1, .monotonic);
            balancer.beginQuery(srv);

            var srvbuf: [128]u8 = undefined;
            log.logQuery(protocol.F_SERVER, fr.qname, null, srv.addrText(&srvbuf), fr.qtype);

            var written: usize = 0;
            var ok = true;
            while (written < qlen) {
                const w = net.sendto(fd, qbuf[written..qlen], &srv.addr, 0) catch {
                    ok = false;
                    break;
                };
                if (w == 0) {
                    ok = false;
                    break;
                }
                written += w;
            }
            if (!ok) {
                net.close(fd);
                balancer.endQuery(srv);
                _ = srv.failed_queries.fetchAdd(1, .monotonic);
                balancer.onFailure(srv, d.server_cooldown_ms, nowms);
                continue;
            }

            socks[nsock] = fd;
            ids[nsock] = id;
            owners[nsock] = srv;
            sent_at[nsock] = util.monoMicros();
            nsock += 1;

            if (hedge_ms > 0) next_send_at = util.monoMillis() + hedge_ms;
        }

        if (nsock == 0) break;

        // ---- 计算本次 poll 的等待时间 ----
        const nowms = util.monoMillis();
        var wait = deadline - nowms;
        if (wait <= 0) break;
        if (next_idx < list.len and hedge_ms > 0) {
            const until_hedge = next_send_at - nowms;
            if (until_hedge < wait) wait = until_hedge;
        }
        if (wait <= 0) continue; // 到点该补发了
        if (wait > 1000) wait = 1000;

        var fds: [protocol.MAX_CONCURRENT_UPSTREAMS]std.posix.pollfd = undefined;
        var idxmap: [protocol.MAX_CONCURRENT_UPSTREAMS]usize = undefined;
        var nfds: usize = 0;
        for (socks[0..nsock], 0..) |fd, i| {
            if (fd < 0) continue;
            fds[nfds] = .{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 };
            idxmap[nfds] = i;
            nfds += 1;
        }
        if (nfds == 0) break;

        const ready = net.poll(fds[0..nfds], @intCast(wait)) catch continue;
        if (ready == 0) continue;

        var got = false;
        for (fds[0..nfds], 0..) |f, k| {
            const i = idxmap[k];
            if (socks[i] < 0) continue;

            // 出错/挂断的 socket：该上游本轮出局
            if ((f.revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL)) != 0 and
                (f.revents & std.posix.POLL.IN) == 0)
            {
                _ = owners[i].failed_queries.fetchAdd(1, .monotonic);
                balancer.onFailure(owners[i], d.server_cooldown_ms, util.monoMillis());
                closeSock(&socks, &owners, i);
                continue;
            }
            if ((f.revents & std.posix.POLL.IN) == 0) continue;

            const n = net.recvfrom(socks[i], &rx, null, 0) catch continue;
            if (n == 0) continue;
            if (!checkReplyWith(&rx, n, fr, ids[i])) continue;

            const rtt: u64 = @intCast(@max(@as(i64, 0), util.monoMicros() - sent_at[i]));
            const rcode = protocol.rcode(rx[protocol.OFF_HB4]);

            // REFUSED：如果还有别的上游可用，先记下来继续等
            if (rcode == protocol.REFUSED and (next_idx < list.len or nsock > 1)) {
                if (n <= pkt.len) {
                    @memcpy(pkt[0..n], rx[0..n]);
                    out.refused_len = n;
                    out.refused_from = owners[i];
                    out.rtt_us = rtt;
                }
                _ = owners[i].failed_queries.fetchAdd(1, .monotonic);
                closeSock(&socks, &owners, i);
                continue;
            }

            if (n <= pkt.len) {
                @memcpy(pkt[0..n], rx[0..n]);
                out.len = n;
                out.winner = owners[i];
                out.rtt_us = rtt;
                got = true;
            }
            break;
        }
        if (got) break;
    }

    // 收尾：关闭仍在等待的 socket。若整轮竞速彻底失败（连 REFUSED 都没有），
    // 把已发出的上游都记为失败 —— 否则一台从不回应的上游永远不会熔断。
    const all_failed = out.len == 0 and out.refused_len == 0;
    var i: usize = 0;
    while (i < nsock) : (i += 1) {
        if (socks[i] < 0) continue;
        const srv = owners[i];
        closeSock(&socks, &owners, i);
        if (all_failed) {
            _ = srv.failed_queries.fetchAdd(1, .monotonic);
            balancer.onFailure(srv, d.server_cooldown_ms, util.monoMillis());
        } else if (srv != out.winner) {
            // 只是没跑赢：不算失败，记一次 retry 便于观测
            _ = srv.retrys.fetchAdd(1, .monotonic);
        }
    }
    return out;
}

/// 关闭竞速中的某个 socket：完成在途计数、释放 fd、标记为空位
fn closeSock(socks: []net.fd_t, owners: []*Server, i: usize) void {
    if (socks[i] < 0) return;
    net.close(socks[i]);
    socks[i] = -1;
    balancer.endQuery(owners[i]);
}

/// 竞速成功后的统一收尾：更新上游健康度、写缓存、记 last_server。
/// （把 id 还原成客户端 id 由外层 forwardQuery 负责。）
fn finishWithWinner(
    d: *Daemon,
    fr: *Frec,
    pkt: []u8,
    len: usize,
    winner: *Server,
    rtt_us: u64,
    refused: bool,
    now: i64,
    result: *ForwardResult,
) void {
    const now_ms = util.monoMillis();
    if (refused) {
        balancer.onFailure(winner, d.server_cooldown_ms, now_ms);
    } else {
        balancer.onSuccess(winner, rtt_us, now_ms);
    }

    if (processReply(d, fr, pkt, len, now, false)) {
        result.len = len;
        result.server = winner;
        result.rcode = protocol.rcode(protocol.headerHb4(pkt));
        result.via_tcp = false;
        const r = domain.filterServers(d, fr.flags, fr.qname);
        noteWinner(d, r.first, winner, result.rcode);
    }
}

/// 把 `pkt` 恢复成原始查询报文（长度 qlen，id 由调用者随后覆盖）。
fn restoreQuery(pkt: []u8, fr: *Frec, qlen: usize) void {
    if (fr.orig_len != 0) {
        const n = @min(qlen, fr.orig_len);
        @memcpy(pkt[0..n], fr.original[0..n]);
    }
    fr.len = qlen;
}

const testing = std.testing;

test "pickDefaultServer 选择 domain 为空的服务器" {
    var d = Daemon{ .allocator = testing.allocator };
    defer d.deinit();

    const s1 = try d.newServer();
    s1.domain = try d.allocator.dupe(u8, "example.com");
    s1.addr = SockAddr.fromIp4(@bitCast([4]u8{ 1, 1, 1, 1 }), 53);
    try d.addServer(s1);

    const s2 = try d.newServer();
    s2.addr = SockAddr.fromIp4(@bitCast([4]u8{ 8, 8, 8, 8 }), 53);
    try d.addServer(s2);

    try domain.buildServerArray(&d);

    // 无域名匹配时应落到默认上游（s2）
    const got = pickDefaultServer(&d);
    try testing.expect(got != null);
    try testing.expectEqual(s2, got.?);
}

test "restoreClientId 把上游 id 换回客户端原始 id" {
    // 回归：曾经直接把上游应答原样回给客户端，客户端收到的是我们发给上游的
    // 随机 id，任何正经解析器都会丢弃这个应答。
    var fr = Frec{
        .packet = (&[_]u8{})[0..0],
        .len = 0,
        .qlen = 0,
        .qname = "example.com",
        .qtype = protocol.T_A,
        .qclass = protocol.C_IN,
    };

    var query: [32]u8 = [_]u8{0} ** 32;
    protocol.setId(&query, 0x1234);
    protocol.setQdcount(&query, 1);
    saveOriginal(&fr, &query, 12);
    try testing.expectEqual(@as(usize, 12), fr.orig_len);

    // 上游应答（带着我们伪造的 id）
    var reply: [32]u8 = [_]u8{0} ** 32;
    protocol.setId(&reply, 0xb917);
    restoreClientId(&reply, &fr);
    try testing.expectEqual(@as(u16, 0x1234), protocol.getShort(&reply, protocol.OFF_ID));
}

test "getId 产生随机 txid" {
    util.randInit(0x12345678);
    var seen = std.AutoHashMap(u16, void).init(testing.allocator);
    defer seen.deinit();
    var i: usize = 0;
    while (i < 64) : (i += 1) try seen.put(getId(), {});
    // 64 次里至少有 32 个不同值（随机性下限检查，允许极端巧合）
    try testing.expect(seen.count() > 32);
}

test "checkReply 校验 txid 与问题区" {
    util.randInit(1);
    var pkt: [512]u8 = [_]u8{0} ** 512;
    // 构造一个查询：example.com A IN
    protocol.setQdcount(&pkt, 1);
    var off: usize = 12;
    off += name.doRfc1035Name(pkt[off..], "example.com").?;
    protocol.putShort(&pkt, off, protocol.T_A);
    protocol.putShort(&pkt, off + 2, protocol.C_IN);
    const qlen = off + 4;

    var nmbuf: [rfc1035.MAXNAMEBUF]u8 = undefined;
    var fr = Frec{
        .packet = &pkt,
        .len = qlen,
        .qlen = qlen,
        .source = SockAddr.fromIp4(addr.LOOPBACK_IP4, 12345),
        .qname = "",
        .qtype = protocol.T_A,
        .qclass = protocol.C_IN,
    };
    const nm = std.mem.sliceTo(&nmbuf, 0);
    _ = nm;

    // 把问题区名字解出来做 qname
    var p: usize = 12;
    _ = name.extractName(&pkt, qlen, &p, &nmbuf, name.EXTR_NAME_EXTRACT, 4);
    fr.qname = std.mem.sliceTo(&nmbuf, 0);
    fr.id = 0x1234;
    protocol.setId(&pkt, fr.id);

    // 正确应答（QR 位置 1）
    pkt[2] |= protocol.HB3_QR;
    try testing.expect(checkReply(&pkt, qlen, &fr));

    // txid 不符
    protocol.setId(&pkt, 0x9999);
    try testing.expect(!checkReply(&pkt, qlen, &fr));
    protocol.setId(&pkt, fr.id);

    // 不是应答
    pkt[2] &= ~protocol.HB3_QR;
    try testing.expect(!checkReply(&pkt, qlen, &fr));
    pkt[2] |= protocol.HB3_QR;

    // 问题区名字不符
    var bad = pkt;
    const off2: usize = 12;
    bad[off2] = 3;
    bad[off2 + 1] = 'x';
    bad[off2 + 2] = 'y';
    bad[off2 + 3] = 'z';
    try testing.expect(!checkReply(&bad, qlen, &fr));

    // qdcount != 1 必须直接丢弃（对应 C 版 reply_query() 的 `ntohs(qdcount) != 1 -> return`）。
    // 实机依据：上游 119.29.29.29 对存在名字的 PTR 查询回 qd=0 的 NXDOMAIN+SOA，
    // C 丢掉、Zig 曾经收下并据此污染了正向名字的解析。
    protocol.setQdcount(&pkt, 0);
    try testing.expect(!checkReply(&pkt, qlen, &fr));
    protocol.setQdcount(&pkt, 2);
    try testing.expect(!checkReply(&pkt, qlen, &fr));
    protocol.setQdcount(&pkt, 1);
    try testing.expect(checkReply(&pkt, qlen, &fr));
}

test "domainNoRebind：标签边界后缀匹配 + 大小写不敏感（--rebind-domain-ok）" {
    const alloc = testing.allocator;
    var d = Daemon{ .allocator = alloc };
    defer {
        for (d.no_rebind.items) |s| alloc.free(s);
        d.no_rebind.deinit(alloc);
    }
    for ([_][]const u8{ "internal.example", "a.lan" }) |s|
        try d.no_rebind.append(alloc, try alloc.dupe(u8, s));

    // 命中：自身 / 子域 / 大小写不敏感
    try testing.expect(domainNoRebind(&d, "internal.example"));
    try testing.expect(domainNoRebind(&d, "host.internal.example"));
    try testing.expect(domainNoRebind(&d, "INTERNAL.EXAMPLE"));
    try testing.expect(domainNoRebind(&d, "x.a.lan"));

    // 不命中：只匹配整标签
    try testing.expect(!domainNoRebind(&d, "notinternal.example"));
    try testing.expect(!domainNoRebind(&d, "xa.lan")); // 'a.lan' 的前一字符不是 '.'
    try testing.expect(!domainNoRebind(&d, "internal.example.com"));
    try testing.expect(!domainNoRebind(&d, "example"));
    try testing.expect(!domainNoRebind(&d, "other.org"));

    // 空列表：一律不豁免（= 全部域名都做 rebind 检查）
    var empty = Daemon{ .allocator = alloc };
    try testing.expect(!domainNoRebind(&empty, "anything.example"));
    empty.no_rebind.deinit(alloc);
}

test "private_net 判定用于 rebind 防护" {
    // 与 rfc1035.c: private_net() 的位掩码表逐条对照
    // 10/8、172.16/12、192.168/16、100.64/10、169.254/16 恒为私有
    try testing.expect(addr.privateNet(@bitCast([4]u8{ 10, 0, 0, 1 }), false));
    try testing.expect(addr.privateNet(@bitCast([4]u8{ 172, 16, 0, 1 }), false));
    try testing.expect(addr.privateNet(@bitCast([4]u8{ 192, 168, 1, 1 }), false));
    try testing.expect(addr.privateNet(@bitCast([4]u8{ 100, 64, 0, 1 }), false));
    try testing.expect(addr.privateNet(@bitCast([4]u8{ 169, 254, 1, 1 }), false));
    // 测试网段
    try testing.expect(addr.privateNet(@bitCast([4]u8{ 192, 0, 2, 1 }), false));
    try testing.expect(addr.privateNet(@bitCast([4]u8{ 198, 51, 100, 1 }), false));
    try testing.expect(addr.privateNet(@bitCast([4]u8{ 203, 0, 113, 1 }), false));
    try testing.expect(addr.privateNet(@bitCast([4]u8{ 255, 255, 255, 255 }), false));
    // 回环/「here」网段只在 ban_localhost 时算私有（对应 C 的 && ban_localhost）
    try testing.expect(!addr.privateNet(@bitCast([4]u8{ 127, 0, 0, 1 }), false));
    try testing.expect(addr.privateNet(@bitCast([4]u8{ 127, 0, 0, 1 }), true));
    try testing.expect(!addr.privateNet(@bitCast([4]u8{ 0, 0, 0, 0 }), false));
    try testing.expect(addr.privateNet(@bitCast([4]u8{ 0, 0, 0, 0 }), true));
    // 公网地址不是私有
    try testing.expect(!addr.privateNet(@bitCast([4]u8{ 1, 1, 1, 1 }), true));
    try testing.expect(!addr.privateNet(@bitCast([4]u8{ 8, 8, 8, 8 }), true));
}
