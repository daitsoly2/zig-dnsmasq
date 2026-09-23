// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! fwdengine.zig — 异步转发引擎（单事件循环）
//!
//! ## 为什么要有这个模块
//!
//! 最初的移植用「固定线程池 + 每个查询同步阻塞等上游」。压测（实机 2 核路由器）
//! 暴露出这个模型的天花板：**并发度 = 线程数**。1000ms 的上游 RTT 下，10 个线程
//! 最多 10 qps/台；实测冷查询只有 105~109 qps，而本地应答（热缓存）能到 30k qps。
//! 转发成了唯一的瓶颈，且加线程并不解决问题（线程栈 + 上下文切换撑不住）。
//!
//! 本模块改成 **单线程事件循环**：一个线程持有全部上游 socket，用 `poll()` 同时
//! 等待所有在途查询的应答。并发度不再受线程数限制，而由内存与在途上限
//! （`dns_forward_max * 8`）决定。
//!
//! 这不是自创设计 —— C 版 dnsmasq 本体、unbound、knot-resolver、CoreDNS 全都是
//! 「单个事件循环 + txid 表」。本模块只是把 C 版的行为搬到 Zig 里。
//!
//! ## 为什么不用 Zig 自带的 std.Io
//!
//! 0.16 的 `std.Io` 有 `async`/`Group`/`Batch`，但实测都不合用：
//!
//! * 默认后端是 `Threaded`，它的 `concurrent()` 每个任务 `std.Thread.spawn`
//!   一个池线程（还有 `concurrent_limit` 与 `ConcurrencyUnavailable`）——
//!   和我们要摆脱的模型完全等价。
//! * `Io.Batch` 确实是真事件循环（`batchAwaitAsync` 里非阻塞 fd + `poll()`），
//!   但 `Io.Operation` 只有 `file_read_streaming` / `file_write_streaming` /
//!   `device_io_control` / `net_receive` 四种：**没有 send、没有定时器**，而且
//!   `awaitAsync` 不接受超时参数。本引擎恰好需要 per-try 超时、hedge 阶梯与
//!   总预算三种定时器，表达不了。
//! * `Io.net.Socket.BindOptions` 只有 `ip6_only`/`allow_broadcast`/`mode`/`protocol`，
//!   没有 `SO_REUSEADDR`、没有 `SO_RCVBUFFORCE`、没有 `IP_PKTINFO`。监听
//!   `0.0.0.0:53` 与接收缓冲强制放大它都做不到。
//! * `Uring` 后端（fiber + io_uring）在目标路由器上确实可用
//!   （kernel 5.4.284, CONFIG_IO_URING=y, io_uring_setup -> fd=3），但本机 WSL 的
//!   seccomp 直接返回 EPERM，本地一行都验证不了；而且要用它必须放弃
//!   `std.start` 的默认启动流程自己构造 `Io`。
//!
//! 结论：用 `poll()` 自己写。IO 层已经隔离在 `net.zig` 里，将来若要接 Uring
//! 只换那一层。
//!
//! ## 结构
//!
//! ```text
//!   工作线程（UDP 本地应答，纯 CPU，多核并行）
//!        │ 未命中：提交 Pending
//!        │ 主线程：accept 到 TCP 连接后交付 fd
//!        ▼
//!   ┌──────────── 引擎线程（单线程，本文件）────────────┐
//!   │  inbox 队列（Pending / TcpConn 两个队列）          │
//!   │  在途查询表 engine.pend[]                        │
//!   │  txid 解复用 (socket 槽位, id) -> Pending          │
//!   │  上游 UDP socket 缓存（每服务器一条，长期持有）      │
//!   │  poll(): 上游 fd + 唤醒管道 + TCP 客户端 fd        │
//!   └──────────────────────────────────────────────────┘
//! ```
//!
//! TCP 客户端连接由引擎全权接管（非阻塞读帧 → 本地应答内联 → 上游异步转发 →
//! 非阻塞写出）。TCP 查询罕见，串行化在引擎里不影响 UDP 热路径；换来的是一条
//! 完全没有阻塞的代码路径。
//!
//! ## 与 C 版的行为对齐
//!
//! * 事务 ID：发往上游前换成随机 id，收回后**必须**换回客户端原始 id
//!   （对应 forward.c:585）。原始查询副本存在 `Frec.original` 里。
//! * 选路、sticky 提权、并发度、超时预算全部复用 `forward.pickCandidates()`，
//!   与同步路径共用一份实现，保证两种模型下行为一致。
//! * 上游健康度记账（`balancer.beginQuery/endQuery/onSuccess/onFailure`）在每一条
//!   腿的完整生命周期上配对 —— 这是之前踩过的坑：只在并发路径记账、串行路径漏记，
//!   导致 `in_flight` 恒为 0、所有上游打分退化成 0。
//! * REFUSED 兜底：只要还有候选没发、或还有别的腿在等，就继续等而不是立刻采用
//!   （对应 forward.c:1271）。
//! * 截断应答改走 TCP（对应 forward.c: tcp_from_udp）；TCP 也失败时把截断的 UDP
//!   应答原样回给客户端（标准行为）。

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
const balancer = @import("balancer.zig");
const server_mod = @import("server.zig");

const Daemon = daemon_mod.Daemon;
const Server = daemon_mod.Server;
const SockAddr = addr.SockAddr;

/// 单个在途查询的报文缓冲大小（与 UDP 监听侧一致）
pub const PKT_SZ: usize = server_mod.UDP_PACKET_MAX;
/// 并发的上游「腿」上限（与同步竞速路径保持一致）
const MAX_LEGS: usize = protocol.MAX_CONCURRENT_UPSTREAMS;
/// 同时存在的 TCP 客户端连接上限。每条连接活跃时占 TCP_PACKET_MAX+2 字节，
/// 32 条约 2MB —— 对家用/小型路由器可接受，也足以应付截断回退的流量。
pub const MAX_TCP_CONNS: usize = 32;
/// TCP 客户端连接空闲超时（对应 config.h: TCP_TIMEOUT）
const TCP_IDLE_MS: i64 = @intCast(protocol.TCP_TIMEOUT_MS);

const MSG_DONTWAIT: u32 = @intCast(std.posix.MSG.DONTWAIT);

// ---------------------------------------------------------------------------
// 应答投递目标
// ---------------------------------------------------------------------------
/// 一次查询的回复往哪送：UDP 直接 sendto，TCP 要按 2 字节长度前缀成帧写回。
const Sink = union(enum) {
    udp: struct {
        fd: net.fd_t,
        client: SockAddr,
        /// 客户端通告的 UDP 负载上限（超出要截断并置 TC 位）
        limit: usize,
    },
    tcp: *TcpConn,
};

// ---------------------------------------------------------------------------
// TCP 客户端连接
// ---------------------------------------------------------------------------
pub const TcpConn = struct {
    fd: net.fd_t,
    client: SockAddr,
    /// 已处理的查询数（对应 C 版 tcp_request 的循环计数）
    queries: usize = 0,

    /// 输入/输出共用的大缓冲（TCP_PACKET_MAX + 2）。懒分配：空闲连接不占这 64KB。
    buf: ?[]u8 = null,

    /// 长度前缀
    hdr: [2]u8 = undefined,
    /// 已读入的长度前缀字节数（0..2）
    hdr_got: usize = 0,
    /// 当前帧已读入 buf 的字节数 / 需要的字节数
    got: usize = 0,
    need: usize = 0,

    /// 待写出范围（针对 conn.buf），out_off == out_len 表示空闲
    out_off: usize = 0,
    out_len: usize = 0,

    /// 该连接当前正在等待上游应答的查询。
    /// 同一连接同时只处理一个查询（与 C 版 tcp_request 一致，保证应答顺序）。
    pending: ?*Pending = null,

    last_ms: i64 = 0,
    dead: bool = false,

    fn ensureBuf(self: *TcpConn) ?[]u8 {
        if (self.buf) |b| return b;
        const b = engine.allocator.alloc(u8, server_mod.TCP_PACKET_MAX + 2) catch return null;
        self.buf = b;
        return b;
    }

    /// 复位「读下一帧」的状态（不动输出状态）
    fn resetInput(self: *TcpConn) void {
        self.hdr_got = 0;
        self.got = 0;
        self.need = 0;
        self.last_ms = util.monoMillis();
    }
};

// ---------------------------------------------------------------------------
// 上游 UDP socket（每个上游服务器一条，长期持有）
// ---------------------------------------------------------------------------
const UpSock = struct {
    fd: net.fd_t,
    srv: *Server,
    /// 该 socket 上当前在途的腿数（仅用于观测/断言）
    legs: usize = 0,
};

// ---------------------------------------------------------------------------
// 上游 TCP 腿（截断回退时使用，非阻塞状态机）
// ---------------------------------------------------------------------------
const TcpLegState = enum { connecting, writing, reading_len, reading_body, done };

const TcpLeg = struct {
    fd: net.fd_t = -1,
    srv: *Server = undefined,
    state: TcpLegState = .connecting,
    /// 阶段复用的缓冲：先装发往上游的查询，再装收回来的应答
    scratch: [PKT_SZ]u8 = undefined,
    /// scratch 中已写出的字节数
    tx_off: usize = 0,
    /// 当前阶段的长度：writing 时是查询长度，reading_body 时是应答长度
    len: usize = 0,
    /// 长度前缀的读入进度
    hdr: [2]u8 = undefined,
    hdr_got: usize = 0,
    started_us: i64 = 0,
    deadline_ms: i64 = 0,
};

// ---------------------------------------------------------------------------
// 在途转发查询
// ---------------------------------------------------------------------------
const Mode = enum { udp, tcp };

const Leg = struct {
    sock_slot: usize = 0,
    id: u16 = 0,
    srv: *Server = undefined,
    sent_ms: i64 = 0,
    sent_us: i64 = 0,
};

pub const Pending = struct {
    /// 应答缓冲（发往上游的报文另外用栈上临时缓冲构造，不占用这里）
    buf: []u8,
    /// 客户端原始查询长度
    qlen: usize = 0,
    fr: forward.Frec = undefined,
    /// `fr.qname` 指向这里 —— 工作线程栈上的 namebuf 在返回后就失效了，
    /// 必须自己持有一份，否则日志与应答校验会读到野内存。
    qname_buf: [rfc1035.MAXNAMEBUF]u8 = undefined,
    sink: Sink = undefined,
    /// 解析请求时的 dnsmasq 时刻（写缓存用）
    now: i64 = 0,
    started_ms: i64 = 0,

    plan: forward.Candidates = .{},
    next_idx: usize = 0,
    sent_count: usize = 0,
    budget_deadline_ms: i64 = 0,
    next_send_ms: i64 = 0,

    mode: Mode = .udp,
    legs: [MAX_LEGS]Leg = undefined,
    n_legs: usize = 0,
    tcp: TcpLeg = .{},

    /// 截断回退时留在 buf 里的那份 UDP 截断应答的长度（TCP 也失败时用它兜底）
    trunc_len: usize = 0,

    /// REFUSED 兜底：把最后一份 REFUSED 应答留在 buf 里备用
    refused_len: usize = 0,
    refused_srv: ?*Server = null,
    refused_rtt_us: u64 = 0,

    /// NODATA 兜底（GSLB 分流保护）：与 REFUSED 同构。
    /// 多上游对同一名字的应答可能不一致（CDN/GSLB 按源调度），例如 ISP/CF
    /// 返回真实 AAAA（ttl=0），阿里/腾讯公共 DNS 返回 NODATA+SOA。all-servers
    /// 竞速下若 NODATA 腿先到就收尾，客户端拿到空应答，更糟的是 extractAddresses
    /// 会把它写进**负缓存**（60s）—— 此后该域名的查询全被污染，表现为
    /// 「刚启动正常、跑一会儿后部分域名解析失败」。
    /// 对策：NODATA 先到时若有别的腿在途就先记下继续等；只有所有腿收齐且
    /// 全是 NODATA 才用它收尾 —— 此时写负缓存是安全的（所有上游都同意没有记录）。
    empty_len: usize = 0,
    empty_srv: ?*Server = null,
    empty_rtt_us: u64 = 0,
};

/// poll 集合里每个 fd 对应什么 —— 让 handleReadable 按 fds[i] 直接取 target[i]，
/// 而不是靠「先遍历 socks 再遍历 conns」的隐式顺序对齐（那样一改顺序就静默错位）。
const Target = union(enum) {
    wake,
    sock: *UpSock,
    conn: *TcpConn,
    tcp_leg: *Pending,
};

// ---------------------------------------------------------------------------
// 引擎
// ---------------------------------------------------------------------------
pub const Engine = struct {
    /// 引擎分配器：只用于 demux/socks/conns/inbox 等**容器**（容量增长有限），
    /// 绝不用来分配 Pending / 报文缓冲 —— 那些走下面的预分配池，
    /// 否则高并发下 mmap 累积会让 RSS 涨到几百 MB 触发 OOM。
    allocator: std.mem.Allocator = std.heap.page_allocator,
    io: std.Io = undefined,
    d: ?*Daemon = null,

    running: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    shutting: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    thread: ?std.Thread = null,

    /// 唤醒管道：生产者投递完就写一个字节，让 poll() 立刻返回
    wake: [2]net.fd_t = .{ -1, -1 },

    // ---- 生产者侧（工作线程 / 主线程）----
    qmutex: std.Io.Mutex = .init,
    inbox: std.ArrayListUnmanaged(*Pending) = .empty,
    conns_inbox: std.ArrayListUnmanaged(*TcpConn) = .empty,

    // ---- 以下仅引擎线程访问 ----
    pend: std.ArrayListUnmanaged(*Pending) = .empty,
    /// (socket_slot << 16) | txid -> Pending
    demux: std.AutoHashMapUnmanaged(u32, *Pending) = .empty,
    /// 上游 UDP socket 表。用 `?*UpSock` 而不是紧凑数组：槽位下标进 demux key，
    /// 必须稳定，关闭时把槽位置 null 而不是搬移元素。
    socks: std.ArrayListUnmanaged(?*UpSock) = .empty,
    conns: std.ArrayListUnmanaged(*TcpConn) = .empty,

    // ---- 报文缓冲池（freelist）----
    bmutex: std.Io.Mutex = .init,
    bufs: std.ArrayListUnmanaged([]u8) = .empty,
    /// 缓冲池硬上限。预分配时一次性 alloc 这么多 4KB 缓冲，从此零运行时分配。
    /// 上限 = `dns_forward_max * 8`，与 server 端 inflight 限流一致：永远够用。
    buf_cap: usize = 0,

    // ---- Pending 对象池（freelist）----
    /// 启动时一次预分配 N 个 Pending，从此引擎自身不 mmap。
    pmutex: std.Io.Mutex = .init,
    pfree: std.ArrayListUnmanaged(*Pending) = .empty,
    pfree_cap: usize = 0,

    // ---- 静默（SIGHUP 重载）----
    /// 重载会 destroy 掉 Server 对象，在途查询手里的 `*Server` 会变成悬垂指针。
    /// 所以重载前必须让引擎把在途查询全部收尾、上游 socket 全部关闭。
    quiesce_req: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    resume_req: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    rmutex: std.Io.Mutex = .init,
    rcond: std.Io.Condition = .init,
    quiesce_ack: bool = false,

    // ---- 统计 ----
    submitted: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    answered: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    servfail: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    tcp_fallbacks: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    stale_replies: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// 上游回了「无效应答」（txid/问题区/qdcount 校验不通过）的次数。
    /// 这些应答按 C 版语义丢弃，但**该腿必须当场退场** —— 否则它会一直挂在
    /// 在途表里，而 NODATA 兜底又要等所有腿，客户端就得干等到腿超时（实测 10s）。
    invalid_replies: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
};

pub var engine: Engine = .{};

// ---------------------------------------------------------------------------
// 生命周期
// ---------------------------------------------------------------------------
pub fn start(d: *Daemon) !void {
    engine.allocator = std.heap.page_allocator;
    engine.io = d.io;
    engine.d = d;

    const rc = std.posix.system.pipe2(&engine.wake, .{ .NONBLOCK = true, .CLOEXEC = true });
    if (std.posix.errno(rc) != .SUCCESS) return error.PipeFailed;

    // 一次性预分配缓冲池 + Pending 池，从此引擎自身**永不运行时 mmap**。
    // 上限与 server 端 inflight 限流（`dns_forward_max * 8`）一致：所有在途查询
    // 都能找到自己的缓冲与 Pending，再多就拒收。
    const cap = d.dns_forward_max * 8;
    engine.buf_cap = cap;
    engine.pfree_cap = cap;
    {
        const bufs = try engine.allocator.alloc([]u8, cap);
        for (bufs) |*slot| {
            slot.* = engine.allocator.alloc(u8, PKT_SZ) catch return error.OutOfMemory;
        }
        engine.bufs = .{ .items = bufs, .capacity = bufs.len };
    }
    {
        const pendings = try engine.allocator.alloc(*Pending, cap);
        for (pendings) |*slot| {
            const p = engine.allocator.create(Pending) catch return error.OutOfMemory;
            // 清零以避免野字段影响 freePending 等路径；buf 必须是空切片而非未定义
            p.* = .{ .buf = &.{} };
            slot.* = p;
        }
        engine.pfree = .{ .items = pendings, .capacity = pendings.len };
    }

    engine.shutting.store(false, .release);
    engine.running.store(true, .release);
    engine.thread = try std.Thread.spawn(.{}, engineMain, .{});
    log.notice("异步转发引擎已启动（单事件循环，零阻塞，预分配 {d} 个 Pending/缓冲）", .{cap});
}

pub fn stop() void {
    if (!engine.running.load(.acquire)) return;
    engine.shutting.store(true, .release);
    wake();
    if (engine.thread) |t| t.join();
    engine.running.store(false, .release);

    for (engine.bufs.items) |b| engine.allocator.free(b);
    engine.bufs.deinit(engine.allocator);
    for (engine.pfree.items) |p| engine.allocator.destroy(p);
    engine.pfree.deinit(engine.allocator);
    engine.inbox.deinit(engine.allocator);
    engine.conns_inbox.deinit(engine.allocator);
    engine.pend.deinit(engine.allocator);
    engine.demux.deinit(engine.allocator);
    engine.socks.deinit(engine.allocator);
    engine.conns.deinit(engine.allocator);
    if (engine.wake[0] >= 0) net.close(engine.wake[0]);
    if (engine.wake[1] >= 0) net.close(engine.wake[1]);
    engine.wake = .{ -1, -1 };
    engine.thread = null;
}

pub fn isRunning() bool {
    return engine.running.load(.acquire);
}

/// 引擎统计（供 SIGUSR1 输出）
pub fn statsText(w: *std.Io.Writer) !void {
    try w.print("异步转发引擎: 提交 {d} / 应答 {d} / SERVFAIL {d} / TCP 回退 {d} / 过期应答 {d}\n", .{
        engine.submitted.load(.monotonic),
        engine.answered.load(.monotonic),
        engine.servfail.load(.monotonic),
        engine.tcp_fallbacks.load(.monotonic),
        engine.stale_replies.load(.monotonic),
    });
}

fn wake() void {
    if (engine.wake[1] < 0) return;
    const b: [1]u8 = .{1};
    _ = std.posix.system.write(engine.wake[1], &b, 1);
}

fn drainWake() void {
    if (engine.wake[0] < 0) return;
    var sink: [64]u8 = undefined;
    while (true) {
        const rc = std.posix.system.read(engine.wake[0], &sink, sink.len);
        if (std.posix.errno(rc) != .SUCCESS) break;
        if (rc == 0 or rc < sink.len) break;
    }
}

// ---------------------------------------------------------------------------
// 报文缓冲池（freelist，启动时预分配，永不运行时 mmap）
// ---------------------------------------------------------------------------
fn bufGet() ?[]u8 {
    engine.bmutex.lockUncancelable(engine.io);
    const cached = engine.bufs.pop();
    engine.bmutex.unlock(engine.io);
    return cached;
}

/// 把缓冲还回池。**不调用 allocator.free**：缓冲是启动时一次 alloc 的，
/// 进程生命周期内复用。还给 OS 的事情交给 stop() 的整体释放。
fn bufPut(b: []u8) void {
    if (b.len != PKT_SZ) return; // 防御：非标准大小直接丢（不应发生）
    engine.bmutex.lockUncancelable(engine.io);
    if (engine.bufs.items.len >= engine.buf_cap) {
        // 极端：调用者比池容量多，丢弃多余缓冲（首次开机时刚 alloc 完会到这里）
        engine.bmutex.unlock(engine.io);
        return;
    }
    engine.bufs.append(engine.allocator, b) catch {
        engine.bmutex.unlock(engine.io);
    };
    engine.bmutex.unlock(engine.io);
}

// ---------------------------------------------------------------------------
// Pending 对象池（freelist，启动时预分配，永不运行时 mmap）
// ---------------------------------------------------------------------------
fn pendGet() ?*Pending {
    engine.pmutex.lockUncancelable(engine.io);
    const p = engine.pfree.pop();
    engine.pmutex.unlock(engine.io);
    return p;
}

fn pendPut(p: *Pending) void {
    engine.pmutex.lockUncancelable(engine.io);
    if (engine.pfree.items.len >= engine.pfree_cap) {
        engine.pmutex.unlock(engine.io);
        return;
    }
    engine.pfree.append(engine.allocator, p) catch {
        engine.pmutex.unlock(engine.io);
    };
    engine.pmutex.unlock(engine.io);
}

// ---------------------------------------------------------------------------
// 提交入口（生产者侧）
// ---------------------------------------------------------------------------
/// 提交一个需要转发上游的 UDP 查询。返回 false 表示引擎不可用
/// （调用者应退回同步路径 `forward.forwardQuery`）。
///
/// 调用者返回后即可释放自己的报文缓冲 —— 这里把查询内容整份拷走了。
///
/// Pending 与 buffer 均取自启动时预分配的 freelist；池空返回 false 触发
/// server 端降级同步路径，避免在峰值流量下 mmap 让 RSS 暴涨触发 OOM。
pub fn submitUdp(
    d: *Daemon,
    pkt: []const u8,
    len: usize,
    req: rfc1035.Request,
    client: *const SockAddr,
    reply_fd: net.fd_t,
    client_limit: usize,
    now: i64,
) bool {
    if (!isRunning()) return false;

    const p = pendGet() orelse {
        log.warning("Pending 池空，引擎拒收（降级同步路径）", .{});
        return false;
    };
    const b = bufGet() orelse {
        pendPut(p);
        log.warning("缓冲池空，引擎拒收（降级同步路径）", .{});
        return false;
    };
    p.* = .{
        .buf = b,
        .sink = .{ .udp = .{ .fd = reply_fd, .client = client.*, .limit = client_limit } },
        .now = now,
        .started_ms = util.monoMillis(),
    };

    const copy_len = @min(len, b.len);
    @memcpy(b[0..copy_len], pkt[0..copy_len]);
    p.qlen = copy_len;
    initFrec(p, req, client, b, copy_len);

    if (!planAndStart(d, p)) return true;
    enqueue(p);
    return true;
}

/// 主线程 accept 到一条 TCP 连接后把 fd 的所有权交给引擎。
pub fn adoptTcpConn(cfd: net.fd_t, client: SockAddr) bool {
    if (!isRunning()) return false;
    net.setNonBlock(cfd) catch {};

    const conn = engine.allocator.create(TcpConn) catch return false;
    conn.* = .{ .fd = cfd, .client = client, .last_ms = util.monoMillis() };

    engine.qmutex.lockUncancelable(engine.io);
    const ok = blk: {
        engine.conns_inbox.append(engine.allocator, conn) catch break :blk false;
        break :blk true;
    };
    engine.qmutex.unlock(engine.io);
    if (!ok) {
        engine.allocator.destroy(conn);
        return false;
    }
    wake();
    return true;
}

/// 填好 frec 与 qname 的自有副本
fn initFrec(p: *Pending, req: rfc1035.Request, client: *const SockAddr, buf: []u8, len: usize) void {
    p.fr = .{
        .packet = buf,
        .len = len,
        .qlen = len,
        .source = client.*,
        .qname = undefined,
        .qtype = req.qtype,
        .qclass = req.qclass,
        .client_edns0 = req.has_edns0,
        .flags = req.flags,
    };
    const n = @min(req.name.len, p.qname_buf.len - 1);
    @memcpy(p.qname_buf[0..n], req.name[0..n]);
    p.qname_buf[n] = 0;
    p.fr.qname = std.mem.sliceTo(&p.qname_buf, 0);
    forward.saveOriginal(&p.fr, buf, len);
}

/// 选路并安排首次发送。返回 false 表示已经就地处理完（无可用上游，已回 SERVFAIL）。
fn planAndStart(d: *Daemon, p: *Pending) bool {
    p.plan = forward.pickCandidates(d, &p.fr);
    if (p.plan.n == 0) {
        const qlen = @min(@min(p.qlen, p.fr.orig_len), p.buf.len);
        sendServfail(p, p.buf, qlen);
        bufPut(p.buf);
        p.buf = &.{};
        pendPut(p);
        return false;
    }
    p.budget_deadline_ms = util.monoMillis() + p.plan.budget_ms;
    p.next_send_ms = util.monoMillis();
    return true;
}

fn enqueue(p: *Pending) void {
    engine.qmutex.lockUncancelable(engine.io);
    const ok = blk: {
        engine.inbox.append(engine.allocator, p) catch break :blk false;
        break :blk true;
    };
    engine.qmutex.unlock(engine.io);
    if (!ok) {
        if (p.buf.len != 0) bufPut(p.buf);
        p.buf = &.{};
        pendPut(p);
        return;
    }
    _ = engine.submitted.fetchAdd(1, .monotonic);
    wake();
}

// ---------------------------------------------------------------------------
// 引擎主循环
// ---------------------------------------------------------------------------
fn engineMain() void {
    var pfd: std.ArrayListUnmanaged(std.posix.pollfd) = .empty;
    defer pfd.deinit(engine.allocator);
    var targets: std.ArrayListUnmanaged(Target) = .empty;
    defer targets.deinit(engine.allocator);

    while (!engine.shutting.load(.acquire)) {
        // ---- SIGHUP 重载的静默请求 ----
        if (engine.quiesce_req.swap(false, .acquire)) {
            doQuiesce();
            ackQuiesce();
            while (!engine.resume_req.load(.acquire) and !engine.shutting.load(.acquire)) {
                pollWakeOnly(200);
            }
            engine.resume_req.store(false, .release);
            continue;
        }

        drainInbox();
        stepAll();
        if (engine.shutting.load(.acquire)) break;

        buildPollSet(&pfd, &targets);
        const timeout = nextTimeoutMs();
        _ = net.poll(pfd.items, timeout) catch {};
        drainWake();
        drainInbox();
        handleReadable(pfd.items, targets.items);
        sweepTcpConns();
    }

    cleanup();
}

fn pollWakeOnly(timeout_ms: i32) void {
    var fds = [_]std.posix.pollfd{
        .{ .fd = engine.wake[0], .events = std.posix.POLL.IN, .revents = 0 },
    };
    _ = net.poll(&fds, timeout_ms) catch {};
    drainWake();
}

fn buildPollSet(pfd: *std.ArrayListUnmanaged(std.posix.pollfd), targets: *std.ArrayListUnmanaged(Target)) void {
    pfd.clearRetainingCapacity();
    targets.clearRetainingCapacity();

    addPoll(pfd, targets, .{ .fd = engine.wake[0], .events = std.posix.POLL.IN, .revents = 0 }, .wake);

    for (engine.socks.items) |maybe| {
        const s = maybe orelse continue;
        if (s.fd < 0) continue;
        addPoll(pfd, targets, .{ .fd = s.fd, .events = std.posix.POLL.IN, .revents = 0 }, .{ .sock = s });
    }
    // 上游 TCP 腿必须排在同一条查询对应的客户端连接**之前**：
    // 一个目标被处理时可能 `closeConn()` 掉某个连接，从而间接结束该连接上的
    // 在途查询；若那个查询的 target 还排在后面，就会读到已释放的 Pending。
    for (engine.pend.items) |p| {
        if (p.mode != .tcp or p.tcp.fd < 0) continue;
        const ev: i16 = switch (p.tcp.state) {
            .connecting, .writing => std.posix.POLL.OUT,
            .reading_len, .reading_body => std.posix.POLL.IN,
            .done => continue,
        };
        addPoll(pfd, targets, .{ .fd = p.tcp.fd, .events = ev, .revents = 0 }, .{ .tcp_leg = p });
    }
    for (engine.conns.items) |c| {
        if (c.dead or c.fd < 0) continue;
        var ev: i16 = std.posix.POLL.IN;
        if (c.out_len > 0) ev |= std.posix.POLL.OUT;
        addPoll(pfd, targets, .{ .fd = c.fd, .events = ev, .revents = 0 }, .{ .conn = c });
    }
}

fn addPoll(
    pfd: *std.ArrayListUnmanaged(std.posix.pollfd),
    targets: *std.ArrayListUnmanaged(Target),
    f: std.posix.pollfd,
    t: Target,
) void {
    if (pfd.items.len >= 512) return;
    pfd.append(engine.allocator, f) catch return;
    targets.append(engine.allocator, t) catch {
        _ = pfd.pop();
        return;
    };
}

/// 下一次需要醒来的时刻（按 poll 语义钳制到 [0, 1000]）
fn nextTimeoutMs() i32 {
    const now = util.monoMillis();
    var earliest: i64 = now + 1000;

    for (engine.pend.items) |p| {
        const t = earliestEventMs(p, now);
        if (t < earliest) earliest = t;
    }
    for (engine.conns.items) |c| {
        if (c.dead) continue;
        const t = c.last_ms + TCP_IDLE_MS;
        if (t < earliest) earliest = t;
    }

    var wait = earliest - now;
    if (wait < 0) wait = 0;
    if (wait > 1000) wait = 1000;
    return @intCast(wait);
}

fn earliestEventMs(p: *Pending, now: i64) i64 {
    var best = p.budget_deadline_ms;

    if (p.mode == .tcp) {
        if (p.tcp.deadline_ms < best) best = p.tcp.deadline_ms;
        return best;
    }

    if (p.next_idx < p.plan.n and p.n_legs < effConc(p)) {
        if (p.n_legs == 0) return now;
        if (p.plan.hedge_ms > 0) {
            if (p.next_send_ms < best) best = p.next_send_ms;
        } else {
            return now;
        }
    }
    if (effConc(p) == 1 and p.n_legs > 0) {
        const t = p.legs[0].sent_ms + p.plan.per_try_ms;
        if (t < best) best = t;
    }
    return best;
}

// ---------------------------------------------------------------------------
// inbox
// ---------------------------------------------------------------------------
fn drainInbox() void {
    // TCP 连接先入库（它们更短，且入库后就能参与本轮 poll）
    while (true) {
        engine.qmutex.lockUncancelable(engine.io);
        const c = engine.conns_inbox.pop();
        engine.qmutex.unlock(engine.io);
        const conn = c orelse break;
        if (engine.conns.items.len >= MAX_TCP_CONNS) {
            net.close(conn.fd);
            engine.allocator.destroy(conn);
            continue;
        }
        engine.conns.append(engine.allocator, conn) catch {
            net.close(conn.fd);
            engine.allocator.destroy(conn);
        };
    }

    while (true) {
        engine.qmutex.lockUncancelable(engine.io);
        const p = engine.inbox.pop();
        engine.qmutex.unlock(engine.io);
        const pend = p orelse break;
        startPending(pend);
    }
}

// ---------------------------------------------------------------------------
// 调度
// ---------------------------------------------------------------------------
fn effConc(p: *const Pending) usize {
    return @max(@as(usize, 1), @min(p.plan.conc, p.plan.n));
}

fn startPending(p: *Pending) void {
    engine.pend.append(engine.allocator, p) catch {
        bufPut(p.buf);
        p.buf = &.{};
        pendPut(p);
        return;
    };
    _ = stepPending(p);
}

fn stepAll() void {
    var i: usize = 0;
    while (i < engine.pend.items.len) {
        const p = engine.pend.items[i];
        switch (stepPending(p)) {
            .keep => i += 1,
            .give_up => {
                _ = engine.pend.swapRemove(i); // 末尾元素被搬到这里，不能 i += 1
                finalizeFail(p);
            },
        }
    }
}

const Step = enum { keep, give_up };

fn stepPending(p: *Pending) Step {
    if (p.mode == .tcp) {
        const t = &p.tcp;
        if (t.state == .done or t.fd < 0) return .give_up;
        if (util.monoMillis() >= t.deadline_ms) return .give_up;
        return .keep;
    }

    const now = util.monoMillis();

    // 1) 串行模式：当前腿超过 per_try_ms 就退场，给下一台机会
    if (effConc(p) == 1) {
        while (p.n_legs > 0 and now - p.legs[0].sent_ms >= p.plan.per_try_ms) {
            retireLeg(p, 0, .timeout);
        }
    }

    // 2) 补发：按并发度把候选铺满（hedge_ms 控制阶梯间隔）
    var guard: usize = 0;
    while (p.next_idx < p.plan.n and p.n_legs < effConc(p) and now < p.budget_deadline_ms) {
        guard += 1;
        if (guard > protocol.MAX_FORWARD_CANDIDATES) break;
        if (p.n_legs > 0 and p.plan.hedge_ms > 0 and now < p.next_send_ms) break;
        if (!sendLeg(p)) continue;
    }

    // 3) 结论
    if (p.n_legs == 0 and p.next_idx >= p.plan.n) return .give_up;
    if (now >= p.budget_deadline_ms) return .give_up;
    return .keep;
}

// ---------------------------------------------------------------------------
// 上游 UDP socket 缓存
// ---------------------------------------------------------------------------
fn sockFor(srv: *Server) ?usize {
    for (engine.socks.items, 0..) |maybe, i| {
        const s = maybe orelse continue;
        if (s.srv == srv and s.fd >= 0) return i;
    }
    const fd = forward.openUpstreamUdp(srv) catch return null;
    const s = engine.allocator.create(UpSock) catch {
        net.close(fd);
        return null;
    };
    s.* = .{ .fd = fd, .srv = srv };

    for (engine.socks.items, 0..) |maybe, i| {
        if (maybe == null) {
            engine.socks.items[i] = s;
            return i;
        }
    }
    engine.socks.append(engine.allocator, s) catch {
        net.close(fd);
        engine.allocator.destroy(s);
        return null;
    };
    return engine.socks.items.len - 1;
}

fn keyOf(slot: usize, id: u16) u32 {
    return (@as(u32, @intCast(slot)) << 16) | @as(u32, id);
}

/// 在指定 socket 上挑一个未被占用的事务 id。
/// 同一条 socket 上可能有多个在途查询，id 必须唯一，否则应答会串台。
fn allocId(slot: usize) ?u16 {
    var tries: usize = 0;
    while (tries < 128) : (tries += 1) {
        const id = forward.getId();
        if (!engine.demux.contains(keyOf(slot, id))) return id;
    }
    return null;
}

fn cooldownMs() i64 {
    const d = engine.d.?;
    return d.server_cooldown_ms;
}

// ---------------------------------------------------------------------------
// 发送一条腿
// ---------------------------------------------------------------------------
fn sendLeg(p: *Pending) bool {
    const srv = p.plan.list[p.next_idx];
    p.next_idx += 1;

    const slot = sockFor(srv) orelse {
        _ = srv.failed_queries.fetchAdd(1, .monotonic);
        balancer.onFailure(srv, cooldownMs(), util.monoMillis());
        return false;
    };
    const sock = engine.socks.items[slot].?;
    const id = allocId(slot) orelse return false;

    // 串行模式下「换到下一台」记一次 retry（对应同步路径的 `if (i != 0) retrys++`）
    if (effConc(p) == 1 and p.sent_count > 0) {
        _ = srv.retrys.fetchAdd(1, .monotonic);
    }

    // 用保存的原始查询重建发包（不能拿 p.buf 拼，它要留着装应答）
    const qlen = @min(@min(p.qlen, p.fr.orig_len), p.buf.len);
    var tx: [PKT_SZ]u8 = undefined;
    @memcpy(tx[0..qlen], p.fr.original[0..qlen]);
    protocol.setId(&tx, id);

    _ = srv.queries.fetchAdd(1, .monotonic);
    balancer.beginQuery(srv);

    var srvbuf: [128]u8 = undefined;
    log.logQuery(protocol.F_SERVER, p.fr.qname, null, srv.addrText(&srvbuf), p.fr.qtype);

    var written: usize = 0;
    while (written < qlen) {
        const w = net.sendto(sock.fd, tx[written..qlen], &srv.addr, 0) catch break;
        if (w == 0) break;
        written += w;
    }
    if (written != qlen) {
        balancer.endQuery(srv);
        _ = srv.failed_queries.fetchAdd(1, .monotonic);
        balancer.onFailure(srv, cooldownMs(), util.monoMillis());
        return false;
    }

    const now_ms = util.monoMillis();
    p.legs[p.n_legs] = .{
        .sock_slot = slot,
        .id = id,
        .srv = srv,
        .sent_ms = now_ms,
        .sent_us = util.monoMicros(),
    };
    p.n_legs += 1;
    p.sent_count += 1;
    sock.legs += 1;

    engine.demux.put(engine.allocator, keyOf(slot, id), p) catch {
        // 放不进解复用表就收不到应答，立刻把这条腿收掉
        p.n_legs -= 1;
        p.sent_count -= 1;
        sock.legs -= 1;
        balancer.endQuery(srv);
        return false;
    };

    if (p.plan.hedge_ms > 0) p.next_send_ms = now_ms + p.plan.hedge_ms;
    return true;
}

const RetireReason = enum { done, timeout, refused, loser, invalid };

fn retireLeg(p: *Pending, idx: usize, reason: RetireReason) void {
    const leg = p.legs[idx];
    _ = engine.demux.remove(keyOf(leg.sock_slot, leg.id));
    balancer.endQuery(leg.srv);
    if (leg.sock_slot < engine.socks.items.len) {
        if (engine.socks.items[leg.sock_slot]) |s| {
            if (s.legs > 0) s.legs -= 1;
        }
    }

    var k = idx;
    while (k + 1 < p.n_legs) : (k += 1) p.legs[k] = p.legs[k + 1];
    p.n_legs -= 1;

    switch (reason) {
        .timeout => {
            _ = leg.srv.failed_queries.fetchAdd(1, .monotonic);
            balancer.onFailure(leg.srv, cooldownMs(), util.monoMillis());
        },
        .refused => _ = leg.srv.failed_queries.fetchAdd(1, .monotonic),
        .loser => _ = leg.srv.retrys.fetchAdd(1, .monotonic),
        // 无效应答：这条腿已经不会再有下文，必须退场。
        // 但不记为失败、不触发熔断 —— 上游对**别的**查询类型仍然可用
        // （实测 119.29.29.29 只有 PTR 查询会回 qd=0 的畸形包，A/AAAA 完全正常），
        // 因一次畸形包就把它整体冷却掉会白白损失一个好上游。记 retrys 即可。
        .invalid => {
            _ = leg.srv.retrys.fetchAdd(1, .monotonic);
            _ = engine.invalid_replies.fetchAdd(1, .monotonic);
        },
        .done => {},
    }
}

/// 全部腿退场。`winner` 指定的那条不算失败，其余记一次 retry。
fn retireAllLegs(p: *Pending, winner: ?*Server) void {
    var winner_seen = winner == null;
    while (p.n_legs > 0) {
        const is_winner = !winner_seen and p.legs[0].srv == winner.?;
        retireLeg(p, 0, if (is_winner) .done else .loser);
        if (is_winner) winner_seen = true;
    }
}

// ---------------------------------------------------------------------------
// 事件分发
// ---------------------------------------------------------------------------
fn handleReadable(fds: []const std.posix.pollfd, targets: []const Target) void {
    const n = @min(fds.len, targets.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const f = fds[i];
        if (f.revents == 0) continue;
        switch (targets[i]) {
            .wake => {},
            .sock => |s| {
                if ((f.revents & (std.posix.POLL.IN | std.posix.POLL.ERR)) != 0) drainSocket(s);
            },
            .conn => |c| {
                if (c.dead) continue;
                handleTcpConnEvents(c, f.revents);
            },
            .tcp_leg => |p| {
                if (p.mode != .tcp or p.tcp.fd != f.fd) continue;
                handleTcpLegEvents(p, f.revents);
            },
        }
    }
}

fn drainSocket(s: *UpSock) void {
    var rx: [protocol.PACKET_BUFF_SZ]u8 = undefined;
    var budget: usize = 64;
    while (budget > 0) : (budget -= 1) {
        const n = net.recvfrom(s.fd, &rx, null, MSG_DONTWAIT) catch break;
        if (n == 0) break;
        handleUpstreamReply(s, &rx, n);
    }
}

fn sockSlotOf(s: *UpSock) ?usize {
    for (engine.socks.items, 0..) |maybe, i| {
        if (maybe) |x| {
            if (x == s) return i;
        }
    }
    return null;
}

fn handleUpstreamReply(s: *UpSock, rx: []u8, n: usize) void {
    if (n < protocol.HEADER_SIZE) return;
    const slot = sockSlotOf(s) orelse return;
    const id = protocol.headerId(rx);
    const p = engine.demux.get(keyOf(slot, id)) orelse {
        _ = engine.stale_replies.fetchAdd(1, .monotonic);
        return;
    };

    var li: ?usize = null;
    for (p.legs[0..p.n_legs], 0..) |l, k| {
        if (l.sock_slot == slot and l.id == id) {
            li = k;
            break;
        }
    }
    const idx = li orelse return;

    if (!forward.checkReplyWith(rx, n, &p.fr, id)) {
        // 校验不通过（txid / 问题区 / qdcount）。按 C 版语义这份应答被丢弃，
        // 但这条腿必须**当场退场** —— C 版 all-servers 是「第一个有效应答即回」，
        // 丢包不影响它出结果；Zig 的 NODATA 兜底要等所有腿，若把这条腿晾在
        // 在途表里，客户端就得干等到腿超时（实测 example.com 的 PTR 卡满 10s）。
        _ = engine.invalid_replies.fetchAdd(1, .monotonic);
        log.debug("丢弃无效应答（txid/问题区/qdcount 不符），并让该腿退场: {s}", .{p.fr.qname});
        retireLeg(p, idx, .invalid);
        return;
    }

    const leg = p.legs[idx];
    const rtt: u64 = @intCast(@max(@as(i64, 0), util.monoMicros() - leg.sent_us));
    _ = leg.srv.last_reply.store(util.dnsmasqTime(), .monotonic);
    const rcode = protocol.rcode(rx[protocol.OFF_HB4]);

    // 截断 -> 改走 TCP（对应 forward.c: tcp_from_udp）
    if ((protocol.headerHb3(rx) & protocol.HB3_TC) != 0) {
        switchToTcp(p, leg.srv, rx, n);
        return;
    }

    // REFUSED 兜底：还有候选没发、或还有别的腿在等，就先记下继续等
    if (rcode == protocol.REFUSED and (p.next_idx < p.plan.n or p.n_legs > 1)) {
        if (n <= p.buf.len) {
            @memcpy(p.buf[0..n], rx[0..n]);
            p.refused_len = n;
            p.refused_srv = leg.srv;
            p.refused_rtt_us = rtt;
            // 与 NODATA 兜底互斥：两者共用 p.buf 暂存，后到的覆盖先到的。
            // 若不清对方的标记，finalizeFail 会拿旧长度去读被覆盖后的 buf，
            // 尾部就是上一份应答的残渣。
            p.empty_len = 0;
            p.empty_srv = null;
        }
        retireLeg(p, idx, .refused);
        return;
    }

    // NODATA 兜底（GSLB 分流保护）：NOERROR + 零应答记录。
    // 多上游应答不一致时（CDN/GSLB 按调度返回不同结果），NODATA 腿先到
    // 不能赢 —— 别的腿可能马上带回真实记录。见 Pending.empty_len 的注释。
    // 只拦 NOERROR+an=0；NXDOMAIN（rcode=3）语义是「名字不存在」，各上游
    // 高度一致，且 C 版也是先到先回，保持原样立即收尾。
    if (rcode == protocol.NOERROR and protocol.ancount(rx) == 0 and
        (p.next_idx < p.plan.n or p.n_legs > 1))
    {
        if (n <= p.buf.len) {
            @memcpy(p.buf[0..n], rx[0..n]);
            p.empty_len = n;
            p.empty_srv = leg.srv;
            p.empty_rtt_us = rtt;
            // 与 REFUSED 兜底互斥（理由同上）
            p.refused_len = 0;
            p.refused_srv = null;
        }
        // NODATA 不是服务器的错（可能只是调度差异），记 loser 而非 refused/timeout，
        // 不计入失败统计，避免把正常的公共 DNS 打进熔断。
        retireLeg(p, idx, .loser);
        return;
    }

    if (n > p.buf.len) {
        retireLeg(p, idx, .timeout);
        return;
    }
    @memcpy(p.buf[0..n], rx[0..n]);
    finalize(p, n, leg.srv, rtt, false);
}

// ---------------------------------------------------------------------------
// 收尾
// ---------------------------------------------------------------------------
fn finalize(p: *Pending, len: usize, srv: *Server, rtt_us: u64, refused: bool) void {
    const d = engine.d.?;

    // 必须把胜出的服务器写回 frec。
    //
    // forward.processReply() 的第一句就是 `const srv = fr.server orelse return true;`
    // —— fr.server 为空时它会在**写缓存之前**直接返回。UDP 腿路径从来不设这个
    // 字段（只有 switchToTcp 设过），于是异步模式下所有查询都「应答正确但永
    // 不缓存」：客户端拿得到结果，日志里却每次都是 forwarded，缓存形同虚设。
    // 同步路径不存在这个问题，因为 queryOneServerUdp() 发包前就赋值了。
    //
    // 放在这里（而不是 sendLeg）是有意的：hedge 模式下多条腿各自发包，谁先
    // 应答谁说了算，只有 finalize 的 srv 参数能准确表达「这份应答来自谁」。
    p.fr.server = srv;

    retireAllLegs(p, srv);
    if (refused) {
        balancer.onFailure(srv, d.server_cooldown_ms, util.monoMillis());
    } else {
        balancer.onSuccess(srv, rtt_us, util.monoMillis());
    }

    if (!forward.processReply(d, &p.fr, p.buf, len, p.now, false)) {
        // 应答被丢弃（--stop-dns-rebind 等），客户端只能靠超时重试
        freePending(p);
        return;
    }
    deliver(p, len, srv);
}

fn deliver(p: *Pending, len: usize, srv: *Server) void {
    const d = engine.d.?;
    // 关键一步：把 id 换回客户端原始 id（对应 forward.c:585）
    forward.restoreClientId(p.buf, &p.fr);
    const rcode = protocol.rcode(protocol.headerHb4(p.buf));
    forward.noteWinner(d, p.plan.master_idx, srv, rcode);
    _ = engine.answered.fetchAdd(1, .monotonic);

    switch (p.sink) {
        .udp => |u| server_mod.sendUdp(u.fd, p.buf[0..len], &u.client, u.limit),
        .tcp => |c| {
            // 顺序很重要：先摘掉连接对该查询的引用，再写。
            // `queueTcpReplyConn` 失败时会 `closeConn()`，而 closeConn 会看到
            // `c.pending` —— 若那时它仍指向本对象，就会提前 free 掉 p。
            if (c.pending == p) c.pending = null;
            queueTcpReplyConn(c, p.buf, len);
            c.resetInput();
        },
    }
    freePending(p);
}

fn finalizeFail(p: *Pending) void {
    // NODATA 兜底（优先级在 REFUSED 之前——它是「正常应答」，只是没有记录）：
    // 所有腿收齐且没有任何有效应答时，把暂存的 NODATA 还给客户端。
    // 此时 extractAddresses 看到的是所有上游一致同意的 NODATA，写负缓存是安全的。
    if (p.empty_len != 0 and p.empty_srv != null) {
        finalize(p, p.empty_len, p.empty_srv.?, p.empty_rtt_us, false);
        return;
    }
    // REFUSED 兜底：候选全部用尽但收到过 REFUSED，仍把最后那份还给客户端
    if (p.refused_len != 0 and p.refused_srv != null) {
        finalize(p, p.refused_len, p.refused_srv.?, p.refused_rtt_us, true);
        return;
    }
    log.warning("上游全部失败，返回 SERVFAIL: {s}", .{p.fr.qname});
    const qlen = @min(@min(p.qlen, p.fr.orig_len), p.buf.len);
    @memcpy(p.buf[0..qlen], p.fr.original[0..qlen]);
    _ = engine.servfail.fetchAdd(1, .monotonic);
    sendServfail(p, p.buf, qlen);
    freePending(p);
}

/// 回 SERVFAIL。`p` 用于与 TCP 连接解引用（见 deliver 里的说明）。
fn sendServfail(p: *Pending, buf: []u8, qlen: usize) void {
    const question_len = name.skipQuestions(buf, qlen) orelse qlen;
    rfc1035.setupReply(buf, protocol.F_RCODE, -1);
    protocol.setRcode(&buf[protocol.OFF_HB4], protocol.SERVFAIL);
    protocol.setAncount(buf, 0);
    protocol.setNscount(buf, 0);
    protocol.setArcount(buf, 0);
    const out = @min(question_len, buf.len);
    switch (p.sink) {
        .udp => |u| {
            _ = net.sendto(u.fd, buf[0..out], &u.client, 0) catch {};
        },
        .tcp => |c| {
            if (c.pending == p) c.pending = null;
            queueTcpReplyConn(c, buf, out);
            c.resetInput();
        },
    }
}

fn freePending(p: *Pending) void {
    // 必须先摘出在途表再释放。
    //
    // 曾经漏掉这一步：handleUpstreamReply() 里收到应答就 finalize + 释放，但这个
    // Pending 还挂在 engine.pend 上，紧接着 stepAll() 就在已释放的内存上跑
    // stepPending()，读到的 mode/legs 全是垃圾 —— 表现为「明明已经回包了，日志里
    // 却又冒出一条 SERVFAIL」，然后是二次释放和堆破坏。
    // 各条收尾路径的「调用者负责摘除」约定太容易漏，所以直接放在这里兜底。
    detachPending(p);

    for (p.legs[0..p.n_legs]) |leg| {
        _ = engine.demux.remove(keyOf(leg.sock_slot, leg.id));
        balancer.endQuery(leg.srv);
        if (leg.sock_slot < engine.socks.items.len) {
            if (engine.socks.items[leg.sock_slot]) |s| {
                if (s.legs > 0) s.legs -= 1;
            }
        }
    }
    p.n_legs = 0;
    if (p.mode == .tcp and p.tcp.fd >= 0) {
        net.close(p.tcp.fd);
        p.tcp.fd = -1;
    }
    if (p.buf.len != 0) bufPut(p.buf);
    p.buf = &.{};
    p.qlen = 0;
    p.mode = .udp;
    p.refused_srv = null;
    p.refused_len = 0;
    // 还给预分配池而非 allocator.destroy —— 进程生命周期内复用，
    // 避免运行时 mmap 让 RSS 在峰值流量下持续上涨触发 OOM。
    pendPut(p);
}

/// 把 p 从在途表摘下（调用者接管后续收尾）。
/// 注意：`engine.pend` 只在 handleReadable 之外被遍历，且这里不做元素搬移以外的
/// 假设 —— handleReadable 通过 Target 持有直接指针，`swapRemove` 不会让它们失效。
fn detachPending(p: *Pending) void {
    for (engine.pend.items, 0..) |x, i| {
        if (x == p) {
            _ = engine.pend.swapRemove(i);
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// 上游 TCP 回退（截断应答）
// ---------------------------------------------------------------------------
fn switchToTcp(p: *Pending, srv: *Server, trunc: []u8, trunc_len: usize) void {
    _ = engine.tcp_fallbacks.fetchAdd(1, .monotonic);
    // 与 forward.zig 同步路径保持同级别（debug），避免同一事件两条路径时有时无。
    log.debug("上游应答被截断，改用 TCP 重试: {s}", .{p.fr.qname});

    // 截断应答留在 buf 里：TCP 也失败时原样回给客户端（标准行为）
    const keep = @min(trunc_len, p.buf.len);
    @memcpy(p.buf[0..keep], trunc[0..keep]);
    p.trunc_len = keep;

    // UDP 阶段结束：腿全部退场。UDP 应答本身合法，不计失败。
    retireAllLegs(p, null);

    const fd = net.socketCreate(srv.addr.store.family, std.posix.SOCK.STREAM, std.posix.IPPROTO.TCP) catch {
        fallbackToTruncated(p, srv);
        return;
    };
    net.setNonBlock(fd) catch {};
    net.setReuseAddr(fd) catch {};
    net.connect(fd, &srv.addr) catch |e| {
        if (e != error.WouldBlock and e != error.InProgress) {
            net.close(fd);
            fallbackToTruncated(p, srv);
            return;
        }
    };

    const qlen = @min(@min(p.qlen, p.fr.orig_len), PKT_SZ - 2);

    // 注意顺序：必须先整体赋 p.tcp，再往 scratch 里拷 ——
    // `p.tcp = .{...}` 会把 scratch 重置成 undefined，先拷后赋等于白拷。
    p.mode = .tcp;
    p.tcp = .{
        .fd = fd,
        .srv = srv,
        .state = .connecting,
        .tx_off = 0,
        .len = qlen,
        .started_us = util.monoMicros(),
        .deadline_ms = util.monoMillis() + @as(i64, protocol.TCP_TIMEOUT_MS) * 2,
    };
    @memcpy(p.tcp.scratch[0..qlen], p.fr.original[0..qlen]);

    // 发往上游用新的随机 txid（与 UDP 路径一致），收回后由 restoreClientId 换回来
    const id = forward.getId();
    protocol.setId(&p.tcp.scratch, id);
    p.fr.id = id;
    p.fr.server = srv;
    p.fr.len = qlen;

    _ = srv.queries.fetchAdd(1, .monotonic);
    balancer.beginQuery(srv);
}

/// TCP 回退也走不通：把手里那份截断的 UDP 应答原样交给客户端
fn fallbackToTruncated(p: *Pending, srv: *Server) void {
    p.mode = .udp;
    p.n_legs = 0;
    balancer.onSuccess(srv, 0, util.monoMillis());
    const len = p.trunc_len;
    p.trunc_len = 0;
    if (len == 0) {
        finalizeFail(p);
        return;
    }
    deliver(p, len, srv);
}

fn handleTcpLegEvents(p: *Pending, revents: i16) void {
    const t = &p.tcp;
    if (t.fd < 0 or t.state == .done) return;

    if ((revents & (std.posix.POLL.ERR | std.posix.POLL.HUP)) != 0 and
        (revents & (std.posix.POLL.IN | std.posix.POLL.OUT)) == 0)
    {
        failTcpLeg(p);
        return;
    }

    switch (t.state) {
        .connecting => {
            var so_err: c_int = 0;
            var optlen: std.posix.socklen_t = @sizeOf(c_int);
            const rc = std.posix.system.getsockopt(
                t.fd,
                std.posix.SOL.SOCKET,
                std.posix.SO.ERROR,
                @ptrCast(&so_err),
                &optlen,
            );
            if (std.posix.errno(rc) != .SUCCESS or so_err != 0) {
                failTcpLeg(p);
                return;
            }
            // 连接建立：补上长度前缀，开始写查询
            var frame: [PKT_SZ + 2]u8 = undefined;
            protocol.putShort(&frame, 0, @intCast(t.len));
            @memcpy(frame[2 .. 2 + t.len], t.scratch[0..t.len]);
            @memcpy(t.scratch[0 .. 2 + t.len], frame[0 .. 2 + t.len]);
            t.len += 2;
            t.tx_off = 0;
            t.state = .writing;
            writeTcpLeg(p);
        },
        .writing => writeTcpLeg(p),
        .reading_len => {
            while (t.hdr_got < 2) {
                const n = net.recv(t.fd, t.hdr[t.hdr_got..], 0) catch |e| {
                    if (e == error.WouldBlock) return;
                    failTcpLeg(p);
                    return;
                };
                if (n == 0) {
                    failTcpLeg(p);
                    return;
                }
                t.hdr_got += n;
            }
            const rlen = protocol.getShort(&t.hdr, 0);
            if (rlen < protocol.HEADER_SIZE or rlen > p.buf.len) {
                failTcpLeg(p);
                return;
            }
            t.len = rlen;
            t.tx_off = 0;
            t.state = .reading_body;
            readTcpLegBody(p);
        },
        .reading_body => readTcpLegBody(p),
        .done => {},
    }
}

fn writeTcpLeg(p: *Pending) void {
    const t = &p.tcp;
    while (t.tx_off < t.len) {
        const w = net.sendto(t.fd, t.scratch[t.tx_off..t.len], null, 0) catch |e| {
            if (e == error.WouldBlock) return;
            failTcpLeg(p);
            return;
        };
        if (w == 0) return;
        t.tx_off += w;
    }
    t.hdr_got = 0;
    t.state = .reading_len;
}

fn readTcpLegBody(p: *Pending) void {
    const t = &p.tcp;
    while (t.tx_off < t.len) {
        // 直接读进 p.buf（应答的最终归属），省掉一次拷贝
        const n = net.recv(t.fd, p.buf[t.tx_off..t.len], 0) catch |e| {
            if (e == error.WouldBlock) return;
            failTcpLeg(p);
            return;
        };
        if (n == 0) {
            failTcpLeg(p);
            return;
        }
        t.tx_off += n;
    }

    const rlen = t.len;
    const srv = t.srv;
    const rtt: u64 = @intCast(@max(@as(i64, 0), util.monoMicros() - t.started_us));
    net.close(t.fd);
    t.fd = -1;
    t.state = .done;
    p.trunc_len = 0;

    if (!forward.checkReplyWith(p.buf, rlen, &p.fr, p.fr.id)) {
        log.debug("上游 TCP 应答校验失败: {s}", .{p.fr.qname});
        balancer.endQuery(srv);
        _ = srv.failed_queries.fetchAdd(1, .monotonic);
        balancer.onFailure(srv, cooldownMs(), util.monoMillis());
        p.mode = .udp;
        detachPending(p);
        finalizeFail(p);
        return;
    }

    _ = srv.last_reply.store(util.dnsmasqTime(), .monotonic);
    balancer.endQuery(srv);
    balancer.onSuccess(srv, rtt, util.monoMillis());
    p.mode = .udp;

    // TCP 模式没有 UDP 腿，retireAllLegs 是空操作；直接进 processReply + 投递
    if (!forward.processReply(engine.d.?, &p.fr, p.buf, rlen, p.now, false)) {
        detachPending(p);
        freePending(p);
        return;
    }
    detachPending(p);
    deliver(p, rlen, srv);
}

fn failTcpLeg(p: *Pending) void {
    const t = &p.tcp;
    if (t.fd >= 0) net.close(t.fd);
    t.fd = -1;
    t.state = .done;
    balancer.endQuery(t.srv);
    _ = t.srv.failed_queries.fetchAdd(1, .monotonic);
    balancer.onFailure(t.srv, cooldownMs(), util.monoMillis());

    p.mode = .udp;
    p.n_legs = 0;
    const srv = t.srv;
    const len = p.trunc_len;
    p.trunc_len = 0;

    detachPending(p);
    if (len != 0) {
        balancer.onSuccess(srv, 0, util.monoMillis());
        deliver(p, len, srv);
    } else {
        finalizeFail(p);
    }
}

// ---------------------------------------------------------------------------
// TCP 客户端连接
// ---------------------------------------------------------------------------
fn handleTcpConnEvents(c: *TcpConn, revents: i16) void {
    c.last_ms = util.monoMillis();

    if ((revents & (std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL)) != 0 and
        (revents & (std.posix.POLL.IN | std.posix.POLL.OUT)) == 0)
    {
        closeConn(c);
        return;
    }

    if (c.out_len > 0) {
        writePending(c) catch {
            closeConn(c);
            return;
        };
        if (c.out_len > 0) return; // 还没写完
    }

    if (c.pending != null) return; // 正在等上游，先不读下一个查询

    if ((revents & std.posix.POLL.IN) != 0) {
        readAndServe(c) catch closeConn(c);
    }
}

fn writePending(c: *TcpConn) !void {
    const buf = c.buf orelse return error.Closed;
    while (c.out_off < c.out_len) {
        const n = net.sendto(c.fd, buf[c.out_off..c.out_len], null, 0) catch |e| {
            if (e == error.WouldBlock) return;
            return error.WriteFailed;
        };
        if (n == 0) return error.WriteFailed;
        c.out_off += n;
    }
    c.out_off = 0;
    c.out_len = 0;
}

/// 把 `payload` 按 2 字节长度前缀成帧放进连接的输出缓冲。
/// `payload` 可能就指向连接自己的缓冲（本地应答路径），此时必须用 copyBackwards
/// 处理重叠 —— `@memcpy` 一旦重叠就直接 panic。
fn queueTcpReplyConn(c: *TcpConn, payload: []const u8, len: usize) void {
    if (c.dead or c.fd < 0) return;
    const buf = c.ensureBuf() orelse {
        closeConn(c);
        return;
    };
    const n = @min(len, payload.len);
    const need = n + 2;
    if (need > buf.len) {
        closeConn(c);
        return;
    }

    if (payload.ptr == buf.ptr) {
        std.mem.copyBackwards(u8, buf[2 .. 2 + n], buf[0..n]);
    } else {
        @memcpy(buf[2 .. 2 + n], payload[0..n]);
    }
    protocol.putShort(buf, 0, @intCast(n));
    c.out_off = 0;
    c.out_len = need;
    writePending(c) catch closeConn(c);
}

fn readAndServe(c: *TcpConn) !void {
    const buf = c.ensureBuf() orelse return error.NoMemory;

    // 阶段一：2 字节长度前缀
    while (c.hdr_got < 2) {
        const n = net.recv(c.fd, c.hdr[c.hdr_got..], 0) catch |e| {
            if (e == error.WouldBlock) return;
            return error.ReadFailed;
        };
        if (n == 0) return error.Eof;
        c.hdr_got += n;
    }
    if (c.need == 0) {
        const plen = protocol.getShort(&c.hdr, 0);
        if (plen < protocol.HEADER_SIZE or plen > buf.len) return error.BadFrame;
        c.need = plen;
        c.got = 0;
    }

    // 阶段二：报文
    while (c.got < c.need) {
        const n = net.recv(c.fd, buf[c.got..c.need], 0) catch |e| {
            if (e == error.WouldBlock) return;
            return error.ReadFailed;
        };
        if (n == 0) return error.Eof;
        c.got += n;
    }

    const plen = c.need;
    const now = util.dnsmasqTime();
    const d = engine.d.?;
    _ = d.query_count.fetchAdd(1, .monotonic);
    c.queries += 1;

    var namebuf: [rfc1035.MAXNAMEBUF]u8 = undefined;
    const req = rfc1035.extractRequest(buf, plen, &namebuf) orelse {
        c.resetInput();
        return;
    };
    log.logQuery(protocol.F_QUERY | req.flags, req.name, c.client.toAllAddr(), null, req.qtype);

    // 本地应答（TCP 不受 512 字节限制）
    const ans = rfc1035.answerRequest(d, buf, plen, server_mod.TCP_PACKET_MAX, now, req, &c.client);
    if (ans.len != 0) {
        queueTcpReplyConn(c, buf, ans.len);
        c.resetInput();
        return;
    }

    // 未命中 -> 转上游（同样先走 UDP，截断时再回退 TCP）
    const p = pendGet() orelse return error.NoMemory;
    const b = bufGet() orelse {
        pendPut(p);
        return error.NoMemory;
    };
    p.* = .{
        .buf = b,
        .sink = .{ .tcp = c },
        .now = now,
        .started_ms = util.monoMillis(),
    };
    const cp = @min(plen, b.len);
    @memcpy(b[0..cp], buf[0..cp]);
    p.qlen = cp;
    initFrec(p, req, &c.client, b, cp);

    if (!planAndStart(d, p)) {
        // 无可用上游，SERVFAIL 已就绪并交给了连接
        return;
    }
    c.pending = p;

    // 输入阶段复位，但保留 c.need，直到应答写完才读下一个查询
    c.hdr_got = 0;
    c.got = 0;
    c.need = 0;
    c.out_off = 0;
    c.out_len = 0;

    enqueue(p);
}

/// 关闭连接。**故意不动 `c.pending`** ——
///
/// 那个在途查询可能还躺在 inbox 里（还没进 `engine.pend`），也可能正被引擎当作
/// TCP 上游腿处理。在这里释放它会造成两条路径上的悬垂/重复释放。
/// 正确做法是：只把连接标记为 dead 并关掉 fd，让那个查询自己跑完它的生命周期
/// （`deliver` / `sendServfail` 会因为 `c.dead` 而丢弃回复），跑完后再把
/// `c.pending` 清空。只有那时才允许 `sweepTcpConns()` 真正回收连接对象。
fn closeConn(c: *TcpConn) void {
    if (c.dead) return;
    c.dead = true;
    if (c.fd >= 0) net.close(c.fd);
    c.fd = -1;
    c.out_off = 0;
    c.out_len = 0;
    if (c.buf) |b| {
        engine.allocator.free(b);
        c.buf = null;
    }
}

fn sweepTcpConns() void {
    const now = util.monoMillis();
    var i: usize = 0;
    while (i < engine.conns.items.len) {
        const c = engine.conns.items[i];
        if (!c.dead and c.pending == null and c.out_len == 0 and now - c.last_ms > TCP_IDLE_MS) {
            closeConn(c);
        }
        // 只有「已关闭」且「在途查询已收尾」的连接才能销毁：
        // 在途查询的 `sink` 还指着这个对象，提前 destroy 就是悬垂指针。
        if (c.dead and c.pending == null) {
            engine.allocator.destroy(c);
            _ = engine.conns.swapRemove(i);
            continue;
        }
        i += 1;
    }
}

// ---------------------------------------------------------------------------
// 静默（SIGHUP 重载）/ 清理
// ---------------------------------------------------------------------------
fn doQuiesce() void {
    // 在途查询手里的 *Server 即将被 destroy，必须全部收尾
    while (engine.pend.items.len > 0) {
        const p = engine.pend.items[engine.pend.items.len - 1];
        _ = engine.pend.pop();
        retireAllLegs(p, null);
        const qlen = @min(@min(p.qlen, p.fr.orig_len), p.buf.len);
        sendServfail(p, p.buf, qlen);
        freePending(p);
    }
    drainInboxQuiesce();

    for (engine.socks.items) |maybe| {
        if (maybe) |s| {
            if (s.fd >= 0) net.close(s.fd);
            engine.allocator.destroy(s);
        }
    }
    engine.socks.clearRetainingCapacity();
    engine.demux.clearRetainingCapacity();

    for (engine.conns.items) |c| {
        // 上面的循环已经把 Pending 全部释放了，先把连接上的引用摘掉再关
        c.pending = null;
        closeConn(c);
        engine.allocator.destroy(c);
    }
    engine.conns.clearRetainingCapacity();
}

fn drainInboxQuiesce() void {
    while (true) {
        engine.qmutex.lockUncancelable(engine.io);
        const c = engine.conns_inbox.pop();
        engine.qmutex.unlock(engine.io);
        const conn = c orelse break;
        closeConn(conn);
        engine.allocator.destroy(conn);
    }
    while (true) {
        engine.qmutex.lockUncancelable(engine.io);
        const p = engine.inbox.pop();
        engine.qmutex.unlock(engine.io);
        const pend = p orelse break;
        const qlen = @min(@min(pend.qlen, pend.fr.orig_len), pend.buf.len);
        sendServfail(pend, pend.buf, qlen);
        freePending(pend);
    }
}

fn ackQuiesce() void {
    engine.rmutex.lockUncancelable(engine.io);
    engine.quiesce_ack = true;
    engine.rcond.signal(engine.io);
    engine.rmutex.unlock(engine.io);
}

/// 主线程在 SIGHUP 重载前调用：让引擎把手上所有 `*Server` 引用放掉，
/// 之后 `domain.cleanupServers()` 才能安全释放它们。
pub fn quiesce() void {
    if (!isRunning()) return;
    engine.rmutex.lockUncancelable(engine.io);
    engine.quiesce_ack = false;
    engine.rmutex.unlock(engine.io);

    engine.quiesce_req.store(true, .release);
    wake();

    engine.rmutex.lockUncancelable(engine.io);
    while (!engine.quiesce_ack) engine.rcond.waitUncancelable(engine.io, &engine.rmutex);
    engine.rmutex.unlock(engine.io);
}

/// 重载完成后恢复引擎（与 `quiesce()` 配对）。`resume` 是 Zig 关键字，故用 unquiesce。
pub fn unquiesce() void {
    if (!isRunning()) return;
    engine.resume_req.store(true, .release);
    wake();
}

fn cleanup() void {
    while (engine.pend.items.len > 0) {
        const p = engine.pend.pop().?;
        freePending(p);
    }
    engine.pend.clearRetainingCapacity();

    // inbox 里还可能有没来得及处理的（关停太快时）
    while (true) {
        engine.qmutex.lockUncancelable(engine.io);
        const p = engine.inbox.pop();
        const c = engine.conns_inbox.pop();
        engine.qmutex.unlock(engine.io);
        if (p) |pend| freePending(pend);
        if (c) |conn| {
            closeConn(conn);
            engine.allocator.destroy(conn);
        }
        if (p == null and c == null) break;
    }

    for (engine.conns.items) |c| {
        c.pending = null;
        closeConn(c);
        engine.allocator.destroy(c);
    }
    engine.conns.clearRetainingCapacity();

    for (engine.socks.items) |maybe| {
        if (maybe) |s| {
            if (s.fd >= 0) net.close(s.fd);
            engine.allocator.destroy(s);
        }
    }
    engine.socks.clearRetainingCapacity();
    engine.demux.clearRetainingCapacity();
}
