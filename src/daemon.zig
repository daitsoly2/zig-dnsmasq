// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! daemon.zig — 对应 C 源码 dnsmasq.h 的 struct daemon / struct server / struct listener
//! 以及 dnsmasq.c 中的全局状态。
//!
//! 设计说明：
//!   * C 版本使用全局 `struct daemon *daemon`，本移植保留同样的全局单例
//!     （`pub var daemon: Daemon`），启动线程前完成初始化，之后只读或受锁保护。
//!   * 「缓存」由 cache.Cache 自带互斥锁保护；服务器统计使用原子计数，
//!     便于多线程查询时无锁累加。

const std = @import("std");
const protocol = @import("protocol.zig");
const addr = @import("addr.zig");
const cache = @import("cache.zig");
const log = @import("log.zig");
const net = @import("net.zig");

const Allocator = std.mem.Allocator;
const Atomic = std.atomic.Value;

/// 多上游调度策略（本移植扩展；dnsmasq 只有 sticky 与 all-servers 两种行为）
pub const BalanceMode = enum {
    /// dnsmasq 原生：粘住本组最近一次应答的上游（last_server），
    /// 并周期性「全发」复检（见 forward.c:427-436）。不均衡，但完全兼容。
    sticky,
    /// 动态负载均衡：按「预期完成时间」选路 —— (在途数 + 1) × EWMA 延迟，
    /// 取最小者。快的上游自动多分流量，慢的/在途多的自动少分。
    dynamic,
    /// 平滑加权轮询：权重由 EWMA 延迟推导（延迟越低权重越高），
    /// 按 Nginx smooth weighted round-robin 的方式平滑展开。
    swrr,
    /// 轮询：在候选集合内依次取，不看延迟。
    round_robin,
    /// 随机：从候选中随机取一台。
    random,
};

/// 对应 struct server
/// 单个 resolv.conf 文件的内容快照，用于 --poll 变更检测。
///
/// 存内容哈希而不是 stat：本移植是静态 musl、不链接 libc（所以 std.c.statx
/// 用不了），而 Zig 0.16 std 里其余 stat API 又都绑在新的 Io 抽象上 —— 依赖
/// 太重。resolv.conf 通常只有几百字节，每个轮询周期读一次的成本可以忽略，
/// 换来的是零依赖与「内容真变了才重载」的等价语义。
pub const ResolvStat = struct {
    hash: u64 = 0,
    /// false 表示上次没能读到该文件（例如文件当时不存在）
    valid: bool = false,
};

pub const Server = struct {
    flags: u16 = 0,
    /// 该服务器负责的域名（server=/dom/1.2.3.4 或 local=/dom/）
    domain: ?[]const u8 = null,
    /// 是否为「本地域」（local=/dom/ 或 server=/dom/#）
    local: bool = false,
    /// 通配域名（server=/*/8.8.8.8）
    wildcard: bool = false,
    /// 无点域名（server=//8.8.8.8）
    for_nodots: bool = false,
    /// 该服务器匹配的域名长度（排序与优先级用）
    domain_len: usize = 0,

    addr: addr.SockAddr = SockAddr_zero,
    source_addr: ?addr.SockAddr = null,
    iface: ?[]const u8 = null,
    tcpfd: net.fd_t = -1,

    // 运行期统计（多线程用原子量）
    queries: Atomic(u64) = Atomic(u64).init(0),
    failed_queries: Atomic(u64) = Atomic(u64).init(0),
    nxdomain_replies: Atomic(u64) = Atomic(u64).init(0),
    retrys: Atomic(u64) = Atomic(u64).init(0),
    /// 上一次成功应答的时间（用于避免反复使用坏服务器）
    last_reply: Atomic(i64) = Atomic(i64).init(0),
    /// 本次「并发竞速」中作为胜出者的次数（本移植扩展，便于观测）
    concurrent_wins: Atomic(u64) = Atomic(u64).init(0),

    // -----------------------------------------------------------------------
    // 动态负载均衡所需的运行期状态（本移植扩展，dnsmasq 无对应字段）
    //
    // dnsmasq 只有「粘住最近成功的那台」（last_server）与 `--all-servers`
    // （全发取最快）两种模式。要在多台上游之间做动态负载均衡，必须额外
    // 观测三件事，否则无法判断该给谁分配流量：
    //   1. 在途请求数 —— 避免把查询堆到正在排队的上游
    //   2. 平滑 RTT（EWMA）—— 让快的上游承担更多
    //   3. 连续失败 / 熔断 —— 及时隔离坏掉的上游
    // -----------------------------------------------------------------------
    /// 当前在途（已发出、尚未收到应答或超时）的查询数
    in_flight: Atomic(u32) = Atomic(u32).init(0),
    /// 平滑往返时间（微秒，EWMA）。0 表示尚无样本。
    ewma_us: Atomic(u64) = Atomic(u64).init(0),
    /// 累计样本数（用于判断 EWMA 是否已经收敛）
    rtt_samples: Atomic(u64) = Atomic(u64).init(0),
    /// 熔断截止时间（util.monoMillis() 时基）；此刻之前该上游不参与选路
    cooldown_until_ms: Atomic(i64) = Atomic(i64).init(0),
    /// 上次「半开探测」放行的时刻（util.monoMillis() 时基）。
    /// 冷却中的上游每 SERVER_PROBE_INTERVAL_MS 放行一次，用于主动探活。
    last_probe_ms: Atomic(i64) = Atomic(i64).init(0),
    /// 最近一次贡献样本时的全局查询序号（对应 Daemon.query_seq）。
    /// 与 SERVER_PROBE_GAP 配合实现「按查询次数计费」的探索预算：序号落后
    /// 超过 PROBE_GAP 就说明这台被冷落了，给它一次重采样机会。
    probe_seq: Atomic(u64) = Atomic(u64).init(0),
    /// 熔断触发次数（观测用）
    circuit_trips: Atomic(u64) = Atomic(u64).init(0),
    /// 平滑加权轮询用的当前权重（仅 swrr 策略下有意义）
    swrr_current: Atomic(i64) = Atomic(i64).init(0),

    // -----------------------------------------------------------------------
    // 「同一域名组」共享的选路状态（对应 dnsmasq.h struct server 的
    // last_server / forwardcount / forwardtime / arrayposn，见 dnsmasq.h:620/628/629）。
    //
    // C 版把这些字段放在 `struct server *master` —— 即 filter_servers() 返回的
    // 组内第一台上；本移植同样只读写组内第一台（别的成员上这些字段不被使用）。
    // -----------------------------------------------------------------------
    /// 在 serverarray 里的下标（对应 struct server::arrayposn）
    arrayposn: usize = 0,
    /// 本组「最近一次应答」的服务器下标；-1 表示未知（对应 last_server）
    last_server: Atomic(i32) = Atomic(i32).init(-1),
    /// 自上次「全发」以来的查询计数（对应 forwardcount）
    forwardcount: Atomic(u32) = Atomic(u32).init(0),
    /// 上次「全发」的时间（对应 forwardtime）
    forwardtime: Atomic(i64) = Atomic(i64).init(0),
    /// 连续失败次数：成功后清零。用于把持续无应答的上游暂时降到候选末尾。
    /// （本移植扩展；dnsmasq 靠 forwardcount/forwardtime 的定期全发来复检）
    consecutive_failures: Atomic(u32) = Atomic(u32).init(0),

    pub fn isLocal(self: *const Server) bool {
        return (self.flags & protocol.SERV_LITERAL_ADDRESS) != 0 or self.local;
    }

    pub fn addrText(self: *const Server, buf: []u8) []const u8 {
        return self.addr.writeTo(buf);
    }
};

const SockAddr_zero: addr.SockAddr = .{ .store = .{ .family = 0 }, .len = 0 };

/// 对应 struct listener
pub const Listener = struct {
    fd: net.fd_t = -1,
    tcpfd: net.fd_t = -1,
    family: u16 = 0,
    port: u16 = 0,
    /// 指向所属接口的地址（这里保存监听地址本身）
    bound: addr.SockAddr = SockAddr_zero,
    /// 监听地址的 IPv4 表示（网络序；非 IPv4 监听为 0）。
    /// 等价于 IP_PKTINFO 收到的「目的地址」—— 因为本移植**每个具体地址一个
    /// socket**，目的地址必然等于绑定地址。--localise-queries 靠它判断
    /// 「查询到达的网段」。
    local4: u32 = 0,
    /// local4 所在接口的掩码（网络序）；0 表示未知（通配绑定或查不到）。
    netmask4: u32 = 0,
};

/// 对应 C dnsmasq.h: `struct doctor`（`--alias`）：把上游返回的 A 记录按掩码改写。
/// 四个地址一律用**网络序**（与 `addr.AllAddr.ip4` / `struct in_addr` 同序），
/// 只有区间比较时才转主机序 —— 与 C 的 is_same_net / ntohl 用法一致。
pub const Doctor = struct {
    /// 区间起点（或非区间时的匹配基址）
    in: u32,
    /// 区间终点；0 表示「不是区间」，用 mask 做同网段判定
    end: u32 = 0,
    /// 改写后的地址
    out: u32,
    /// 掩码，默认 /32
    mask: u32 = 0xffffffff,
};

pub const Daemon = struct {
    allocator: Allocator = std.heap.page_allocator,
    io: std.Io = undefined,

    // ---------------- 选项位（对应 OPT_*）----------------
    /// 对应 dnsmasq 的 `unsigned int options[OPTION_SIZE]`：
    /// 位序号即 protocol.OPT_xxx 的值，可直接与 C 源码对照。
    options: [protocol.OPTION_WORDS]u32 = [_]u32{0} ** protocol.OPTION_WORDS,

    // ---------------- DNS 配置 ----------------
    port: u16 = protocol.NAMESERVER_PORT,
    /// --edns-packet-max
    edns_pktsz: u16 = protocol.EDNS_PKTSZ,
    /// --cache-size
    cachesize: i32 = @intCast(protocol.CACHESIZ),
    /// --local-ttl / --neg-ttl / --max-ttl / --max-cache-ttl / --min-cache-ttl
    local_ttl: u32 = 0,
    neg_ttl: u32 = 0,
    max_ttl: u32 = 0,
    max_cache_ttl: u32 = 0,
    min_cache_ttl: u32 = 0,
    /// --use-stale-cache（0=禁用；>0 = 过期后该秒数内仍可服务）
    /// 对应 C 的 daemon->cache_max_expiry；-1 在 Zig 侧省略，因为常规配置
    /// 只会给一个有限秒数（UCI 默认 3600）。
    stale_cache_ttl: u32 = 0,
    auth_ttl: u32 = protocol.AUTH_TTL,
    /// --max-cache-ttl 的上限，0 表示不限制
    use_max_cache_ttl: bool = false,

    /// --domain / --expand-hosts
    domain: ?[]const u8 = null,
    expand_hosts: bool = false,

    /// --dns-forward-max
    dns_forward_max: u32 = 150,
    /// --dns-loop-detect
    loop_detect: bool = false,

    /// --threads：本移植新增的多线程查询参数（默认按 CPU 数）
    threads: usize = 0,

    // ---------------- 文件与路径 ----------------
    /// --resolv-file（默认 /etc/resolv.conf）
    resolv_files: std.ArrayList([]const u8) = .empty,
    /// resolv.conf 上一次的 stat 快照，与 resolv_files 一一对应。
    /// 用途：轮询时先比对 mtime/size，文件没变就完全不重读 —— 既省掉每
    /// 20 秒一次的无谓读盘，也避免重复追加同名上游（那是致命的：服务器
    /// 数组会一路膨胀，每条查询要竞速的上游越来越多，最终大面积超时）。
    resolv_stats: std.ArrayList(ResolvStat) = .empty,
    /// --addn-hosts / --hostsdir 读到的额外 hosts 文件
    addn_hosts: std.ArrayList([]const u8) = .empty,
    /// --hostsdir=<目录>：目录里的**每个普通文件**都当 hosts 文件读。
    /// 对应 C 的 `daemon->dynamic_dirs`（flags 含 AH_HOSTS），见
    /// `inotify.c:set_dynamic_inotify`。odhcpd 把 `odhcpd.hosts.<ifname>`
    /// 写在这个目录里，是 DHCP → DNS 的接合点。
    hosts_dirs: std.ArrayList([]const u8) = .empty,
    /// --conf-file
    conf_file: ?[]const u8 = null,
    /// --log-facility
    log_file: ?[]const u8 = null,
    /// --log-facility=<facility 名> 解析出来的 syslog facility 值。
    /// 与 `log_file` 互斥：C 的判据是「值里有没有斜杠 / 是不是 "-"」
    /// （option.c:2284），见 `log.classifyLogFacility`。
    log_facility: ?u8 = null,
    /// --pid-file
    pid_file: ?[]const u8 = null,
    /// --user / --group（本移植暂不切换权限，仅记录）
    user: ?[]const u8 = null,
    group: ?[]const u8 = null,
    /// --interface / --listen-address / --except-interface / --local-service
    listen_addrs: std.ArrayList(addr.SockAddr) = .empty,
    /// --interface=<网卡名>
    interfaces: std.ArrayList([]const u8) = .empty,
    /// --except-interface=<网卡名>（与 interfaces 一起决定监听哪些地址）
    except_interfaces: std.ArrayList([]const u8) = .empty,
    /// --rebind-domain-ok=/dom/…/：豁免 rebind 防护的域名列表（对应 C 的 daemon->no_rebind）
    no_rebind: std.ArrayList([]const u8) = .empty,
    /// --alias=…：上游 A 记录改写规则（对应 C 的 daemon->doctors）
    doctors: std.ArrayList(Doctor) = .empty,

    // ---------------- 服务器与域名 ----------------
    /// 所有服务器（含 local=/dom/ 与 server=/dom/ip）
    servers: std.ArrayList(*Server) = .empty,
    /// 按域名长度排序后的服务器数组（对应 dnsmasq 的 serverarray）
    serverarray: std.ArrayList(*Server) = .empty,
    /// --address=/dom/ip 生成的本地 RR（对应 blockdata.c，暂存）
    address_list: std.ArrayList(AddressRule) = .empty,

    // ---------------- 多上游并发查询（本移植扩展，dnsmasq 无对应选项）----------------
    /// --concurrent-servers=<n>：触发「全发」时最多并发 n 台上游。
    ///   0（默认）= 组内全部，1 = 退化为串行（等价 dnsmasq 的行为）。
    /// 对应 config.h 的 FR_MAX_CONCURRENT 上限。
    concurrent_servers: usize = 0,
    /// --hedge-after=<ms>：阶梯式补发。触发「全发」时先只发 1 台，
    /// 若 ms 毫秒内无有效应答再补发下一台，直到发完候选或达到并发上限。
    ///   0（默认）= 立即全部并发发出（等价 dnsmasq --all-servers 的行为）。
    hedge_ms: i32 = 0,

    // ---------------- 上游调度策略（本移植扩展）----------------
    /// --balance=<mode>：多台上游之间的选路方式。默认 sticky，即 dnsmasq 原生语义。
    balance_mode: BalanceMode = .sticky,
    /// 单台上游的等待时间（毫秒）。0 表示 dnsmasq 原生语义：一直等到
    /// 整个 TIMEOUT 用完才换下一台。非 0 即「快速重试」：每 fast_retry_ms
    /// 换一台上游，总预算仍受 TIMEOUT 约束（对应 --fast-dns-retry）。
    ///
    /// 默认取 DEFAULT_FAST_RETRY_MS：只要启用了非 sticky 的均衡策略，
    /// 「坏上游要能快速让位」就是均衡成立的前提，因此默认开启。
    fast_retry_ms: i32 = protocol.DEFAULT_FAST_RETRY_MS,
    /// --server-cooldown=<ms>：上游连续失败后熔断的基准冷却时长（默认 2000ms）。
    /// 实际冷却会按连续失败次数退避，上限 SERVER_COOLDOWN_MAX_MS。
    server_cooldown_ms: i64 = protocol.SERVER_COOLDOWN_DEFAULT_MS,
    /// round-robin 游标
    rr_cursor: Atomic(u32) = Atomic(u32).init(0),

    /// --sync-forward：禁用异步转发引擎，退回「工作线程同步阻塞等上游」的旧模型。
    ///
    /// 保留这条路径有两个用途：
    ///   1. 引擎启动失败时的自动兜底（见 main.zig）；
    ///   2. 在同一台机器上做严格 A/B 对比 —— 拿历史数字比是不可靠的
    ///      （实机波动可达 5 倍，见 REAL-ENV-TEST-REPORT.html 的说明）。
    sync_forward: bool = false,

    // ---------------- 运行期 ----------------
    cache: cache.Cache = undefined,
    cache_ready: bool = false,
    listeners: std.ArrayList(Listener) = .empty,
    packet_buff_sz: usize = protocol.PACKET_BUFF_SZ,
    query_count: Atomic(u64) = Atomic(u64).init(0),
    /// 全局「选路次数」计数（每次 balancer.collect() 自增一次）。
    /// 供 Server.probe_seq 做差值，实现按查询次数计费的探索预算。
    query_seq: Atomic(u64) = Atomic(u64).init(0),
    running: Atomic(bool) = Atomic(bool).init(true),
    /// SIGHUP 触发的重载标记
    reload: Atomic(bool) = Atomic(bool).init(false),
    /// 启动时间
    start_time: i64 = 0,

    // ---------------- 日志相关 ----------------
    log_queries: bool = false,

    // ---------------- 辅助 ----------------
    /// 对应 dnsmasq.h 的 option_bool(x)
    pub fn option(self: *const Daemon, opt: u32) bool {
        return (self.options[opt / protocol.OPTION_BITS] & protocol.optBit(opt)) != 0;
    }

    /// 对应 set_option_bool(x)
    pub fn setOpt(self: *Daemon, opt: u32) void {
        self.options[opt / protocol.OPTION_BITS] |= protocol.optBit(opt);
    }

    /// 对应 reset_option_bool(x)
    pub fn resetOpt(self: *Daemon, opt: u32) void {
        self.options[opt / protocol.OPTION_BITS] &= ~protocol.optBit(opt);
    }

    /// 新建一个 server 记录（domain 会被复制）
    pub fn newServer(self: *Daemon) !*Server {
        const s = try self.allocator.create(Server);
        s.* = .{};
        return s;
    }

    pub fn addServer(self: *Daemon, s: *Server) !void {
        try self.servers.append(self.allocator, s);
    }

    /// 清空服务器列表
    pub fn clearServers(self: *Daemon) void {
        for (self.servers.items) |s| {
            if (s.domain) |d| self.allocator.free(d);
            if (s.iface) |i| self.allocator.free(i);
            self.allocator.destroy(s);
        }
        self.servers.clearRetainingCapacity();
        self.serverarray.clearRetainingCapacity();
    }

    /// 统计输出（对应 dnsmasq 的 SIGUSR1 输出）
    /// 输出运行期统计（SIGUSR1 / 退出时）。
    /// 每台上游一行，末尾附一行缓存统计 —— 便于脚本抓取（压测脚本按前缀解析）。
    pub fn dumpStats(self: *Daemon, w: anytype) void {
        const balancer = @import("balancer.zig");
        var buf: [256]u8 = undefined;
        var n_upstream: usize = 0;

        for (self.servers.items) |s| {
            if (s.isLocal()) continue;
            const line = balancer.formatServerStat(s, &buf);
            w.print("{s}\n", .{line}) catch {};
            n_upstream += 1;
        }
        if (n_upstream == 0) w.print("server: 未配置上游\n", .{}) catch {};

        if (self.cache_ready) {
            const st = self.cache.stats();
            // 注意两组计数的口径不同：
            //   lookups  = 单次 findByName/findByAddr 的次数（一次查询会累加多次，
            //              拿它算命中率会把分母放大好几倍）
            //   queries  = 单次查询的最终去向，命中率要用这一组
            const qtotal = st.query_hits + st.query_misses;
            const permille: u64 = if (qtotal == 0) 0 else (st.query_hits * 1000) / qtotal;
            w.print(
                "cache entries={d}/{d} lookups={d}/{d} queries hit={d} miss={d} config={d} hitrate={d}.{d}%\n",
                .{
                    self.cache.countEntries(),
                    self.cache.cachesize,
                    st.hits,
                    st.misses,
                    st.query_hits,
                    st.query_misses,
                    st.query_local_config,
                    permille / 10,
                    permille % 10,
                },
            ) catch {};
        }

        w.print("queries total={d}\n", .{self.query_count.load(.monotonic)}) catch {};
    }

    pub fn deinit(self: *Daemon) void {
        if (self.cache_ready) self.cache.deinit();
        self.clearServers();
        for (self.resolv_files.items) |p| self.allocator.free(p);
        self.resolv_files.deinit(self.allocator);
        self.resolv_stats.deinit(self.allocator);
        for (self.addn_hosts.items) |p| self.allocator.free(p);
        self.addn_hosts.deinit(self.allocator);
        for (self.hosts_dirs.items) |p| self.allocator.free(p);
        self.hosts_dirs.deinit(self.allocator);
        // listen_addrs 里存的是 SockAddr **值**（append 时按值拷入），
        // 元素内存由 ArrayList 自己的缓冲区持有 —— deinit 会释放它。
        // 曾经这里写成 `for (items) |*a| destroy(a)`：那是对「数组内部的
        // 指针」调用 destroy，等于 free 一个非分配起点，属于 UB
        // （正常退出路径必然执行到，只是页分配器下大多没立刻炸）。
        self.listen_addrs.deinit(self.allocator);
        for (self.interfaces.items) |i| self.allocator.free(i);
        self.interfaces.deinit(self.allocator);
        for (self.except_interfaces.items) |i| self.allocator.free(i);
        self.except_interfaces.deinit(self.allocator);
        self.no_rebind.deinit(self.allocator);
        self.doctors.deinit(self.allocator);
        self.servers.deinit(self.allocator);
        self.serverarray.deinit(self.allocator);
        for (self.address_list.items) |r| {
            self.allocator.free(r.domain);
            if (r.addr_name) |n| self.allocator.free(n);
        }
        self.address_list.deinit(self.allocator);
        self.listeners.deinit(self.allocator);
        if (self.domain) |v| self.allocator.free(v);
        if (self.conf_file) |v| self.allocator.free(v);
        if (self.log_file) |v| self.allocator.free(v);
        if (self.pid_file) |v| self.allocator.free(v);
        if (self.user) |v| self.allocator.free(v);
        if (self.group) |v| self.allocator.free(v);
    }
};

/// --address=/dom/ip 规则（对应 blockdata.c 的 blockdata 简化版）
pub const AddressRule = struct {
    domain: []const u8,
    wildcard: bool,
    addr4: ?u32 = null,
    addr6: ?[16]u8 = null,
    addr_name: ?[]const u8 = null,
    local: bool = false,
};

/// 全局单例指针（对应 C 的 `struct daemon *daemon`）。
///
/// 这里**必须**是指针而不是值：`Daemon` 内含多个 `std.ArrayList`，
/// 按值拷贝会让副本与原实例的 `items`/`len` 各自独立 —— 之前正是这样
/// 导致 `buildServerArray()` 写进本地实例、而工作线程读副本，
/// 上游服务器数组永远是空的。启动线程前设置一次，之后只读。
pub var instance: ?*Daemon = null;

/// 取全局实例。未初始化时属于内部错误（线程启动前必须已设置）。
pub fn get() *Daemon {
    return instance orelse @panic("Daemon 全局实例尚未初始化");
}

pub fn optionBool(opt: u32) bool {
    return get().option(opt);
}

/// 取当前时间（对应 dnsmasq 每轮循环里的 now）
pub fn now() i64 {
    const util = @import("util.zig");
    return util.dnsmasqTime();
}

test "daemon option bits and server list" {
    const testing = std.testing;
    var d = Daemon{ .allocator = testing.allocator };
    defer d.deinit();

    try testing.expect(!d.option(protocol.OPT_BOGUSPRIV));
    d.setOpt(protocol.OPT_BOGUSPRIV);
    try testing.expect(d.option(protocol.OPT_BOGUSPRIV));
    // 位序号与 dnsmasq.h 一致：OPT_BOGUSPRIV=0，OPT_NODOTS_LOCAL=12，OPT_LOCAL_SERVICE=49
    try testing.expectEqual(@as(u32, 0), protocol.OPT_BOGUSPRIV);
    try testing.expectEqual(@as(u32, 12), protocol.OPT_NODOTS_LOCAL);
    try testing.expectEqual(@as(u32, 49), protocol.OPT_LOCAL_SERVICE);
    d.setOpt(protocol.OPT_LOCAL_SERVICE);
    try testing.expect(d.option(protocol.OPT_LOCAL_SERVICE));
    try testing.expect(!d.option(protocol.OPT_NODOTS_LOCAL));
    d.resetOpt(protocol.OPT_LOCAL_SERVICE);
    try testing.expect(!d.option(protocol.OPT_LOCAL_SERVICE));

    const s = try d.newServer();
    s.flags = protocol.SERV_USE_RESOLV;
    s.addr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 8, 8, 8, 8 }), 53);
    try d.addServer(s);
    try testing.expectEqual(@as(usize, 1), d.servers.items.len);

    var buf: [64]u8 = undefined;
    try testing.expectEqualStrings("8.8.8.8#53", d.servers.items[0].addrText(&buf));
}
