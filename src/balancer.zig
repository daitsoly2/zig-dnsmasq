// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! balancer.zig — 多上游动态负载均衡（本移植扩展）
//!
//! ## 为什么需要这个模块
//!
//! dnsmasq 原生只有两种使用上游的方式，都不是负载均衡：
//!
//!   * 默认（forward.c:427-436）：用 `master->last_server` **粘住**本组最近
//!     成功应答的那台，只在 `forwardcount > FORWARD_TEST(50)` 或距上次全发
//!     超过 `FORWARD_TIME(20s)` 时才「全发」一轮做健康复检。
//!     → 所有流量压在一台上，其余上游长期闲置。
//!   * `--all-servers`：每次查询都并发发给组内**所有**上游，取最先返回的。
//!     → 延迟最低，但上游开销随服务器数线性放大（N 台上游 = N 倍查询量）。
//!
//! 本模块提供按上游**实时表现**分配流量的策略（`--balance=<mode>`），
//! 默认仍是 `sticky`（完全兼容 dnsmasq 行为）。
//!
//! ## dynamic 策略
//!
//! 以「预期完成时间」为排序依据，取最小者：
//!
//!     score = (in_flight + 1) × EWMA(RTT)
//!
//! 这同时表达了两件事：
//!   * `in_flight` —— 已经在排队/在途的查询越多，再塞给它就越慢（排队论里的
//!     「最少未完成工作量」优先，即 Least Outstanding Requests）；
//!   * `EWMA(RTT)` —— 网络层面本来就慢的上游，单位工作耗时长，应少分。
//!
//! `+1` 是为了让空闲且 RTT 极小的上游不会把 score 压到 0（否则所有空闲上游
//! 并列，排序退化为原序）。
//!
//! 从未采样过的上游（`rtt_samples == 0`）score 记 0，即**优先被探测**用一次；
//! 一旦有了样本就回到正常竞争。这样新加入的上游不必等周期性「全发」也能融入。
//!
//! ## 熔断
//!
//! 上游连续失败 `SERVER_FAIL_THRESHOLD` 次后进入冷却，冷却时长按失败次数
//! 指数退避（上限 `SERVER_COOLDOWN_MAX_MS`）。冷却中的上游被排到候选**末尾**
//! 而不是直接丢弃 —— 否则当所有上游都在冷却时会无服务器可用，宁可降级也不要
//! 直接 SERVFAIL。任意一次成功应答立即清除熔断状态。

const std = @import("std");
const protocol = @import("protocol.zig");
const util = @import("util.zig");
const log = @import("log.zig");

const addr = @import("addr.zig");
const daemon_mod = @import("daemon.zig");
const Daemon = daemon_mod.Daemon;
const Server = daemon_mod.Server;
const BalanceMode = daemon_mod.BalanceMode;

const Atomic = std.atomic.Value;

// ---------------------------------------------------------------------------
// 生命周期钩子：由 forward.zig 在查询的不同阶段调用
// ---------------------------------------------------------------------------

/// 查询将要发给该上游（发出前调用，立刻计入在途）
pub fn beginQuery(s: *Server) void {
    _ = s.in_flight.fetchAdd(1, .monotonic);

    // 记录「这台最近一次被真正用上」的查询序号 —— dynamic 的探索预算靠它算差值。
    //
    // 之所以放在这里而不是 onSuccess：探测位要是超时/失败了，也该算「已经看过
    // 它了」。否则同一台会连续霸占探测位，把探索预算全吃掉，其它被冷落的
    // 上游一台都轮不到。
    if (daemon_mod.instance) |d| {
        s.probe_seq.store(d.query_seq.load(.monotonic), .monotonic);
    }
}

/// 查询结束（无论成功、超时还是发送失败都要调用，与 beginQuery 配对）
pub fn endQuery(s: *Server) void {
    // 用 CAS 而不是 fetchSub：即使出现意外的多余调用也不会把计数绕回 2^32
    var cur = s.in_flight.load(.monotonic);
    while (cur > 0) {
        if (s.in_flight.cmpxchgWeak(cur, cur - 1, .monotonic, .monotonic)) |actual| {
            cur = actual;
        } else return;
    }
}

/// 收到有效应答：更新 EWMA、记录采样时刻、清零连续失败与熔断
pub fn onSuccess(s: *Server, rtt_us: u64, now_ms: i64) void {
    updateEwma(s, rtt_us, now_ms);
    s.consecutive_failures.store(0, .monotonic);
    s.cooldown_until_ms.store(0, .monotonic);
    // 必须记录采样时刻：dynamic 策略靠它判断样本是否过期（过期就优先重采样）。
    // 早先这里把 now_ms 丢掉了，于是 last_reply 恒为 0，重采样规则从未生效。
    s.last_reply.store(now_ms, .monotonic);
}

/// 一次失败（超时 / 发送失败 / 应答不可用）
pub fn onFailure(s: *Server, base_cooldown_ms: i64, now_ms: i64) void {
    const fails = s.consecutive_failures.fetchAdd(1, .monotonic) + 1;
    if (fails < protocol.SERVER_FAIL_THRESHOLD) return;

    // 指数退避：每多失败一次冷却翻倍，上限 SERVER_COOLDOWN_BACKOFF_MAX 与
    // SERVER_COOLDOWN_MAX_MS 双重封顶。
    // 压测教训：退避指数一度是 5（64 倍），一台短暂抖动的上游会被冷却近一分钟，
    // 期间它被 usable() 完全排除、恢复后也迟迟回流不了。退避应当是「温和升级」
    // 而不是「惩罚放大器」。
    const over: u6 = @intCast(@min(fails - protocol.SERVER_FAIL_THRESHOLD, protocol.SERVER_COOLDOWN_BACKOFF_MAX));
    const base = @max(base_cooldown_ms, 1);
    // 总封顶随基准值放宽：--server-cooldown 显式配了大于基准的值时，
    // 不能让默认封顶把它压回默认量级。
    const hard_max = @max(base << protocol.SERVER_COOLDOWN_BACKOFF_MAX, protocol.SERVER_COOLDOWN_MAX_MS);
    const cd = @min(base << over, hard_max);
    const was = s.cooldown_until_ms.swap(now_ms + cd, .monotonic);

    // 只在「从可用转为熔断」的那一次记一次 trip，避免重复日志
    if (was <= now_ms) {
        _ = s.circuit_trips.fetchAdd(1, .monotonic);
        // 关键：探测时间戳必须以「进入冷却的时刻」起算。
        // last_probe_ms 的初值是 0，若不加这一句，任何上游一进入冷却就立刻
        // 满足 now - 0 >= SERVER_PROBE_INTERVAL_MS，探测位会当即将它放行，
        // 冷却等于形同虚设。
        s.last_probe_ms.store(now_ms, .monotonic);
        log.notice("上游连续失败 {d} 次，熔断 {d}ms", .{ fails, cd });
    }
}

/// 冷却中的上游是否到了该放行「半开探测」的时刻。
///
/// 熔断器不靠时钟被动恢复：冷却期内每隔 SERVER_PROBE_INTERVAL_MS 放行一次
/// 探测，既能在上游恢复后迅速回流（不必等完整个冷却期），又因为探测频率
/// 远低于正常流量而不会把请求堆到仍不可用的上游上。
pub fn isProbeDue(s: *const Server, now_ms: i64) bool {
    if (!isCooling(s, now_ms)) return false;
    const last = s.last_probe_ms.load(.monotonic);
    return now_ms - last >= protocol.SERVER_PROBE_INTERVAL_MS;
}

/// 标记该上游刚被放行过一次探测（下一次探测要再等一个探测间隔）
fn stampProbe(s: *Server, now_ms: i64) void {
    s.last_probe_ms.store(now_ms, .monotonic);
}

/// 该上游是否处于熔断冷却期
pub fn isCooling(s: *const Server, now_ms: i64) bool {
    return s.cooldown_until_ms.load(.monotonic) > now_ms;
}

/// 平滑 RTT 采样（EWMA）。`alpha = 1/8`，与 TCP 的 SRTT 估计一致。
fn updateEwma(s: *Server, sample_us: u64, now_ms: i64) void {
    const prev_at = s.last_reply.load(.monotonic);

    var cur = s.ewma_us.load(.monotonic);
    while (true) {
        const next: u64 = if (cur == 0 or prev_at == 0)
            // 第一个样本：直接采用
            sample_us
        else if (now_ms - prev_at > @as(i64, @intCast(protocol.EWMA_TAU_MS * 5)))
            // 间隔超过 5*tau：旧估计已经彻底过时（上游大概长时间没被选中，
            // 或者整个服务空转了很久），直接丢弃、采用新样本。
            // 阈值与 tau 联动而不是写死一个常数，改动衰减节奏时不用同步改这里。
            sample_us
        else blk: {
            // 双机制权重：
            //   * 样本密集（dt 很小）时，权重退化为 1/2^SHIFT 的固定平滑，
            //     好处是能抑制抖动，反映的是「最近的稳定水平」。
            //   * 样本稀疏（dt 很大）时，改用时间衰减 alpha = dt/(dt+tau)，
            //     间隔越长越信任新样本 —— 否则一个陈旧的高延迟估计会把
            //     「上游已经变快」这件事拖上十几秒才反映出来。
            //
            // 实现上取 num = max(dt, tau/7)：
            //   dt = 0        -> num = tau/7 -> alpha = 1/8（等价固定平滑）
            //   dt = tau      -> num = tau   -> alpha = 1/2
            //   dt >= 4*tau   -> 截断       -> alpha = 4/5
            const tau: u64 = protocol.EWMA_TAU_MS;
            const dt: u64 = @intCast(@max(@as(i64, 0), now_ms - prev_at));
            const num: u64 = @min(@max(dt, tau / 7), tau * 4);
            const c = @as(u128, cur);
            const v = @as(u128, sample_us);
            const den = @as(u128, num) + @as(u128, tau);
            break :blk @intCast((c * @as(u128, tau) + v * @as(u128, num)) / den);
        };
        if (s.ewma_us.cmpxchgWeak(cur, next, .monotonic, .monotonic)) |actual| {
            cur = actual;
        } else break;
    }
    _ = s.rtt_samples.fetchAdd(1, .monotonic);
}

// ---------------------------------------------------------------------------
// 候选收集与排序
// ---------------------------------------------------------------------------

/// 收集结果。`out[0..n_ready]` 是未熔断的候选（已按策略排好序），
/// `out[n_ready..n]` 是熔断中的候选（排在末尾，仅在 n_ready == 0 时使用）。
pub const Picked = struct {
    /// 候选总数
    n: usize = 0,
    /// 其中可立即使用的数量 = n_probe + 未熔断的数量。
    /// 布局是 `[0..n_probe)` 探测位 + `[n_probe..n_ready)` 健康上游，
    /// 两者都会参与转发，因此 usable() 直接取 `[0..n_ready)`。
    n_ready: usize = 0,
    /// 前段中有多少是「半开探测位」（冷却中但到了探测时刻）
    n_probe: usize = 0,

    /// 实际可用的候选切片（n_ready > 0 时只用可立即使用的）
    pub fn usable(self: Picked, out: []*Server) []*Server {
        return out[0..(if (self.n_ready > 0) self.n_ready else self.n)];
    }
};

/// 从 serverarray 的 `[first, last)` 区间收集可转发上游，并按当前策略排序。
///
/// `out` 由调用者提供（至少要 MAX_FORWARD_CANDIDATES 容量），
/// 避免热路径上的堆分配。
pub fn collect(
    d: *Daemon,
    first: usize,
    last: usize,
    now_ms: i64,
    out: []*Server,
) Picked {
    var res = Picked{};
    const cap = @min(out.len, protocol.MAX_FORWARD_CANDIDATES);

    const arr = d.serverarray.items;
    const hi = @min(last, arr.len);

    // 按三类分别收集，最后再按 [探测位][健康][冷却中] 的顺序摊到 out 里。
    // 用固定大小的栈上缓冲，避免热路径堆分配。
    var probe_buf: [protocol.MAX_FORWARD_CANDIDATES]*Server = undefined;
    var ready_buf: [protocol.MAX_FORWARD_CANDIDATES]*Server = undefined;
    var cold_buf: [protocol.MAX_FORWARD_CANDIDATES]*Server = undefined;
    var n_probe: usize = 0;
    var n_ready: usize = 0;
    var n_cold: usize = 0;

    var i = first;
    while (i < hi) : (i += 1) {
        const srv = arr[i];
        if (!isForwardable(srv)) continue;

        if (!isCooling(srv, now_ms)) {
            if (n_ready < cap) {
                ready_buf[n_ready] = srv;
                n_ready += 1;
            }
        } else if (n_probe < cap and isProbeDue(srv, now_ms)) {
            // 半开探测：冷却中但到了探测时刻，放行一次并重新计时
            stampProbe(srv, now_ms);
            probe_buf[n_probe] = srv;
            n_probe += 1;
        } else if (n_cold < cap) {
            cold_buf[n_cold] = srv;
            n_cold += 1;
        }
    }

    // ---- 探测配额的分配（dynamic 专属）----
    //
    // 每 SERVER_PROBE_GAP 次选路**全局**只放行一台被冷落的上游去探测。
    //
    // 为什么必须是全局配额而不是「每台各自计数」：后者下探索开销是 N/GAP
    // （N = 被冷落的上游数），上游越多、尾延迟越差 —— 实测 3 台冷上游时
    // 有 7.5% 的查询被探测带走，P95 从 3ms 恶化到 60ms。改成全局配额后，
    // 无论集群多大，探测最多只吃掉 1/GAP 的流量。
    //
    // 代价是被冷落的上游要轮着来：N 台冷上游时每台约每 N*GAP 次选路才能
    // 重采样一次。这是刻意的取舍 —— 探测的收益是「可能发现更好的上游」，
    // 而它的成本（尾延迟）是每一笔查询都要付的。
    const query_seq = d.query_seq.fetchAdd(1, .monotonic);
    var probe_target: ?*Server = null;
    if (d.balance_mode == .dynamic and n_ready > 0) {
        if (query_seq % protocol.SERVER_PROBE_GAP == 0) {
            // 挑「被冷落最久」的那台（probe_seq 最小）
            var worst: ?*Server = null;
            var worst_seq: u64 = std.math.maxInt(u64);
            for (ready_buf[0..n_ready]) |sv| {
                const lag = query_seq -% sv.probe_seq.load(.monotonic);
                if (lag <= protocol.SERVER_PROBE_GAP) continue; // 预算还没到
                if (sv.rtt_samples.load(.monotonic) == 0) continue; // 没采过样的本来就排最前
                const ps = sv.probe_seq.load(.monotonic);
                if (ps < worst_seq) {
                    worst_seq = ps;
                    worst = sv;
                }
            }
            probe_target = worst;
        }
    }

    // 只在健康上游之间做策略排序。探测位必须保持在最前：若把它们一起排序，
    // 动态打分（依赖的还是熔断前的旧 EWMA）会把它们排到后面，探测就永远不会
    // 真正发生，「半开」就退化成「只看冷却时钟」。
    const ready = ready_buf[0..n_ready];
    switch (d.balance_mode) {
        // dnsmasq 原生：顺序由 forward.zig 的 last_server 决定，这里不动
        .sticky => {},
        .dynamic => sortDynamic(ready, probe_target),
        .swrr => sortSwrr(ready),
        .round_robin => rotate(ready, d.rr_cursor.fetchAdd(1, .monotonic)),
        .random => shuffle(ready),
    }

    var w: usize = 0;
    for (probe_buf[0..n_probe]) |srv| {
        out[w] = srv;
        w += 1;
    }
    for (ready_buf[0..n_ready]) |srv| {
        out[w] = srv;
        w += 1;
    }
    for (cold_buf[0..n_cold]) |srv| {
        out[w] = srv;
        w += 1;
    }

    res.n = w;
    res.n_probe = n_probe;
    res.n_ready = n_probe + n_ready;
    return res;
}

/// 该上游是否可用于转发（与 C 版 forward_query 的跳过条件一致）
fn isForwardable(s: *const Server) bool {
    if (s.isLocal()) return false;
    if ((s.flags & (protocol.SERV_LOOP | protocol.SERV_GOT_TCP)) != 0) return false;
    return true;
}

/// dynamic 的排序键：预期完成时间（越小越优先）。
///
/// 打分 = (在途 + 1) × EWMA，这就是 Little 定律给出的「预期完成时间」：
/// 排在一台空闲且快（EWMA 小）的上游前面，永远比排在忙或慢的上游前面划算。
///
/// 另外叠加一条「探索」规则：被冷落的上游会拿到 0 分（最优），从而被重新采样。
/// 没有这条规则会有一个致命盲区 —— 一旦某台因延迟最低而长期独占流量，
/// 其余上游的 EWMA 就再也不更新，哪怕它们已经变快也永远发现不了。
///
/// 探测目标由 `collect()` 统一分配（全局配额，见那里的注释），本函数只负责
/// 给被选中的那台打 0 分。
pub fn scoreDynamic(s: *const Server, probe_target: ?*const Server) u64 {
    // 从未采样过：返回 0 让它在排序中排最前（冷启动探测）。
    if (s.rtt_samples.load(.monotonic) == 0) return 0;
    // 本轮拿到探测配额的那台：同样给 0 分（见 collect() 里的全局配额分配）
    if (probe_target != null and probe_target.? == s) return 0;

    const e = s.ewma_us.load(.monotonic);
    const inflight: u64 = s.in_flight.load(.monotonic);
    return (inflight + 1) *% e;
}

/// dynamic 策略的排序：按打分升序。需要知道本轮谁拿到了探测配额，
/// 因此不用通用的 insertionSort（那个只接受无上下文的比较函数）。
fn sortDynamic(items: []*Server, probe_target: ?*const Server) void {
    var i: usize = 1;
    while (i < items.len) : (i += 1) {
        const key = items[i];
        const kscore = scoreDynamic(key, probe_target);
        var j = i;
        while (j > 0 and scoreDynamic(items[j - 1], probe_target) > kscore) : (j -= 1) {
            items[j] = items[j - 1];
        }
        items[j] = key;
    }
}

/// swrr 的静态权重：延迟越低权重越高。未采样过给中等权重，
/// 以便它在平滑轮询里也能拿到一部分流量（而不是被饿死）。
pub fn swrrWeight(s: *const Server) i64 {
    if (s.rtt_samples.load(.monotonic) == 0) return 100;
    const e = s.ewma_us.load(.monotonic);
    // 1e6 / (ewma+1)，单位微秒；1ms -> 1000，1s -> 1
    const w = 1_000_000 / (e + 1);
    return @intCast(@max(@as(u64, 1), w));
}

/// 平滑加权轮询的排序：反复选出「当前权重最大」的候选。
/// `swrr_current` 是跨查询的持久状态，因此这里每次调用都会推进它。
fn insertionSort(
    items: []*Server,
    comptime less: fn (void, *Server, *Server) bool,
) void {
    var i: usize = 1;
    while (i < items.len) : (i += 1) {
        const key = items[i];
        var j = i;
        while (j > 0 and less({}, key, items[j - 1])) : (j -= 1) {
            items[j] = items[j - 1];
        }
        items[j] = key;
    }
}

/// 按 SWRR 规则给出候选顺序（会推进每台的 swrr_current）
fn sortSwrr(items: []*Server) void {
    const n = items.len;
    if (n <= 1) return;

    var total: i64 = 0;
    for (items) |s| total += swrrWeight(s);
    if (total <= 0) return;

    // 一次调用只推进**一轮** SWRR 选择。
    //
    // 这一点很关键：调用方在一次查询里只会用上候选列表的头部（串行模式只用
    // 第一个元素，并发模式把其余当作失败兜底）。若像早先那样在这里把 n 个
    // 候选全部排完，每查询就会推进 n 次 SWRR 状态 —— 实际观察到的分布会
    // 严重偏离权重（实测最快的那台拿到 100%，而按 1/EWMA 它只该拿约 85%）。
    //
    // 标准 SWRR：所有候选的当前权重都 += 自身权重，选出最大者，再让胜者
    // 扣掉总权重。长期下来每台被选中的比例收敛到 w_i / Σw。
    var best: usize = 0;
    var best_cur: i64 = std.math.minInt(i64);
    for (items, 0..) |s, k| {
        const w = swrrWeight(s);
        const cur = s.swrr_current.fetchAdd(w, .monotonic) + w;
        if (cur > best_cur) {
            best_cur = cur;
            best = k;
        }
    }
    _ = items[best].swrr_current.fetchSub(total, .monotonic);

    // 胜者换到头部；其余候选保持原有相对顺序，作为失败后的兜底路径。
    if (best != 0) std.mem.swap(*Server, &items[0], &items[best]);
}

/// 以 `cursor` 为起点把候选集合循环左移
fn rotate(items: []*Server, cursor: u32) void {
    if (items.len <= 1) return;
    const off = cursor % items.len;
    if (off == 0) return;
    std.mem.rotate(*Server, items, off);
}

/// Fisher-Yates 洗牌
fn shuffle(items: []*Server) void {
    if (items.len <= 1) return;
    var i: usize = items.len - 1;
    while (i > 0) : (i -= 1) {
        const j = util.randBelow(@intCast(i + 1));
        std.mem.swap(*Server, &items[i], &items[j]);
    }
}

// ---------------------------------------------------------------------------
// 观测：把每台上游的实时状态输出成一行（SIGUSR1 / 退出时用）
// ---------------------------------------------------------------------------

/// 把一台上游的统计格式化进 `buf`，返回切片
pub fn formatServerStat(s: *const Server, buf: []u8) []const u8 {
    var abuf: [128]u8 = undefined;
    const addr_text = s.addrText(&abuf);
    const ewma = s.ewma_us.load(.monotonic);
    return std.fmt.bufPrint(buf, "server {s}: queries={d} wins={d} fail={d} inflight={d} rtt_ewma={d}.{d:0>3}ms trips={d}", .{
        addr_text,
        s.queries.load(.monotonic),
        s.concurrent_wins.load(.monotonic),
        s.failed_queries.load(.monotonic),
        s.in_flight.load(.monotonic),
        ewma / 1000,
        ewma % 1000,
        s.circuit_trips.load(.monotonic),
    }) catch "server ?";
}

/// 打印所有上游的统计（对应 dnsmasq 的 SIGUSR1 / dump 行为）
const testing = std.testing;

test "EWMA 收敛到稳定延迟" {
    // 注意：allocator.create 不套用结构体默认值，这里必须用栈上 .{} 初始化，
    // 否则原子字段里是未初始化内存（实测会是 0xAAAAAAAA 之类的垃圾值）。
    var s: Server = .{};
    const p = &s;

    // 连续 20 个 10ms 样本后，EWMA 应该接近 10ms
    for (0..20) |_| onSuccess(p, 10_000, 0);
    const e = p.ewma_us.load(.monotonic);
    try testing.expect(e > 9_500 and e < 10_500);

    // 之后持续 20ms，EWMA 会向 20ms 靠拢但不会瞬间跳到 20ms
    for (0..40) |_| onSuccess(p, 20_000, 0);
    const e2 = p.ewma_us.load(.monotonic);
    try testing.expect(e2 > 17_000 and e2 < 20_500);
}

test "连续失败触发熔断并按次数温和退避" {
    var sv: Server = .{};
    const s = &sv;
    const base: i64 = protocol.SERVER_COOLDOWN_DEFAULT_MS; // 1000

    try testing.expect(!isCooling(s, 1000));

    // 未达阈值不熔断
    onFailure(s, base, 1000);
    onFailure(s, base, 1000);
    try testing.expect(!isCooling(s, 1000));

    // 第 3 次达到阈值 -> 冷却 1 倍基准 = 1000ms
    onFailure(s, base, 1000);
    try testing.expect(isCooling(s, 1500));
    try testing.expect(isCooling(s, 1999));
    try testing.expect(!isCooling(s, 2001));
    try testing.expectEqual(@as(u64, 1), s.circuit_trips.load(.monotonic));

    // 第 4 次 -> 2 倍 = 2000ms
    onFailure(s, base, 10_000);
    try testing.expect(isCooling(s, 11_999));
    try testing.expect(!isCooling(s, 12_001));

    // 第 5 次起 -> 撞上 SERVER_COOLDOWN_BACKOFF_MAX（2）与
    // SERVER_COOLDOWN_MAX_MS（4000）双重封顶，不会无限翻倍。
    // 压测教训：曾经退避到 64 倍（近一分钟），上游恢复后长时间收不到流量。
    onFailure(s, base, 20_000);
    const cd = s.cooldown_until_ms.load(.monotonic) - 20_000;
    try testing.expectEqual(protocol.SERVER_COOLDOWN_MAX_MS, cd);

    // 一次成功立即清除冷却与失败计数
    onSuccess(s, 5000, 30_000);
    try testing.expect(!isCooling(s, 30_000));
    try testing.expectEqual(@as(u32, 0), s.consecutive_failures.load(.monotonic));
}

test "EWMA 时间衰减：样本越稀疏，对「上游变快」的收敛越快" {
    // 同一个变化：150ms -> 1ms。区别只在采样密度。
    var sparse: Server = .{};
    sparse.ewma_us.store(150_000, .monotonic);
    sparse.rtt_samples.store(1, .monotonic);
    sparse.last_reply.store(1_000, .monotonic);

    var dense: Server = .{};
    dense.ewma_us.store(150_000, .monotonic);
    dense.rtt_samples.store(1, .monotonic);
    dense.last_reply.store(1_000, .monotonic);

    // 稀疏：每 1.2s 一个样本（被冷落的上游正是这种处境）
    var t: i64 = 2_200;
    for (0..5) |_| {
        onSuccess(&sparse, 1_000, t);
        t += 1_200;
    }
    // 密集：每 15ms 一个样本（持续有流量的上游）
    var td: i64 = 1_015;
    for (0..5) |_| {
        onSuccess(&dense, 1_000, td);
        td += 15;
    }

    const es = sparse.ewma_us.load(.monotonic);
    const ed = dense.ewma_us.load(.monotonic);

    // 稀疏采样必须已经基本收敛到新值。若只有固定平滑系数，
    // 5 个样本只能把 150ms 拉到约 100ms，重适应会被拖到几十秒之后。
    try testing.expect(es < 5_000);
    // 密集采样仍保持原有平滑特性（抑制抖动优先），因此还是个大数
    try testing.expect(ed > 50_000);
}

test "陈旧样本直接采用：上游变快后一次探测就能反映出来" {
    var sv: Server = .{};
    const s = &sv;

    // 旧估计 150ms，且采样时刻已经很旧
    s.ewma_us.store(150_000, .monotonic);
    s.rtt_samples.store(10, .monotonic);
    s.last_reply.store(1_000, .monotonic);

    const now: i64 = 1_000 + @as(i64, @intCast(protocol.EWMA_TAU_MS * 5)) + 1;
    onSuccess(s, 1_000, now); // 现在只花 1ms

    // 关键：必须**直接采用**新样本。若按 1/2^SHIFT 平滑，结果会是 ~131ms，
    // 而被冷落的上游本来就没几次采样机会，照这个速度要很久才能收敛，
    // 「重适应」就只是一句口号。
    try testing.expectEqual(@as(u64, 1_000), s.ewma_us.load(.monotonic));

    // 连续采样（样本新鲜）仍然走平滑：从 1ms 跳到 100ms 不会一步到位
    onSuccess(s, 100_000, now + 10);
    const e = s.ewma_us.load(.monotonic);
    try testing.expect(e > 1_000 and e < 100_000);
}

test "SWRR 长期分布收敛到 w_i/Σw（回归：曾把整轮排完导致 100% 集中）" {
    var a: Server = .{}; // 2ms，权重 500
    var b: Server = .{}; // 15ms，权重 66
    var c: Server = .{}; // 60ms，权重 16
    var d: Server = .{}; // 150ms，权重 6
    const pairs = [_]struct { s: *Server, us: u64 }{
        .{ .s = &a, .us = 2_000 },
        .{ .s = &b, .us = 15_000 },
        .{ .s = &c, .us = 60_000 },
        .{ .s = &d, .us = 150_000 },
    };
    for (pairs) |it| {
        it.s.ewma_us.store(it.us, .monotonic);
        it.s.rtt_samples.store(10, .monotonic);
    }

    var list = [_]*Server{ &a, &b, &c, &d };
    var wins = [_]usize{0} ** 4;
    const rounds: usize = 1200;
    for (0..rounds) |_| {
        sortSwrr(&list);
        // 只有 list[0] 会被真正使用（调用方一次查询只取头部），
        // 因此「胜出」只能按头部计。早先误把整个列表都计一遍，
        // 结果是四台都是 1200/1200，看起来像 100% 均分。
        const top = list[0];
        if (top == &a) wins[0] += 1;
        if (top == &b) wins[1] += 1;
        if (top == &c) wins[2] += 1;
        if (top == &d) wins[3] += 1;
    }

    // 权重比例 500 : 66 : 16 : 6，总量 588
    const total_weight: f64 = 588;
    const expect = [_]f64{
        @as(f64, 500) / total_weight,
        @as(f64, 66) / total_weight,
        @as(f64, 16) / total_weight,
        @as(f64, 6) / total_weight,
    };
    for (wins, 0..) |n, i| {
        const got = @as(f64, @floatFromInt(n)) / @as(f64, @floatFromInt(rounds));
        // 允许 ±5 个百分点，足够宽松，但「100% 集中在一台」这类错误必然被抓到
        try testing.expect(@abs(got - expect[i]) < 0.05);
    }
    // 慢上游必须真的拿到过流量，而不是被彻底饿死
    try testing.expect(wins[3] > 0);
}

test "探索：拿到探测配额的上游被打 0 分" {
    var hot: Server = .{}; // 很快，一直在被用
    var cold: Server = .{}; // 很慢，很久没被选中
    hot.ewma_us.store(1_000, .monotonic);
    hot.rtt_samples.store(100, .monotonic);
    cold.ewma_us.store(150_000, .monotonic);
    cold.rtt_samples.store(100, .monotonic);

    // 没有配额时：纯按 (在途+1)×EWMA 打分，hot 明显更优（不被探测打扰）
    try testing.expect(scoreDynamic(&hot, null) < scoreDynamic(&cold, null));
    try testing.expect(scoreDynamic(&cold, null) > 0);

    // 拿到配额的那台被打 0 分 -> 排到最前，从而被重新采样。
    // 这正是「某台变快了但一直没被选中 -> 永远发现不了」这个盲区的解药。
    try testing.expectEqual(@as(u64, 0), scoreDynamic(&cold, &cold));
    // 配额只影响那一台，其余照常打分
    try testing.expect(scoreDynamic(&hot, &cold) > 0);

    // 从未采样过的上游永远返回 0（冷启动探测），与配额无关
    var fresh: Server = .{};
    try testing.expectEqual(@as(u64, 0), scoreDynamic(&fresh, null));
}

test "探测配额是全局的：N 台冷上游也只有 1/GAP 的流量被探测带走" {
    const a = testing.allocator;
    var d = Daemon{ .allocator = a };
    defer d.deinit();
    d.balance_mode = .dynamic;

    // 1 台快的 + 3 台慢的（慢的会被冷落，全都「欠采样」）
    const speed = [_]u64{ 2_000, 150_000, 150_000, 150_000 };
    var fast: *Server = undefined;
    for (speed, 0..) |us, k| {
        const sv = try d.newServer();
        sv.addr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 10, 0, 0, @intCast(k + 1) }), 53);
        onSuccess(sv, us, 0);
        try d.addServer(sv);
        if (k == 0) fast = sv;
    }
    try @import("domain.zig").buildServerArray(&d);

    var out: [8]*Server = undefined;
    var probed_to_cold: usize = 0;
    const rounds: usize = 800;

    // 模拟 rounds 次选路：每轮只把头部（真正会被用的那台）当作「已使用」，
    // 这正是串行转发的实际行为。
    for (0..rounds) |_| {
        const picked = collect(&d, 0, d.serverarray.items.len, 1000, &out);
        const winner = picked.usable(&out)[0];
        if (winner != fast) probed_to_cold += 1;
        // 模拟 beginQuery 里对 probe_seq 的刷新
        winner.probe_seq.store(d.query_seq.load(.monotonic), .monotonic);
    }

    const ratio = @as(f64, @floatFromInt(probed_to_cold)) / @as(f64, @floatFromInt(rounds));
    // 期望约 1/GAP = 2.5%。允许上浮（第一轮冷启动时未采样的上游本来就会排最前，
    // 这里 3 台慢上游已采样所以不触发），但必须显著低于「每台各算各的」时的
    // N/GAP = 7.5%，否则说明全局配额没生效。
    try testing.expect(ratio < 0.05);
    try testing.expect(ratio > 0.005); // 也不能完全不探测，否则会失去重适应能力
}

test "sortDynamic：配额命中的上游排到最前" {
    var a: Server = .{}; // 很快
    var b: Server = .{}; // 很慢
    a.ewma_us.store(2_000, .monotonic);
    a.rtt_samples.store(5, .monotonic);
    b.ewma_us.store(50_000, .monotonic);
    b.rtt_samples.store(5, .monotonic);

    // 没有配额：a 在前
    var list = [_]*Server{ &a, &b };
    sortDynamic(&list, null);
    try testing.expectEqual(&a, list[0]);
    try testing.expectEqual(&b, list[1]);

    // 配额给 b：b 被提到最前
    var list2 = [_]*Server{ &a, &b };
    sortDynamic(&list2, &b);
    try testing.expectEqual(&b, list2[0]);
    try testing.expectEqual(&a, list2[1]);
}

test "半开探测：冷却中的上游按间隔放行一次" {
    var sv: Server = .{};
    const s = &sv;
    const base: i64 = protocol.SERVER_COOLDOWN_DEFAULT_MS;

    // 触发熔断
    onFailure(s, base, 0);
    onFailure(s, base, 0);
    onFailure(s, base, 1000);

    // 刚进入冷却时不该立刻探测：探测时钟以「进入冷却的时刻」起算。
    // （若 last_probe_ms 保持初值 0，这里会立刻返回 true，冷却形同虚设。）
    try testing.expect(!isProbeDue(s, 1001));

    // 经过一个探测间隔后放行一次
    try testing.expect(isProbeDue(s, 1000 + protocol.SERVER_PROBE_INTERVAL_MS));

    // 从 collect() 的角度验证：探测位被放进 usable 段，且不会重复占用
    var d = Daemon{ .allocator = testing.allocator };
    defer d.deinit();
    d.balance_mode = .dynamic;

    const up = try d.newServer();
    up.flags = 0;
    up.addr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 8, 8, 8, 8 }), 53);
    try d.servers.append(d.allocator, up);
    try d.serverarray.append(d.allocator, up);

    // 让 up 进入冷却
    up.consecutive_failures.store(protocol.SERVER_FAIL_THRESHOLD, .monotonic);
    up.cooldown_until_ms.store(10_000, .monotonic);
    up.last_probe_ms.store(0, .monotonic);

    var buf: [protocol.MAX_FORWARD_CANDIDATES]*Server = undefined;

    // 距上次探测不足一个间隔 -> 只能进「冷却中」段，usable 为空时兜底返回它
    const p1 = collect(&d, 0, 1, 100, &buf);
    try testing.expectEqual(@as(usize, 0), p1.n_ready);
    try testing.expectEqual(@as(usize, 1), p1.n);

    // 间隔已过 -> 拿到一个探测位
    const p2 = collect(&d, 0, 1, protocol.SERVER_PROBE_INTERVAL_MS + 1, &buf);
    try testing.expectEqual(@as(usize, 1), p2.n_ready);
    try testing.expectEqual(@as(usize, 1), p2.n_probe);

    // 同一次探测窗口内不重复放行（时间戳已更新）
    const p3 = collect(&d, 0, 1, protocol.SERVER_PROBE_INTERVAL_MS + 2, &buf);
    try testing.expectEqual(@as(usize, 0), p3.n_ready);
}


test "在途计数配对且不会下溢" {
    var sv: Server = .{};
    const s = &sv;

    beginQuery(s);
    beginQuery(s);
    try testing.expectEqual(@as(u32, 2), s.in_flight.load(.monotonic));
    endQuery(s);
    try testing.expectEqual(@as(u32, 1), s.in_flight.load(.monotonic));
    endQuery(s);
    try testing.expectEqual(@as(u32, 0), s.in_flight.load(.monotonic));
    // 多余的 endQuery 不应把计数绕到 2^32-1
    endQuery(s);
    try testing.expectEqual(@as(u32, 0), s.in_flight.load(.monotonic));
}

test "dynamic 排序：在途少、延迟低的优先" {
    const a = testing.allocator;
    var d = Daemon{ .allocator = a };
    defer d.deinit();
    d.balance_mode = .dynamic;

    // A：10ms，空闲；B：10ms，但有 4 个在途；C：50ms，空闲；D：未采样
    const sa = try d.newServer();
    sa.addr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 1, 1, 1, 1 }), 53);
    onSuccess(sa, 10_000, 0);

    const sb = try d.newServer();
    sb.addr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 2, 2, 2, 2 }), 53);
    onSuccess(sb, 10_000, 0);
    sb.in_flight.store(4, .monotonic);

    const sc = try d.newServer();
    sc.addr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 3, 3, 3, 3 }), 53);
    onSuccess(sc, 50_000, 0);

    const sd = try d.newServer();
    sd.addr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 4, 4, 4, 4 }), 53);
    // 故意不采样

    try d.addServer(sa);
    try d.addServer(sb);
    try d.addServer(sc);
    try d.addServer(sd);
    try @import("domain.zig").buildServerArray(&d);

    var out: [8]*Server = undefined;
    const picked = collect(&d, 0, d.serverarray.items.len, 1000, &out);
    try testing.expectEqual(@as(usize, 4), picked.n_ready);

    // 第 1 台必须是未采样的 D（优先探测）
    try testing.expectEqual(sd, out[0]);
    // 然后是空闲且快的 A（score = 1×10000）
    try testing.expectEqual(sa, out[1]);
    // B 与 C 打分相同（都是 50000）：B 慢在「在途 4 个」，C 慢在「RTT 50ms」。
    // 插入排序是稳定的，因此二者保持 serverarray 原序（B 在前）。
    try testing.expectEqual(sb, out[2]);
    try testing.expectEqual(sc, out[3]);

    // 定量核对打分
    try testing.expectEqual(@as(u64, 0), scoreDynamic(sd, null));
    try testing.expectEqual(@as(u64, 10_000), scoreDynamic(sa, null));
    try testing.expectEqual(@as(u64, 50_000), scoreDynamic(sc, null));
    try testing.expectEqual(@as(u64, 50_000), scoreDynamic(sb, null)); // (4+1)×10000
}

test "熔断中的上游排到末尾，但不会被丢弃" {
    const a = testing.allocator;
    var d = Daemon{ .allocator = a };
    defer d.deinit();
    d.balance_mode = .dynamic;

    const s1 = try d.newServer();
    s1.addr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 1, 1, 1, 1 }), 53);
    onSuccess(s1, 10_000, 0);

    const s2 = try d.newServer();
    s2.addr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 2, 2, 2, 2 }), 53);
    onSuccess(s2, 10_000, 0);
    // 让 s2 熔断
    onFailure(s2, 2000, 1000);
    onFailure(s2, 2000, 1000);
    onFailure(s2, 2000, 1000);

    try d.addServer(s1);
    try d.addServer(s2);
    try @import("domain.zig").buildServerArray(&d);

    var out: [8]*Server = undefined;
    const picked = collect(&d, 0, d.serverarray.items.len, 1000, &out);
    try testing.expectEqual(@as(usize, 2), picked.n);
    try testing.expectEqual(@as(usize, 1), picked.n_ready);
    try testing.expectEqual(s1, out[0]);
    try testing.expectEqual(s2, out[1]); // 熔断的仍在候选里，只是排后面
    try testing.expectEqual(@as(usize, 1), picked.usable(&out).len);

    // 全部熔断时，usable() 会退化为「全部候选」，避免无服务器可用
    const cooling = Picked{ .n = 2, .n_ready = 0 };
    try testing.expectEqual(@as(usize, 2), cooling.usable(&out).len);
}

test "round_robin 轮转与 random 覆盖全部候选" {
    const a = testing.allocator;
    var d = Daemon{ .allocator = a };
    defer d.deinit();
    d.balance_mode = .round_robin;

    var srvs: [3]*Server = undefined;
    for (&srvs, 0..) |*slot, i| {
        const s = try d.newServer();
        s.addr = addr.SockAddr.fromIp4(@bitCast([4]u8{ 10, 0, 0, @as(u8, @intCast(i + 1)) }), 53);
        slot.* = s;
        try d.addServer(s);
    }
    try @import("domain.zig").buildServerArray(&d);

    var out: [8]*Server = undefined;
    var firsts: [3]*Server = undefined;
    for (&firsts, 0..) |*f, i| {
        const picked = collect(&d, 0, d.serverarray.items.len, 1000, &out);
        try testing.expectEqual(@as(usize, 3), picked.n_ready);
        f.* = out[0];
        _ = i;
    }
    // 三次连续调用应该给出三个不同的起点（轮询）
    try testing.expect(firsts[0] != firsts[1]);
    try testing.expect(firsts[1] != firsts[2]);
    try testing.expect(firsts[0] != firsts[2]);

    d.balance_mode = .random;
    var seen = [_]bool{false} ** 3;
    for (0..60) |_| {
        const picked = collect(&d, 0, d.serverarray.items.len, 1000, &out);
        _ = picked;
        for (srvs, 0..) |s, i| {
            if (out[0] == s) seen[i] = true;
        }
    }
    // 60 次随机里三台都该被选中过
    for (seen) |v| try testing.expect(v);
}
