// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! cache.zig — 对应 C 源码 src/cache.c（DNS 缓存：LRU 链表 + 哈希桶 + 正/负缓存 + 反向查询）
//!
//! 移植要点：
//!   * 结构与 C 保持一致：crec 的 next/prev（LRU 链）、hash_next（桶内链）、
//!     addr/ttd/uid/flags/name 字段含义相同，F_* 标志位一一对应。
//!   * 多线程：整个缓存由一把互斥锁（`mutex`）保护。锁**不在本文件内部获取**，
//!     而是由调用方在「一段完整的缓存交互」外层持有 —— 因为很多操作是
//!     「查找 -> 读字段 -> 插入」的组合，逐函数加锁并不能保证这段组合的原子性。
//!     目前的持锁点是：
//!         rfc1035.answerRequest()   —— 本地应答整段（纯内存，无网络 IO）
//!         rfc1035.extractAddresses()—— 把上游应答写入缓存
//!         server.reload() / server 的定期 expire
//!     注意：绝不能把转发（网络等待）放在锁内，否则会把所有查询串行化。
//!   * 差异：C 版本用固定名字缓冲区池（store_name/free_names）存放长名字，
//!     这里改用分配器（仅长名字），并在淘汰时释放，语义不变。

const std = @import("std");
const protocol = @import("protocol.zig");
const addr = @import("addr.zig");
const name = @import("name.zig");
const util = @import("util.zig");

const Atomic = std.atomic.Value;

pub const UID_NONE: u32 = 0;

/// 缓存命中统计快照（findXxx 级的 hits/misses 与查询级的 query_*）
pub const Stats = struct {
    /// 查找级命中次数（一次查询会累加多次）
    hits: u64 = 0,
    /// 查找级未命中次数
    misses: u64 = 0,
    /// 查询级命中（本地缓存直接回答）
    query_hits: u64 = 0,
    /// 查询级未命中（需要转发上游）
    query_misses: u64 = 0,
    /// 查询级「配置类本地应答」（--address / local= / domain-needed）
    query_local_config: u64 = 0,
};
/// 名字长度不超过该值时内联保存在 CRec 里（对应 C 的 char name[SMALLDNAME]）
pub const SMALLDNAME: usize = 63;

pub const Io = std.Io;

/// 对应 struct crec
pub const CRec = struct {
    next: ?*CRec = null,
    prev: ?*CRec = null,
    hash_next: ?*CRec = null,
    addr: addr.AllAddr = .{ .none = {} },
    ttd: i64 = 0,
    uid: u32 = UID_NONE,
    flags: u32 = 0,
    sname: [SMALLDNAME + 1]u8 = [_]u8{0} ** (SMALLDNAME + 1),
    /// 名字过长时单独保存（对应 C 的 F_BIGNAME + name.bname）
    bname: ?[]u8 = null,
    /// 指向别的缓存记录的名字（对应 C 的 F_NAMEP + name.namep）
    namep: ?*CRec = null,
};

pub const CacheError = error{OutOfMemory};

/// 名字里是否有大写字母（用于快路径判断：绝大多数缓存名已是小写）
fn hasUpper(nm: []const u8) bool {
    for (nm) |c| {
        if (c >= 'A' and c <= 'Z') return true;
    }
    return false;
}

/// 大小写不敏感的名字哈希（Wyhash + 进程级 seed）。
///
/// Wyhash 本身不折叠大小写，而缓存要求 "Foo.com" 与 "foo.com" 落同一桶，
/// 所以这里补一层折子：先扫一遍找大写字母——
///   * 没有大写（绝大多数情况，缓存里的名字本就已小写）→ 直接哈希原切片，零拷贝；
///   * 有大写 → 用 64 字节栈缓冲分块折叠后流式喂给 Wyhash（不额外分配、不加大栈帧）。
fn wyhashName(seed: u64, nm: []const u8) u64 {
    if (!hasUpper(nm)) return std.hash.Wyhash.hash(seed, nm);

    var wh = std.hash.Wyhash.init(seed);
    var buf: [64]u8 = undefined;
    var i: usize = 0;
    while (i < nm.len) {
        const n = @min(buf.len, nm.len - i);
        for (nm[i .. i + n], 0..) |c, j| {
            buf[j] = if (c >= 'A' and c <= 'Z') c + ('a' - 'A') else c;
        }
        wh.update(buf[0..n]);
        i += n;
    }
    return wh.final();
}

pub const Cache = struct {
    allocator: std.mem.Allocator,
    mutex: Io.Mutex = .init,

    /// 对应 daemon->cache_head / cache_tail：所有记录的 LRU 链
    cache_head: ?*CRec = null,
    cache_tail: ?*CRec = null,
    /// 空闲记录链（C 中通过 flags == 0 判断，这里显式维护）
    free_head: ?*CRec = null,

    /// 哈希表
    hash_table: []?*CRec = &.{},
    hash_size: usize = 0,
    /// 名字哈希的 seed（std.hash.Wyhash）。
    ///
    /// C 版的 cache_hash 混入 `mix_tab`（= typestr[] 数组字节，含指针 → 依赖
    /// 进程内存布局/ASLR），因此桶分布每次运行都不同；本移植原先简化为纯
    /// rotate-7，丢掉了这点熵。改用 Wyhash + 进程级随机 seed 既更快，
    /// 又把「每次运行分布不同」这个性质以可移植的方式补回来（抗哈希洪泛）。
    /// 进程内固定（首次 setSize 时播种），保证同一 Cache 的所有操作落在同一桶。
    hash_seed: u64 = 0,

    /// 记录总数
    cachesize: usize = 0,
    /// 已用记录数
    count: usize = 0,

    /// --use-stale-cache：过期后该秒数内仍可服务。0 = 禁用。
    /// 由 daemon 在 init/setSize 时同步过来。
    stale_ttl: u32 = 0,

    /// **单次查找**级别的命中/未命中。用原子量：查询线程更新，
    /// SIGUSR1 的统计线程读取。
    ///
    /// 注意这不是「缓存命中率」：一次查询会做多次查找（CNAME 链最多 8 次、
    /// 地址、负缓存、非终结点……），用它算命中率会把分母放大 6 倍以上
    /// （压测里 500 个冷域名得到 3209 次 miss，命中率被算成 13.5%）。
    /// 真正的命中率请用下面的 query_hits / query_misses。
    hits: Atomic(u64) = Atomic(u64).init(0),
    misses: Atomic(u64) = Atomic(u64).init(0),

    /// **单次查询**级别的命中/未命中（由 answerRequest 在返回时记账）。
    /// 口径与用户直觉一致：一次查询要么命中缓存、要么需要转发。
    query_hits: Atomic(u64) = Atomic(u64).init(0),
    query_misses: Atomic(u64) = Atomic(u64).init(0),
    /// 本地应答但既非缓存命中、也非转发（--address / local= / domain-needed 等配置类应答）
    query_local_config: Atomic(u64) = Atomic(u64).init(0),

    /// 记录数组（用于释放）
    records: ?[]CRec = null,

    pub fn init(allocator: std.mem.Allocator, cachesize: usize) CacheError!Cache {
        var c = Cache{ .allocator = allocator };
        try c.setSize(cachesize);
        return c;
    }

    /// 对应 cache_init()：分配记录并按 LRU 链串起来
    pub fn setSize(self: *Cache, cachesize: usize) CacheError!void {
        // 首次建表时播种（进程内只播一次；setSize 重入不重播，避免无谓重排）
        if (self.hash_seed == 0) self.hash_seed = util.rand64();
        // 重新分配
        if (self.cachesize > 0) self.clear();
        self.cachesize = cachesize;
        self.cache_head = null;
        self.cache_tail = null;
        self.free_head = null;
        self.count = 0;
        self.stale_ttl = 0; // 由 setStaleTtl 单独设

        if (cachesize > 0) {
            const recs = try self.allocator.alloc(CRec, cachesize);
            self.records = recs;
            for (recs) |*r| {
                r.* = .{};
                r.next = self.free_head;
                self.free_head = r;
            }
        }

        // C 版本保证 hash_size 为 2 的幂（hash_bucket 用位与取模）
        var buckets: usize = 64;
        while (buckets < cachesize / 10 + 1) buckets <<= 1;
        if (self.hash_table.len != 0) self.allocator.free(self.hash_table);
        self.hash_table = try self.allocator.alloc(?*CRec, buckets);
        self.hash_size = buckets;
        @memset(self.hash_table, null);
    }

    /// 设置 --use-stale-cache 窗口（0=禁用）。daemon 在 init 后调用一次。
    pub fn setStaleTtl(self: *Cache, ttl: u32) void {
        self.stale_ttl = ttl;
    }

    pub fn deinit(self: *Cache) void {
        self.clear();
        if (self.hash_table.len != 0) {
            self.allocator.free(self.hash_table);
            self.hash_table = &.{};
        }
        if (self.records) |recs| {
            self.allocator.free(recs);
            self.records = null;
        }
        self.cachesize = 0;
    }

    // -----------------------------------------------------------------------
    // 锁（对外函数使用）
    // -----------------------------------------------------------------------
    pub fn lock(self: *Cache, io: Io) void {
        self.mutex.lockUncancelable(io);
    }

    pub fn unlock(self: *Cache, io: Io) void {
        self.mutex.unlock(io);
    }

    // -----------------------------------------------------------------------
    // 名字存取
    // -----------------------------------------------------------------------
    /// 对应 cache_get_name()
    pub fn getName(self: *Cache, crecp: *const CRec) []const u8 {
        if ((crecp.flags & protocol.F_BIGNAME) != 0) {
            if (crecp.bname) |b| return b;
        }
        if ((crecp.flags & protocol.F_NAMEP) != 0) {
            if (crecp.namep) |p| return self.getName(p);
        }
        return std.mem.sliceTo(&crecp.sname, 0);
    }

    /// 对应 cache_get_cname_target()
    ///
    /// 两种保存方式都要支持，缺一不可 —— 只实现指针那条会让「从上游应答里
    /// 提取出来的 CNAME」全部返回空目标（实机上表现为：缓存命中的应答里
    /// CNAME 目标名为空、后续 A 记录也随之丢失）。
    pub fn getCnameTarget(self: *Cache, crecp: *const CRec) []const u8 {
        if (crecp.addr.cname.is_name_ptr)
            return crecp.addr.cname.target_name orelse "";
        const target = crecp.addr.cname.target_crec orelse return "";
        const p: *const CRec = @ptrCast(@alignCast(target));
        return self.getName(p);
    }

    // -----------------------------------------------------------------------
    // 哈希
    // -----------------------------------------------------------------------
    /// 名字 -> 桶。用标准库 Wyhash（带进程级随机 seed）。
    ///
    /// 与旧实现（C 的 rotate-7 + add）的差异：
    ///   * 更快（实测 15.8 字节名字 ~3.5ns vs ~17ns）；分布更好、低位也充分混合，
    ///     可直接用 `& (size-1)` 取桶。
    ///   * 大小写不敏感由 wyhashName() 保证（Wyhash 本身不做折叠）。
    /// 桶归属与 C 不同，但这**不影响任何外部可观测行为**：缓存不跨进程/跨实现共享，
    /// 只在进程内要求「插入、查找、删除用同一个函数」——这一点是满足的。
    fn hashBucket(self: *Cache, nm: []const u8) *?*CRec {
        const h = wyhashName(self.hash_seed, nm);
        return &self.hash_table[@as(usize, @intCast(h & (self.hash_size - 1)))];
    }

    /// 对应 cache_hash()：F_REVERSE 与 F_IMMORTAL 记录排在同名普通记录之后
    fn hashInsert(self: *Cache, crecp: *CRec) void {
        const nm = self.getName(crecp);
        var up = self.hashBucket(nm);
        const flags = crecp.flags & (protocol.F_IMMORTAL | protocol.F_REVERSE);

        if ((flags & protocol.F_REVERSE) == 0) {
            while (up.*) |entry| {
                if ((entry.flags & protocol.F_REVERSE) == 0) break;
                up = &entry.hash_next;
            }

            if ((flags & protocol.F_IMMORTAL) != 0) {
                while (up.*) |entry| {
                    if ((entry.flags & protocol.F_IMMORTAL) != 0) break;
                    up = &entry.hash_next;
                }
            }
        }

        while (up.*) |entry| {
            const entry_name = self.getName(entry);
            if (!name.hostnameIsEqual(entry_name, nm) or
                flags != (entry.flags & (protocol.F_IMMORTAL | protocol.F_REVERSE)))
                break;
            up = &entry.hash_next;
        }

        crecp.hash_next = up.*;
        up.* = crecp;
    }

    fn hashRemove(self: *Cache, crecp: *CRec) void {
        const nm = self.getName(crecp);
        var up = self.hashBucket(nm);
        while (up.*) |entry| {
            if (entry == crecp) {
                up.* = entry.hash_next;
                crecp.hash_next = null;
                return;
            }
            up = &entry.hash_next;
        }
    }

    // -----------------------------------------------------------------------
    // LRU 链
    // -----------------------------------------------------------------------
    /// 对应 cache_link()：链头是最新使用的记录
    fn link(self: *Cache, crecp: *CRec) void {
        if (self.cache_head) |head| head.prev = crecp;
        crecp.next = self.cache_head;
        crecp.prev = null;
        self.cache_head = crecp;
        if (self.cache_tail == null) self.cache_tail = crecp;
    }

    /// 对应 cache_unlink()
    fn unlink(self: *Cache, crecp: *CRec) void {
        if (crecp.prev) |p| p.next = crecp.next else self.cache_head = crecp.next;
        if (crecp.next) |n| n.prev = crecp.prev else self.cache_tail = crecp.prev;
        crecp.next = null;
        crecp.prev = null;
    }

    /// 对应 is_expired()
    /// 对应 is_expired()，带 --use-stale-cache 支持：
///   `self.stale_ttl == 0` → 老语义：ttd 一过就算过期。
///   `self.stale_ttl  > 0` → 距离 ttd 没超过 stale_ttl 秒时**仍可使用**。
/// 这样陈旧记录在窗口内继续被 findByName 命中，crecTtl 会自动把
/// TTL 返回为 0，让客户端主动重发。
    fn isExpired(self: *const Cache, crecp: *const CRec, now: i64) bool {
        if ((crecp.flags & protocol.F_IMMORTAL) != 0) return false;
        const past = now - crecp.ttd;
        if (past < 0) return false;
        if (self.stale_ttl != 0 and past < @as(i64, @intCast(self.stale_ttl))) return false;
        return true;
    }

    /// 对应 cache_free()：把记录从哈希与 LRU 中摘除并放回空闲链
    pub fn cacheFree(self: *Cache, crecp: *CRec) void {
        self.hashRemove(crecp);
        self.unlink(crecp);

        if (crecp.bname) |b| {
            self.allocator.free(b);
            crecp.bname = null;
        }

        // CNAME 名字模式持有的是自有拷贝，必须在 addr 被清空前释放，
        // 否则 allocCrec 里的 `r.* = .{}` 会让这块内存永远找不回来。
        if ((crecp.flags & protocol.F_CNAME) != 0 and crecp.addr.cname.is_name_ptr) {
            if (crecp.addr.cname.target_name) |tn| {
                self.allocator.free(tn);
                crecp.addr.cname.target_name = null;
            }
        }

        // 高5：F_RR（SRV/PTR 正向缓存）持有的 RDATA 是自有拷贝，同样必须在
        // addr 被清空前释放。用 tag 判断而非 flags 判断，避免 union 字段误读。
        if (std.meta.activeTag(crecp.addr) == .rr) {
            if (crecp.addr.rr.owned and crecp.addr.rr.data.len != 0)
                self.allocator.free(crecp.addr.rr.data);
            crecp.addr.rr = .{};
        }

        crecp.flags &= ~(protocol.F_FORWARD | protocol.F_REVERSE);
        crecp.uid = UID_NONE;
        crecp.addr = .{ .none = {} };
        crecp.ttd = 0;
        crecp.sname[0] = 0;

        crecp.next = self.free_head;
        self.free_head = crecp;
        if (self.count > 0) self.count -= 1;
    }

    /// 从空闲链取一条记录；没有空闲时淘汰最久未使用的**可回收**记录
    ///
    /// 关键约束（此前漏掉，是实机压测暴露的严重 bug）：
    /// F_HOSTS / F_DHCP / F_CONFIG 记录**永远不能被淘汰**。对应 C 版
    /// cache.c 的两处：
    ///   * cache_scan_free()：命中 `crecp->flags & (F_HOSTS|F_DHCP|F_CONFIG)`
    ///     时直接 return（表示「这是 hosts 记录，删不得」），释放前一律带
    ///     `if (!(crecp->flags & (F_HOSTS | F_DHCP | F_CONFIG))) cache_free(...)`；
    ///   * really_insert()：从 cache_tail 往前找槽位，找不到可回收的就
    ///     `insert_error = 1; return NULL;` —— **宁可这次不缓存，也不动它们**。
    ///
    /// 旧实现直接 `cacheFree(self.cache_tail)`，无条件干掉 LRU 队尾。而 hosts
    /// 记录在启动时入表、之后极少被查询（LRU 只在使用时被提到队首），于是它们
    /// 一路沉到队尾，重负载下最先被淘汰。实测：500 域名 × 32 线程压 120s 之后，
    /// localhost / ip6-localhost / ip6-loopback 的 hosts 记录全部消失，连
    /// `localhost A` 都回 NXDOMAIN（C 版同样负载下始终正常）——正是靠「重启后
    /// 立刻恢复」确认了是内存态淘汰、而非配置或解析问题。
    fn allocCrec(self: *Cache, now: i64) ?*CRec {
        // 过期清理由调用方（insertEx → evictExpired）负责；这里纯按 LRU 顺序回收，
        // 与 C 的 really_insert 一致。
        _ = now;
        if (self.free_head) |r| {
            self.free_head = r.next;
            r.* = .{};
            return r;
        }

        // 无空闲记录：自 LRU 尾部（最久未使用）向前找第一条**可回收**记录。
        // C 里 cache_free() 会把释放的记录挂到 LRU 尾部，所以 really_insert()
        // 通常只看队尾一次；这里因为空闲记录走的是独立 free_head（已从 LRU 摘除），
        // 需要显式跳过队尾中不可回收的记录。普通记录照常按 LRU 淘汰（不要求过期）。
        // 给一个扫描上限，避免「整张表都不可回收」时退化成 O(n)；真到那一步
        // 就与 C 一样放弃本次插入（返回 null）。
        const MAX_SCAN: usize = 1024;
        var victim = self.cache_tail;
        var scanned: usize = 0;
        while (victim) |v| : (victim = v.prev) {
            scanned += 1;
            if (scanned > MAX_SCAN) break;

            // 不可回收：hosts / DHCP / 配置 / 不朽记录
            if ((v.flags & (protocol.F_HOSTS | protocol.F_DHCP | protocol.F_CONFIG)) != 0) continue;
            if ((v.flags & protocol.F_IMMORTAL) != 0) continue;

            self.cacheFree(v);
            if (self.free_head) |r| {
                self.free_head = r.next;
                r.* = .{};
                return r;
            }
            return null;
        }
        return null;
    }

    /// 先尝试淘汰过期记录，腾出空间
    fn evictExpired(self: *Cache, now: i64) void {
        var crecp = self.cache_tail;
        var scanned: usize = 0;
        while (crecp) |c| {
            const prev = c.prev;
            if (self.isExpired(c, now)) self.cacheFree(c);
            crecp = prev;
            scanned += 1;
            if (scanned > 64) break;
        }
    }

    /// 释放「同名 + 同地址族」的正向地址记录，返回释放条数。
    ///
    /// 对应 C 版 `cache_scan_free()` 在 F_FORWARD 路径下命中
    /// `flags & crecp->flags & (F_IPV4 | F_IPV6)` 时对可回收记录的释放
    /// （`!(crecp->flags & (F_HOSTS|F_DHCP|F_CONFIG))` 才删）。
    ///
    /// **为什么需要它**：上游应答在「CNAME TTL 短 → 反复过期 → 反复转发」时会把
    /// 同一组 A/AAAA 反复插进缓存。没有这一步，旧记录不会被替换，缓存里就会出现
    /// 重复 RR —— 实测（假上游返回 3 条 A + CNAME(TTL=1)）Zig 版纯缓存命中回
    /// **6 条**（1.1.1.1,2.2.2.2,3.3.3.3,1.1.1.1,2.2.2.2,3.3.3.3），C 版回 3 条。
    ///
    /// **语义是「整组替换」不是「同名只留一条」**：C 用 new_chain 批处理让
    /// 同一应答内的多条地址互不驱逐，所以一个应答里的 3 个不同地址全部保留；
    /// 再次转发时先释放旧的同名同族记录、再插入新的一批，于是地址集合被整体替换
    /// （实测：上游把 1.1/2.2 改成 3.3/4.4 后，缓存只剩 3.3/4.4）。
    /// 这里的批处理等价物是**调用方保证「每个 (名字, 族) 在一次应答里只清一次」**。
    ///
    /// 与 C 一致的另一点：**不看是否过期**，同名同族的可回收记录一律替换；
    /// HOSTS / DHCP / CONFIG 记录永不释放。
    pub fn clearForwardAddrs(self: *Cache, nm: []const u8, family: u32, now: i64) usize {
        _ = now;
        var removed: usize = 0;
        var crecp = self.hashBucket(nm).*;
        while (crecp) |entry| {
            const nxt = entry.hash_next;
            if ((entry.flags & protocol.F_FORWARD) != 0 and
                (entry.flags & family) != 0 and
                (entry.flags & (protocol.F_HOSTS | protocol.F_DHCP | protocol.F_CONFIG)) == 0 and
                name.hostnameIsEqual(self.getName(entry), nm))
            {
                self.cacheFree(entry);
                removed += 1;
            }
            crecp = nxt;
        }
        return removed;
    }

    /// round-robin 轮转：把哈希桶里「第一条同名同族正向记录」移到桶尾，
    /// 使**下一次**查找从不同的记录开始。
    ///
    /// 对应 C 版 `cache_find_by_name()` 的行为 —— 它在每次查找时重排哈希链
    /// （`*up = crecp->hash_next; crecp->hash_next = *insert; *insert = crecp;`），
    /// 于是同名多条 A/AAAA 的下一次应答从下一条记录开头，即 round-robin。
    /// 由 `--no-round-robin`（`OPT_NORR`）关闭；本方法只在开启时被调用。
    ///
    /// 只有匹配记录 ≥2 条时才真正重排（单条轮转无意义，且避免每查询无谓改链）。
    /// 哈希链顺序不影响任何查找正确性（查找总是扫完整个桶），所以移动是安全的。
    pub fn rotateForwardAddrs(self: *Cache, nm: []const u8, family: u32) void {
        const bucket = self.hashBucket(nm);
        var prev: ?*CRec = null;
        var cur = bucket.*;
        var first: ?*CRec = null;
        var first_prev: ?*CRec = null;
        var last: ?*CRec = null;
        var last_prev: ?*CRec = null;
        var count: usize = 0;
        while (cur) |entry| {
            if ((entry.flags & protocol.F_FORWARD) != 0 and
                (entry.flags & family) != 0 and
                name.hostnameIsEqual(self.getName(entry), nm))
            {
                if (first == null) {
                    first = entry;
                    first_prev = prev;
                }
                last = entry;
                last_prev = prev;
                count += 1;
            }
            prev = entry;
            cur = entry.hash_next;
        }
        if (count < 2) return;

        // 方向与 C 实测一致：把**最后一条**匹配记录移到**第一条之前**
        //（即右旋一位）。C 实测序列 1,2,3 → 3,1,2 → 2,3,1 → 1,2,3，
        // 正是「末条提前」；若改成「首条移尾」会得到反方向的 2,3,1。
        const f = first.?;
        const l = last.?;
        const lp = last_prev.?; // count>=2 ⇒ last ≠ first ⇒ last_prev 必非空

        lp.hash_next = l.hash_next; // 把 l 从原位置摘下
        if (first_prev) |fp| {
            fp.hash_next = l; // 插到 first 之前
        } else {
            bucket.* = l;
        }
        l.hash_next = f;
    }

    // -----------------------------------------------------------------------
    // 插入 / 查找
    // -----------------------------------------------------------------------
    /// 对应 cache_insert()
    pub fn insert(
        self: *Cache,
        nm: []const u8,
        a: ?addr.AllAddr,
        class: u16,
        now: i64,
        ttl: u32,
        flags: u32,
    ) ?*CRec {
        return self.insertEx(nm, a, class, now, ttl, flags, true);
    }

    /// insert 的内部实现。
    ///
    /// `do_non_term` 为 false 时不再连带创建父级空记录 —— 建非终结点本身也要
    /// 插记录，若不关掉就会无限递归（C 版本是直接插记录绕开这一点）。
    fn insertEx(
        self: *Cache,
        nm: []const u8,
        a: ?addr.AllAddr,
        class: u16,
        now: i64,
        ttl: u32,
        flags: u32,
        do_non_term: bool,
    ) ?*CRec {
        _ = class;
        if (nm.len == 0 or nm.len > protocol.MAXDNAMESTR) return null;

        var crecp = self.allocCrec(now);
        if (crecp == null) {
            self.evictExpired(now);
            crecp = self.allocCrec(now);
        }
        const c = crecp orelse return null;

        // 名字存储
        if (nm.len <= SMALLDNAME) {
            @memcpy(c.sname[0..nm.len], nm);
            c.sname[nm.len] = 0;
            c.flags = flags & ~(protocol.F_BIGNAME | protocol.F_NAMEP);
        } else {
            const b = self.allocator.alloc(u8, nm.len) catch {
                self.cacheFree(c);
                return null;
            };
            @memcpy(b, nm);
            c.bname = b;
            c.flags = flags | protocol.F_BIGNAME;
        }

        if (a) |v| c.addr = v;

        if ((flags & protocol.F_IMMORTAL) != 0) {
            c.ttd = @as(i64, ttl); // 对应 C：immortal 记录的 ttd 直接保存 ttl
        } else {
            c.ttd = now + @as(i64, ttl);
        }
        c.uid = UID_NONE;

        self.hashInsert(c);
        self.link(c);
        self.count += 1;

        // 对应 C 的 add_hosts_entry() 末尾 / 配置记录插入后的 make_non_terminals()
        if (do_non_term) {
            // 只对「本地名字」建非终结点：hosts / 配置来的正向地址记录
            if ((flags & protocol.F_FORWARD) != 0 and
                (flags & (protocol.F_HOSTS | protocol.F_CONFIG)) != 0 and
                (flags & (protocol.F_IPV4 | protocol.F_IPV6 | protocol.F_CNAME)) != 0 and
                (flags & (protocol.F_NEG | protocol.F_REVERSE)) == 0)
            {
                self.makeNonTerminals(nm, now, ttl, flags);
            }
        }
        return c;
    }

    /// 对应 cache.c: make_non_terminals()
    ///
    /// 为一个本地名字（如 three.two.one）建立各级父名的「空记录」
    /// （two.one、one）。这些记录不带 F_IPV4/F_IPV6/F_CNAME，
    /// 作用是让父名字的查询得到 NoData 而不是 NXDOMAIN，
    /// 同时给 check_for_local_domain() 提供「这个域下确实有本地名字」的依据。
    fn makeNonTerminals(self: *Cache, nm: []const u8, now: i64, ttl: u32, flags: u32) void {
        // 去掉地址类与反向标记：父名只是「非终结点」，不代表具体地址
        const keep = flags & ~(protocol.F_IPV4 | protocol.F_IPV6 | protocol.F_CNAME |
            protocol.F_RR | protocol.F_DNSKEY | protocol.F_DS | protocol.F_REVERSE);

        var rest: []const u8 = nm;
        while (std.mem.indexOfScalar(u8, rest, '.')) |dot| {
            rest = rest[dot + 1 ..];
            if (rest.len == 0) break;

            // 已有同名的正向本地记录 -> 只把更晚的到期时间/不朽属性传下去
            if (self.findLocalByName(rest, now, protocol.F_HOSTS | protocol.F_CONFIG)) |ex| {
                if ((ex.flags & protocol.F_IMMORTAL) == 0) {
                    if ((flags & protocol.F_IMMORTAL) != 0) {
                        ex.flags |= protocol.F_IMMORTAL;
                    } else if (ex.ttd < now + @as(i64, ttl)) {
                        ex.ttd = now + @as(i64, ttl);
                    }
                }
                continue;
            }

            _ = self.insertEx(rest, null, protocol.C_IN, now, ttl, keep, false);
        }
    }

    /// 在哈希桶里找「名字完全相同」的本地记录（对应 C make_non_terminals 里的查重）
    fn findLocalByName(self: *Cache, nm: []const u8, now: i64, kind: u32) ?*CRec {
        var crecp = self.hashBucket(nm).*;
        while (crecp) |c| {
            if (!self.isExpired(c, now) and (c.flags & protocol.F_FORWARD) != 0 and
                (c.flags & kind) != 0 and name.hostnameIsEqual(self.getName(c), nm))
                return c;
            crecp = c.hash_next;
        }
        return null;
    }

    /// 对应 cache_insert() 的 CNAME 版本
    ///
    /// 两种模式：
    ///   - `target` 非空：指针模式，目标名取自那条缓存记录（is_name_ptr = false）
    ///   - `target_name` 非空：名字模式（is_name_ptr = true）。**必须拷贝**：
    ///     调用方 extractAddresses 传进来的是会被下一条 RR 覆盖的临时缓冲，
    ///     直接保存切片会变成悬垂引用，缓存命中时目标名就成了垃圾。
    pub fn insertCname(
        self: *Cache,
        nm: []const u8,
        target: ?*CRec,
        target_name: ?[]const u8,
        now: i64,
        ttl: u32,
        flags: u32,
    ) ?*CRec {
        const c = self.insert(nm, null, protocol.C_IN, now, ttl, flags | protocol.F_CNAME) orelse
            return null;

        if (target) |t| {
            c.addr = .{ .cname = .{
                .target_crec = @ptrCast(t),
                .target_name = null,
                .uid = 0,
                .is_name_ptr = false,
            } };
        } else if (target_name) |tn| {
            const owned = self.allocator.dupe(u8, tn) catch {
                c.addr = .{ .cname = .{} };
                return c;
            };
            c.addr = .{ .cname = .{
                .target_crec = null,
                .target_name = owned,
                .uid = 0,
                .is_name_ptr = true,
            } };
        } else {
            c.addr = .{ .cname = .{} };
        }
        return c;
    }

    /// 对应 cache_find_by_name()：遍历整个桶内的哈希链。
    /// 注意：C 版本在链上查找时**不会**因为碰到不同名字就提前退出
    /// （同一桶里可能混有别的名字），这里保持一致。
    /// 按名字在哈希桶里找一条正向记录。
    ///
    /// **`flags` 只允许传「类型位」**（F_IPV4 / F_IPV6 / F_CNAME / F_NEG /
    /// F_NXDOMAIN / F_DNSKEY / F_DS ...），绝不能掺 F_FORWARD。
    ///
    /// 原因：下面的匹配是 `(c.flags & flags) != 0` —— 「交集判空」，与 C 版
    /// cache_find_by_name() 里的 `crecp->flags & prot` 语义一致（F_FORWARD 由本
    /// 函数自己单独校验）。C 的所有调用点传的都是单一类型位，交集判空才恰好
    /// 等价于类型精确匹配；一旦多传 F_FORWARD，任何正向记录都会满足交集，
    /// 于是 AAAA 查询会命中 A 记录、负缓存查询会命中正向记录。
    /// 这个坑在本地套件里看不出来（只查 A），是实机 A/B 对比才暴露的。
    pub fn findByName(self: *Cache, nm: []const u8, now: i64, flags: u32) ?*CRec {
        const r = self.findByNameFrom(null, nm, now, flags);
        if (r != null) _ = self.hits.fetchAdd(1, .monotonic) else _ = self.misses.fetchAdd(1, .monotonic);
        return r;
    }

    /// 对应 cache_find_by_name(crecp, name, now, prot) 的「续查」形态：
    /// `start` 为 null 时从哈希桶头找起，否则从该记录的下一条继续。
    ///
    /// 用途是把同名记录**全部**取出来应答 —— CDN 域名的 A 记录动辄十几条，
    /// 只答第一条会让负载均衡/容灾退化成单点（实机测试发现）。
    /// 续查不再累加 hits/misses：那两个计数器的口径是「一次查询做了几次查找」。
    pub fn findByNameFrom(self: *Cache, start: ?*CRec, nm: []const u8, now: i64, flags: u32) ?*CRec {
        var crecp = if (start) |s| s.hash_next else self.hashBucket(nm).*;
        while (crecp) |c| {
            if (!self.isExpired(c, now) and (c.flags & protocol.F_FORWARD) != 0 and
                (c.flags & flags) != 0 and name.hostnameIsEqual(self.getName(c), nm))
            {
                return c;
            }
            crecp = c.hash_next;
        }
        return null;
    }

    /// 对应 cache_find_by_addr()：按地址反查名字（用于 --bogus-priv / 局部域名）
    pub fn findByAddr(self: *Cache, a: addr.AllAddr, now: i64, prot: u32) ?*CRec {
        for (self.hash_table) |*bucket| {
            var crecp = bucket.*;
            while (crecp) |c| {
                if ((c.flags & protocol.F_REVERSE) != 0 and
                    (c.flags & prot) != 0 and
                    !self.isExpired(c, now) and
                    c.addr.eql(a))
                    return c;
                crecp = c.hash_next;
            }
        }
        return null;
    }

    /// 对应 cache.c: cache_find_non_terminal()
    ///
    /// 语义是「在这个名字下是否有本地记录」，实现方式是查**同名**的
    /// 非终结点记录（由 makeNonTerminals() 建立），而不是逐级找后缀：
    ///   * 必须带 F_FORWARD（本地记录）
    ///   * 不能是 F_NXDOMAIN（那是「确实不存在」的结论）
    ///   * 未过期，且名字完全相等
    pub fn findNonTerminal(self: *Cache, nm: []const u8, now: i64) bool {
        var crecp = self.hashBucket(nm).*;
        while (crecp) |c| {
            if (!self.isExpired(c, now) and
                (c.flags & protocol.F_FORWARD) != 0 and
                (c.flags & protocol.F_NXDOMAIN) == 0 and
                name.hostnameIsEqual(self.getName(c), nm))
                return true;
            crecp = c.hash_next;
        }
        return false;
    }

    /// 对应 cache_remove_uid()
    pub fn removeUid(self: *Cache, uid: u32) u32 {
        var removed: u32 = 0;
        for (self.hash_table) |*bucket| {
            var crecp = bucket.*;
            while (crecp) |c| {
                const tmp = c.hash_next;
                if (c.uid == uid) {
                    self.cacheFree(c);
                    removed += 1;
                }
                crecp = tmp;
            }
        }
        return removed;
    }

    /// 对应 cache_start_insert/cache_end_insert 的批处理——这里即时插入，
    /// 仅保留入口以便与 C 的调用点对应。
    pub fn startInsert(self: *Cache) void {
        _ = self;
    }

    pub fn endInsert(self: *Cache) void {
        _ = self;
    }

    /// 对应 cache_clear()：清空所有记录（保留内存）
    pub fn clear(self: *Cache) void {
        for (self.hash_table) |*bucket| {
            var crecp = bucket.*;
            while (crecp) |c| {
                const next = c.hash_next;
                self.cacheFree(c);
                crecp = next;
            }
            bucket.* = null;
        }
        // cacheFree 会把记录放回 free_head
    }

    /// 对应 crec_ttl()
    pub fn crecTtl(self: *Cache, crecp: *const CRec, now: i64, conf_ttl: u32) u32 {
        _ = self;
        const ttl: i64 = crecp.ttd - now;

        if ((crecp.flags & protocol.F_DHCP) != 0) {
            if ((crecp.flags & protocol.F_IMMORTAL) == 0 and ttl < @as(i64, conf_ttl))
                return @intCast(@max(ttl, 0));
            return conf_ttl;
        }

        if ((crecp.flags & protocol.F_IMMORTAL) != 0) return @intCast(crecp.ttd);
        if (ttl < 0) return 0;
        return @intCast(ttl);
    }

    /// 对应 crec_is_stale()，与 isExpired 同语义（陈旧窗口由 self.stale_ttl 控）。
    pub fn isStale(self: *Cache, crecp: *const CRec, now: i64) bool {
        return self.isExpired(crecp, now);
    }

    fn crecIsStale_(crecp: *const CRec, now: i64) bool {
        return ((crecp.flags & protocol.F_IMMORTAL) == 0) and (crecp.ttd - now < 0);
    }

    /// 是否已经超过陈旧窗口可以彻底清理（与 isStale 同义，命名上更清楚）
    pub fn isExpiredForGC(self: *Cache, crecp: *const CRec, now: i64) bool {
        return self.isExpired(crecp, now);
    }

    /// 过期清理（对应 cache 的 housekeeping）
    pub fn expire(self: *Cache, now: i64) usize {
        var n: usize = 0;
        var crecp = self.cache_tail;
        while (crecp) |c| {
            const prev = c.prev;
            if (self.isExpired(c, now)) {
                self.cacheFree(c);
                n += 1;
            }
            crecp = prev;
        }
        return n;
    }

    /// 记一次查询的最终去向。由 answerRequest 收尾时调用。
    pub fn noteQuery(self: *Cache, from_cache: bool, answered: bool) void {
        if (from_cache) {
            _ = self.query_hits.fetchAdd(1, .monotonic);
        } else if (answered) {
            _ = self.query_local_config.fetchAdd(1, .monotonic);
        } else {
            _ = self.query_misses.fetchAdd(1, .monotonic);
        }
    }

    /// 缓存统计（供 SIGUSR1 与压测观测）。
    /// `hits/misses` 是查找级，`query_*` 是查询级 —— 命中率请用后者。
    pub fn stats(self: *const Cache) Stats {
        return .{
            .hits = self.hits.load(.monotonic),
            .misses = self.misses.load(.monotonic),
            .query_hits = self.query_hits.load(.monotonic),
            .query_misses = self.query_misses.load(.monotonic),
            .query_local_config = self.query_local_config.load(.monotonic),
        };
    }

    /// 查询级缓存命中率（0.0 ~ 1.0）。无查询样本时返回 0。
    pub fn hitRatio(self: *const Cache) f64 {
        const st = self.stats();
        const total = st.query_hits + st.query_misses;
        if (total == 0) return 0;
        return @as(f64, @floatFromInt(st.query_hits)) / @as(f64, @floatFromInt(total));
    }

    pub fn countEntries(self: *Cache) usize {
        return self.count;
    }
};

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------
const testing = std.testing;

test "cache insert / find / expire" {
    const allocator = testing.allocator;
    var c = try Cache.init(allocator, 16);
    defer c.deinit();

    var a: addr.AllAddr = .{ .ip4 = 0 };
    _ = addr.parseIp4("192.168.1.10", &a.ip4);

    const now: i64 = 1000;
    const rec = c.insert("host.example.com", a, protocol.C_IN, now, 60, protocol.F_FORWARD | protocol.F_IPV4);
    try testing.expect(rec != null);
    try testing.expectEqual(@as(usize, 1), c.countEntries());

    const found = c.findByName("HOST.example.com", now + 10, protocol.F_FORWARD | protocol.F_IPV4);
    try testing.expect(found != null);
    try testing.expectEqual(@as(u32, 50), c.crecTtl(found.?, now + 10, 3600));

    // 过期后查不到
    try testing.expect(c.findByName("host.example.com", now + 100, protocol.F_FORWARD) == null);

    // 过期清理
    _ = c.expire(now + 200);
    try testing.expectEqual(@as(usize, 0), c.countEntries());
}

/// 统计某个名字下某「地址族」的正向记录条数（测试辅助）
fn countForward(c: *Cache, nm: []const u8, now: i64, family: u32) usize {
    var n: usize = 0;
    var it: ?*CRec = null;
    while (c.findByNameFrom(it, nm, now, protocol.F_FORWARD | family)) |r| {
        n += 1;
        it = r;
    }
    return n;
}

test "clearForwardAddrs：同名同族整组替换（重复 RR 回归）" {
    const allocator = testing.allocator;
    var c = try Cache.init(allocator, 32);
    defer c.deinit();
    const now: i64 = 1000;
    const flags = protocol.F_FORWARD | protocol.F_IPV4;

    const group1 = [_][]const u8{ "1.1.1.1", "2.2.2.2", "3.3.3.3" };
    for (group1) |s| {
        var a: addr.AllAddr = .{ .ip4 = 0 };
        try testing.expect(addr.parseIp4(s, &a.ip4));
        try testing.expect(c.insert("cdn.example", a, protocol.C_IN, now, 60, flags) != null);
    }
    try testing.expectEqual(@as(usize, 3), countForward(&c, "cdn.example", now, protocol.F_IPV4));

    // 重转发同一组地址：整组替换后仍是 3 条（修复前会累积成 6 条 —— 实机回归点）
    try testing.expectEqual(@as(usize, 3), c.clearForwardAddrs("cdn.example", protocol.F_IPV4, now));
    for (group1) |s| {
        var a: addr.AllAddr = .{ .ip4 = 0 };
        _ = addr.parseIp4(s, &a.ip4);
        _ = c.insert("cdn.example", a, protocol.C_IN, now, 60, flags);
    }
    try testing.expectEqual(@as(usize, 3), countForward(&c, "cdn.example", now, protocol.F_IPV4));

    // 地址变化：整组替换（旧地址全部消失，与 C 实测一致）
    try testing.expectEqual(@as(usize, 3), c.clearForwardAddrs("cdn.example", protocol.F_IPV4, now));
    for ([_][]const u8{ "9.9.9.9", "8.8.8.8" }) |s| {
        var a: addr.AllAddr = .{ .ip4 = 0 };
        _ = addr.parseIp4(s, &a.ip4);
        _ = c.insert("cdn.example", a, protocol.C_IN, now, 60, flags);
    }
    try testing.expectEqual(@as(usize, 2), countForward(&c, "cdn.example", now, protocol.F_IPV4));

    // 异族（IPv6）不受 IPv4 清理影响
    var a6: addr.AllAddr = .{ .ip6 = undefined };
    _ = addr.parseIp6("2001:db8::1", &a6.ip6);
    _ = c.insert("cdn.example", a6, protocol.C_IN, now, 60, protocol.F_FORWARD | protocol.F_IPV6);
    try testing.expectEqual(@as(usize, 2), c.clearForwardAddrs("cdn.example", protocol.F_IPV4, now));
    try testing.expectEqual(@as(usize, 1), countForward(&c, "cdn.example", now, protocol.F_IPV6));

    // HOSTS / CONFIG 记录永不释放（对应 C cache_scan_free 的 F_HOSTS 保护）
    var ah: addr.AllAddr = .{ .ip4 = 0 };
    _ = addr.parseIp4("10.0.0.1", &ah.ip4);
    _ = c.insert("lanhost", ah, protocol.C_IN, now, 60, protocol.F_FORWARD | protocol.F_IPV4 | protocol.F_HOSTS);
    try testing.expectEqual(@as(usize, 0), c.clearForwardAddrs("lanhost", protocol.F_IPV4, now));
    try testing.expectEqual(@as(usize, 1), countForward(&c, "lanhost", now, protocol.F_IPV4));
}

/// 取某个名字下第一条匹配地址的最后一个八位组（测试辅助，用于观察顺序）
fn firstOctet(c: *Cache, nm: []const u8, now: i64, family: u32) u8 {
    const r = c.findByName(nm, now, protocol.F_FORWARD | family) orelse return 0;
    return @as([4]u8, @bitCast(r.addr.ip4))[3];
}

test "rotateForwardAddrs：同名多地址右旋（round-robin 与 C 同向）" {
    const allocator = testing.allocator;
    var c = try Cache.init(allocator, 32);
    defer c.deinit();
    const now: i64 = 1000;
    const flags = protocol.F_FORWARD | protocol.F_IPV4;
    for ([_][]const u8{ "1.1.1.1", "2.2.2.2", "3.3.3.3" }) |s| {
        var a: addr.AllAddr = .{ .ip4 = 0 };
        _ = addr.parseIp4(s, &a.ip4);
        _ = c.insert("rr.example", a, protocol.C_IN, now, 60, flags);
    }
    // 首条是 1；每次轮转把「末条移到最前」（右旋），与 C 实测序列一致
    try testing.expectEqual(@as(u8, 1), firstOctet(&c, "rr.example", now, protocol.F_IPV4));
    c.rotateForwardAddrs("rr.example", protocol.F_IPV4);
    try testing.expectEqual(@as(u8, 3), firstOctet(&c, "rr.example", now, protocol.F_IPV4));
    c.rotateForwardAddrs("rr.example", protocol.F_IPV4);
    try testing.expectEqual(@as(u8, 2), firstOctet(&c, "rr.example", now, protocol.F_IPV4));
    c.rotateForwardAddrs("rr.example", protocol.F_IPV4);
    try testing.expectEqual(@as(u8, 1), firstOctet(&c, "rr.example", now, protocol.F_IPV4));

    // 三条仍在（轮转不得丢记录）
    try testing.expectEqual(@as(usize, 3), countForward(&c, "rr.example", now, protocol.F_IPV4));

    // 单条记录：轮转是 no-op，且不能崩
    var a: addr.AllAddr = .{ .ip4 = 0 };
    _ = addr.parseIp4("5.5.5.5", &a.ip4);
    _ = c.insert("one.example", a, protocol.C_IN, now, 60, flags);
    c.rotateForwardAddrs("one.example", protocol.F_IPV4);
    try testing.expectEqual(@as(u8, 5), firstOctet(&c, "one.example", now, protocol.F_IPV4));
}

test "名字哈希：大小写等价 + 跨分块折叠一致（Wyhash 迁移回归）" {
    const seed: u64 = 0x0123456789abcdef;

    // 1) 大小写必须归一到同一哈希（否则 "Foo.COM" 与 "foo.com" 会各自落桶、漏命中）
    try testing.expectEqual(wyhashName(seed, "Foo.COM"), wyhashName(seed, "foo.com"));
    try testing.expectEqual(wyhashName(seed, "WWW.A.Example"), wyhashName(seed, "www.a.example"));

    // 2) 无大写的快路径必须与 std 的直接哈希逐位相同
    try testing.expectEqual(std.hash.Wyhash.hash(seed, "foo.com"), wyhashName(seed, "foo.com"));

    // 3) 超过 64 字节的名字会走分块折叠，结果必须与全小写版本一致
    const up = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lo = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz";
    try testing.expect(up.len > 64);
    try testing.expectEqual(wyhashName(seed, up), wyhashName(seed, lo));

    // 4) 分布不退化：1000 个不同名字不应挤在极少数桶里
    const allocator = testing.allocator;
    var c = try Cache.init(allocator, 10_000); // → hash_size = 1024
    defer c.deinit();
    var seen = try allocator.alloc(bool, c.hash_size);
    defer allocator.free(seen);
    @memset(seen, false);
    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        var nmbuf: [32]u8 = undefined;
        const nm = try std.fmt.bufPrint(&nmbuf, "h{d}.example.com", .{i});
        const bucket = c.hashBucket(nm);
        const idx = (@intFromPtr(bucket) - @intFromPtr(&c.hash_table[0])) / @sizeOf(?*CRec);
        seen[idx] = true;
    }
    var used: usize = 0;
    for (seen) |b| {
        if (b) used += 1;
    }
    // 1000 个名字散到 1024 桶，期望用掉 600+ 个桶；阈值取 500 以容忍实现细节
    try testing.expect(used > 500);
}

test "cache eviction keeps most recent" {
    const allocator = testing.allocator;
    var c = try Cache.init(allocator, 4);
    defer c.deinit();

    var a: addr.AllAddr = .{ .ip4 = 0 };
    _ = addr.parseIp4("10.0.0.1", &a.ip4);

    var i: usize = 0;
    while (i < 4) : (i += 1) {
        var buf: [32]u8 = undefined;
        const nm = std.fmt.bufPrint(&buf, "h{d}.test", .{i}) catch unreachable;
        _ = c.insert(nm, a, protocol.C_IN, 100, 1000, protocol.F_FORWARD | protocol.F_IPV4);
        _ = c.findByName(nm, 100, protocol.F_FORWARD);
    }

    // 再插一条，触发淘汰最久未使用的记录
    _ = c.insert("extra.test", a, protocol.C_IN, 100, 1000, protocol.F_FORWARD | protocol.F_IPV4);
    try testing.expect(c.countEntries() <= 5);
    try testing.expect(c.findByName("extra.test", 100, protocol.F_FORWARD) != null);
}

test "cache 淘汰绝不回收 hosts/DHCP 记录（实机压测回归）" {
    // 现象：500 域名 × 32 线程压 120s 后，localhost 等 hosts 记录被挤出缓存，
    // 连 `localhost A` 都回 NXDOMAIN。根因是 allocCrec 无条件淘汰 LRU 队尾，
    // 而 hosts 记录启动后极少被查询，会一路沉到队尾。C 版永不回收这类记录。
    const allocator = testing.allocator;
    var c = try Cache.init(allocator, 8);
    defer c.deinit();

    var a: addr.AllAddr = .{ .ip4 = 0 };
    _ = addr.parseIp4("127.0.0.1", &a.ip4);
    const now: i64 = 1000;

    // 一条 hosts 记录（F_HOSTS | F_IMMORTAL，非终结点也会连带插入）
    const hflags = protocol.F_FORWARD | protocol.F_IPV4 | protocol.F_HOSTS | protocol.F_IMMORTAL;
    try testing.expect(c.insert("localhost", a, protocol.C_IN, now, 1 << 30, hflags) != null);

    // 灌入远超容量的普通上游缓存记录（长 TTL，不会因过期被回收）
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var buf: [48]u8 = undefined;
        const nm = std.fmt.bufPrint(&buf, "flood{d}.example.com", .{i}) catch unreachable;
        _ = c.insert(nm, a, protocol.C_IN, now, 100000, protocol.F_FORWARD | protocol.F_IPV4);
        // 模拟真实查询：新记录被 LRU 提到队首，hosts 记录随之下沉
        _ = c.findByName(nm, now, protocol.F_FORWARD);
    }

    // hosts 记录必须仍然在
    const still = c.findByName("localhost", now, protocol.F_FORWARD | protocol.F_IPV4);
    try testing.expect(still != null);

    // 整张表都被 hosts 记录占满时，也绝不能互相挤掉：向小缓存灌入远超容量的
    // hosts 名字，最先插入的那些必须仍然在（对应 C「宁可插入失败也不动它们」）。
    var c2 = try Cache.init(allocator, 8);
    defer c2.deinit();
    var k: usize = 0;
    while (k < 40) : (k += 1) {
        var buf: [48]u8 = undefined;
        const nm = std.fmt.bufPrint(&buf, "h{d}.lan", .{k}) catch unreachable;
        _ = c2.insert(nm, a, protocol.C_IN, now, 1 << 30, hflags);
    }
    try testing.expect(c2.findByName("h0.lan", now, protocol.F_FORWARD) != null);
    try testing.expect(c2.findByName("h1.lan", now, protocol.F_FORWARD) != null);
}

test "use-stale-cache: 窗口内仍服务，窗口外视为过期" {
    const a = testing.allocator;
    var c = try Cache.init(a, 16);
    defer c.deinit();

    var a4 = addr.AllAddr{ .ip4 = 0 };
    try testing.expect(addr.parseIp4("1.2.3.4", &a4.ip4));
    const now: i64 = 1000;
    const ttl: u32 = 60; // ttd = 1060

    _ = c.insert("stale.example", a4, protocol.C_IN, now, ttl, protocol.F_FORWARD | protocol.F_IPV4);

    // 禁用：陈旧窗口外立即过期
    c.setStaleTtl(0);
    try testing.expect(c.findByName("stale.example", now + 61, protocol.F_IPV4) == null);

    // 启用窗口=120 秒：滞后 1 秒仍命中，滞后 121 秒不再命中
    c.setStaleTtl(120);
    try testing.expect(c.findByName("stale.example", now + 61, protocol.F_IPV4) != null);
    try testing.expect(c.findByName("stale.example", now + 181, protocol.F_IPV4) == null);

    // 命中时 crecTtl 应返回 0（让客户端主动重发）
    if (c.findByName("stale.example", now + 61, protocol.F_IPV4)) |crecp| {
        try testing.expectEqual(@as(u32, 0), c.crecTtl(crecp, now + 61, 600));
    }
}

test "查询级缓存统计与查找级分开计数" {
    const a = testing.allocator;
    var c = try Cache.init(a, 64);
    defer c.deinit();

    const now: i64 = 1000;
    // 查找级：直接调用 findByName，miss 累加
    _ = c.findByName("nope.example", now, protocol.F_IPV4);
    _ = c.findByName("nope.example", now, protocol.F_IPV4);
    try testing.expectEqual(@as(u64, 2), c.stats().misses);
    try testing.expectEqual(@as(u64, 0), c.stats().query_misses);

    // 查询级：由 answerRequest 收尾时记账，口径是「一次查询一个结果」
    c.noteQuery(false, false); // 需要转发
    c.noteQuery(true, true); // 缓存命中
    c.noteQuery(true, true); // 缓存命中
    c.noteQuery(false, true); // --address / local= 之类的配置类应答

    const st = c.stats();
    try testing.expectEqual(@as(u64, 2), st.query_hits);
    try testing.expectEqual(@as(u64, 1), st.query_misses);
    try testing.expectEqual(@as(u64, 1), st.query_local_config);
    // 命中率只由 query_hits / query_misses 决定：2/(2+1) = 66.7%
    try testing.expect(c.hitRatio() > 0.666 and c.hitRatio() < 0.667);

    // 无样本时不除零
    var e = try Cache.init(a, 8);
    defer e.deinit();
    try testing.expectEqual(@as(f64, 0), e.hitRatio());
}

test "cache cname target" {
    const allocator = testing.allocator;
    var c = try Cache.init(allocator, 8);
    defer c.deinit();

    const target = c.insert("target.example.com", .{ .ip4 = 0 }, protocol.C_IN, 100, 60, protocol.F_FORWARD);
    const alias = c.insertCname("alias.example.com", target, null, 100, 60, protocol.F_FORWARD);
    try testing.expect(alias != null);
    try testing.expectEqualStrings("target.example.com", c.getCnameTarget(alias.?));
    try testing.expectEqualStrings("alias.example.com", c.getName(alias.?));
}

// 回归测试（实机发现）：上面那个测试走的是「指针模式」，而 extractAddresses
// 生产路径走的是「名字模式」（target_crec 传 null）。两条路都必须能取到目标名；
// 且名字模式必须持有自己的拷贝 —— 调用方传进来的切片指向一个会被下一条 RR
// 覆盖的临时缓冲，直接存切片会让缓存命中时的目标名变成垃圾。
test "cache cname target（名字模式：自有拷贝，不受调用方缓冲复用影响）" {
    const allocator = testing.allocator;
    var c = try Cache.init(allocator, 8);
    defer c.deinit();

    var tmp: [64]u8 = undefined;
    const t1 = "www.a.shifen.com";
    @memcpy(tmp[0..t1.len], t1);

    const alias = c.insertCname("www.baidu.com", null, tmp[0..t1.len], 100, 60,
        protocol.F_FORWARD | protocol.F_CNAME);
    try testing.expect(alias != null);
    try testing.expectEqualStrings(t1, c.getCnameTarget(alias.?));

    // 调用方复用同一块缓冲写下一条 RR 的名字：缓存里的目标名必须原样不变
    @memcpy(tmp[0..7], "garbage");
    try testing.expectEqualStrings(t1, c.getCnameTarget(alias.?));
    try testing.expectEqualStrings("www.baidu.com", c.getName(alias.?));

    // 通过缓存查找拿到的同一条记录也要能取到目标名
    const found = c.findByName("www.baidu.com", 100, protocol.F_CNAME);
    try testing.expect(found != null);
    try testing.expectEqualStrings(t1, c.getCnameTarget(found.?));

    // clear() 释放自有拷贝；testing.allocator 负责断言不泄漏
    c.clear();
}

test "big name storage" {
    const allocator = testing.allocator;
    var c = try Cache.init(allocator, 4);
    defer c.deinit();

    // 构造一个超过 63 字符的名字
    const big = "averyveryverylonglabelname" ** 4 ++ ".example.com";
    const rec = c.insert(big, .{ .ip4 = 0 }, protocol.C_IN, 100, 60, protocol.F_FORWARD);
    try testing.expect(rec != null);
    try testing.expect((rec.?.flags & protocol.F_BIGNAME) != 0);
    try testing.expectEqualStrings(big, c.getName(rec.?));
    try testing.expect(c.findByName(big, 100, protocol.F_FORWARD) != null);

    // 释放后名字缓冲不应泄漏（由 testing.allocator 检查）
    c.clear();
}
