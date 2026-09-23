// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! DHCPv6 / RA / NDP 运行时（server 模式优先）。
//!
//! 对照 odhcpd 的三个来源：
//!   - `router.c`  —— RA 的发送时机（启动即发 + 周期 + RS 触发）与内容；
//!   - `dhcpv6.c`  —— UDP :547 的报文处理（SOLICIT/REQUEST/RENEW/REBIND/
//!     INFORMATION-REQUEST → ADVERTISE/REPLY）；
//!   - `ndp.c`     —— 对**租约地址**的 NS 代理应答（内核只认自己的地址，
//!     客户端互相 NS 我们分配出去的地址时必须由我们代答）。
//!
//! 已知的阶段取舍（都写在这里，免得后人重新踩一遍）：
//!   - **relay 模式暂不支持**（按 server 处理 hybrid）。.1 的 lan 段是
//!     `ra='server'/dhcpv6='server'`，relay 是 downstream 场景，等有真实
//!     需求再补（需要跨接口转发 + interface-id 选项）。
//!   - IA_PD（前缀委派）暂不下发：下游路由器场景，lan 上没有。
//!   - 地址分配是**确定性哈希**（DUID+IAID → 接口 ID），重启后同一个客户端
//!     会拿回同一个地址，所以现阶段可以不落租约文件（与 odhcpd 的
//!     static-EUI64 分配行为等价）。
//!   - PIO 的 valid/preferred 用 v6conf 的上限（5400/2700），没有去读内核
//!     的 IFA_CACHEINFO —— 只要 RA 周期（默认 600s）小于它，SLAAC 地址就
//!     不会因为 RA 停发而过期。
//!
//! socket 层面的实测结论（见 DHCP-PLAN.md 第九节，全部在 .2 上验证过）：
//!   - raw ICMPv6 socket **会收到自己 TX 的包**，所以 ICMP6_FILTER 绝不能
//!     放行 134(RA)，且收包后要丢弃「源地址是自己」的报文（NA 也会自环）；
//!   - ICMPv6 校验和由内核代填，构造报文时填 0；
//!   - `IPV6_MULTICAST_LOOP=0` 关掉组播自环，双保险。

const std = @import("std");
const posix = std.posix;
const system = std.os.linux;
const net = @import("net.zig");
const addr = @import("addr.zig");
const log = @import("log.zig");
const util = @import("util.zig");
const v6conf = @import("v6conf.zig");
const dhcpv6 = @import("dhcpv6.zig");
const router = @import("router.zig");

const Allocator = std.mem.Allocator;

const IPPROTO_ICMPV6: i32 = 58;
const ICMP6_FILTER: u32 = 1; // setsockopt(IPPROTO_ICMPV6, ICMP6_FILTER, ...)
const SOLICITED_NODE_PREFIX: [16]u8 = .{ 0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xFF, 0, 0, 0 };

// IPv4 侧同类常量在 odhcpd_main.zig；这里 v6 的表很小，独立定义。
const MAX_V6_LEASES = 128;
const IA_VALID: u32 = 86400; // IA_NA 有效期（1 天）
const IA_PREFERRED: u32 = 43200;
const IA_T1: u32 = 21600; // 0.5 * valid
const IA_T2: u32 = 34560; // 0.8 * valid

/// 兜底全量重拉接口 IPv6 地址的间隔。**主路径是 netlink 事件**（见
/// openEventSocket）：地址/路由一变内核立刻推 RTM_NEWADDR/RTM_DELADDR/
/// RTM_*ROUTE，tick 里 1 秒内合并处理，这里只是防 netlink 丢事件的长间隔兜底。
const REFRESH_SECS: i64 = 60;
/// 前缀消失后旧 PIO 的残余有效期（preferred 恒 0）——让客户端把旧 SLAAC
/// 地址降级/淘汰，而不是等它自然过期。
const OLD_PIO_VALID: i64 = 600;

/// ipv6_mreq 在 Zig 0.16 的 std.os.linux 里没有现成结构，自己摆（RFC 3493）。
const Ipv6Mreq = extern struct {
    multiaddr: [16]u8,
    ifindex: u32,
};

/// ICMPv6 过滤器是 256 位的位图，**置位 = 丢弃**（musl/netinet/icmp6.h 的
/// SETBLOCK 是 setbit、SETPASS 是 clearbit，缺省全 0 = 全放行）。
/// 所以「只放行给定类型」= 全部置 1，再清掉放行位。
pub fn icmp6FilterPassOnly(types: []const u8) [32]u8 {
    var f = [_]u8{0xFF} ** 32;
    for (types) |ty| f[ty / 8] &= ~(@as(u8, 1) << @intCast(ty % 8));
    return f;
}

/// 一条 DHCPv6 分配记录（按 DUID+IAID 索引）。
const Lease6 = struct {
    duid: [32]u8 = undefined,
    duid_len: u8 = 0,
    iaid: u32 = 0,
    addr: [16]u8 = undefined,
    valid_until: i64 = 0,
};

/// 每个启用了 v6 的接口的运行时状态。
pub const V6Iface = struct {
    conf: v6conf.Iface6,
    ifindex: u32,
    mac: [6]u8 = .{ 0, 0, 0, 0, 0, 0 },
    /// 本接口的链路本地地址（RDNSS 缺省通告它，NA/RA 也用它做源）
    link_local: [16]u8 = [_]u8{0} ** 16,
    /// 全局地址 + 前缀长（PIO 的来源）
    globals: std.ArrayListUnmanaged(GlobalAddr) = .empty,
    icmp_fd: posix.fd_t = -1,
    udp_fd: posix.fd_t = -1,
    /// 下一次周期 RA 的时间戳（util.dnsmasqTime 秒）
    next_ra: i64 = 0,
    /// 前缀消失后的旧 PIO（preferred=0，valid 递减到 0 为止）。
    /// 放在接口上而不是全局表里 —— 换前缀本来就是 per-interface 的事件。
    old_prefixes: std.ArrayListUnmanaged(OldPio) = .empty,

    const GlobalAddr = struct {
        /// 归一化后的 /64 前缀（PIO 用）
        a: [16]u8,
        plen: u8,
        /// **本接口在这个前缀上的实际可用地址**（如 240e:...:26d0::1）。
        /// RDNSS 要通告的是这个「可路由的自身地址」，不是前缀。
        /// 归一化只影响 PIO；RDNSS 需要真实地址。
        self_addr: [16]u8 = [_]u8{0} ** 16,
        /// IFA_CACHEINFO 的绝对墙钟秒。0 = 内核没给。
        preferred: u32 = 0,
        valid: u32 = 0,
    };
    const OldPio = struct { prefix: [16]u8, valid: i64 };

    /// RA 是否启用（server/hybrid 按 server 跑；relay 暂不支持）
    pub fn raActive(self: *const V6Iface) bool {
        return self.conf.ra == .server or self.conf.ra == .hybrid;
    }
    pub fn dhcp6Active(self: *const V6Iface) bool {
        return self.conf.dhcpv6 == .server or self.conf.dhcpv6 == .hybrid;
    }
};

pub const V6Runtime = struct {
    allocator: Allocator,
    ifaces: std.ArrayListUnmanaged(V6Iface) = .empty,
    leases: [MAX_V6_LEASES]Lease6 = undefined,
    lease_count: usize = 0,
    server_duid: [10]u8 = undefined,
    duid_len: usize = 0,
    /// 下一次兜底重拉接口地址的时间（秒）
    next_refresh: i64 = 0,
    /// netlink 事件 socket（RTNLGRP_IPV6_IFADDR + RTNLGRP_IPV6_ROUTE 订阅）
    event_fd: posix.fd_t = -1,
    /// 有新分配时置位，由 Runtime 的每秒节拍消费（触发状态文件重写）
    dirty: bool = false,
    /// 事件标记：有地址增删 → 全量 refresh；有 ::/0 路由增删 → 全接口重发 RA。
    /// tick（≤1s）里合并处理，把事件风暴折叠成一次 refresh + 至多一条 RA。
    pending_refresh: bool = false,
    pending_ra_all: bool = false,
    packets_in: u64 = 0,
    packets_out: u64 = 0,

    pub fn init(allocator: Allocator) V6Runtime {
        var rt = V6Runtime{ .allocator = allocator };
        // 租约表必须清零 —— 里面是 undefined 内存，duid_len 当长度用
        @memset(&rt.leases, .{});
        return rt;
    }

    pub fn deinit(self: *V6Runtime) void {
        if (self.event_fd >= 0) net.close(self.event_fd);
        for (self.ifaces.items) |*i| {
            if (i.icmp_fd >= 0) net.close(i.icmp_fd);
            if (i.udp_fd >= 0) net.close(i.udp_fd);
            i.globals.deinit(self.allocator);
            i.old_prefixes.deinit(self.allocator);
        }
        self.ifaces.deinit(self.allocator);
    }

    // -----------------------------------------------------------------
    // 启动
    // -----------------------------------------------------------------

    /// 按 cfg.v6 的配置逐接口建 socket。任何一个接口失败只降级该接口，
    /// 不拖垮整个进程 —— 跟 v4 的 openSocket 策略一致。
    pub fn start(self: *V6Runtime, cfg_v6: []const v6conf.Iface6) void {
        var first_mac: ?[6]u8 = null;
        for (cfg_v6) |conf| {
            if (!conf.anyEnabled()) continue;
            const ifindex = net.ifaceIndex(conf.ifname) orelse {
                log.warning("v6 接口 {s}（设备 {s}）不存在，跳过", .{ conf.name, conf.ifname });
                continue;
            };
            var iface = V6Iface{
                .conf = conf,
                .ifindex = ifindex,
                .icmp_fd = -1,
                .udp_fd = -1,
            };
            iface.mac = readMacFromSys(conf.ifname) orelse iface.mac;
            if (first_mac == null) first_mac = iface.mac;
            _ = self.refreshIface(&iface);

            const icmp_ok = self.openIcmp(&iface);
            const udp_ok = if (iface.dhcp6Active()) self.openUdp(&iface) else true;
            if (!icmp_ok and !udp_ok) {
                log.warning("v6 接口 {s}：ICMPv6/UDP 547 都建立失败，该接口的 v6 服务不可用", .{conf.ifname});
                continue;
            }
            if (iface.raActive()) {
                // 启动即发一条 RA（odhcpd 也是接口 up 就发），手机不用等 600s
                iface.next_ra = util.dnsmasqTime();
            }
            self.ifaces.append(self.allocator, iface) catch {
                log.warning("v6 接口 {s}：内存不足，跳过", .{conf.ifname});
                continue;
            };
            log.notice("v6 接口 {s}：RA={s} DHCPv6={s} NDP={s}（{d} 个全局前缀）", .{
                conf.ifname,
                @tagName(conf.ra),
                @tagName(conf.dhcpv6),
                @tagName(conf.ndp),
                iface.globals.items.len,
            });
        }
        if (self.ifaces.items.len == 0) return;
        // 事件订阅要先于周期兜底：next_refresh 拉长到 60s，靠事件即时跟随
        self.event_fd = openEventSocket();
        self.next_refresh = util.dnsmasqTime() + REFRESH_SECS;
        if (first_mac) |mac| {
            self.duid_len = dhcpv6.duidLL(&self.server_duid, mac).len;
        }
        @memset(&self.leases, .{});
    }

    /// 从 netlink 拉一次本接口的 IPv6 地址，与现有状态做差分：
    ///   - 新出现的 /64 前缀 → 记录并触发立即 RA；
    ///   - 消失的 /64 前缀 → 进 old_prefixes（preferred=0 降级宣告）；
    ///   - 链路本地地址更新（接口重建会变）。
    /// 返回「前缀集合是否变化」。
    fn refreshIface(self: *V6Runtime, iface: *V6Iface) bool {
        var list: std.ArrayListUnmanaged(net.IfaceAddr) = .empty;
        defer list.deinit(self.allocator);
        net.listIfaceAddrs(self.allocator, &list) catch return false;

        var fresh: std.ArrayListUnmanaged(V6Iface.GlobalAddr) = .empty;
        defer fresh.deinit(self.allocator);
        var new_ll: ?[16]u8 = null;
        for (list.items) |ia| {
            if (ia.ifindex != iface.ifindex) continue;
            if (!ia.sa.isIp6()) continue;
            const in6: *const posix.sockaddr.in6 = @ptrCast(&ia.sa.store);
            const a = in6.addr;
            if (isLinkLocal(a)) {
                if (new_ll == null) new_ll = a;
                continue;
            }
            if (a[0] == 0xFF or a[0] == 0) continue; // 组播/未指定
            // br-lan 拿到的是 PD 下发的 **/60**（如 240e:x:x:26d0::1/60）——
            // SLAAC 只认 /64，odhcpd 也只宣告 /64。这里归一化成该前缀里的
            // 第一个 /64（路由器自己的 ::1 就在里面，on-link 天然成立）。
            // 比 /64 还长的（plen>64）对 SLAAC 无意义，跳过。
            if (ia.prefixlen > 64) continue;
            fresh.append(self.allocator, .{
                .a = maskPrefix(a, 64),
                .plen = 64,
                .self_addr = a,
                .preferred = ia.preferred,
                .valid = ia.valid,
            }) catch {};
        }

        var changed = false;
        // 消失的 /64 前缀 → 降级 PIO
        for (iface.globals.items) |g| {
            if (g.plen != 64) continue;
            if (!hasP64(fresh.items, g.a)) {
                iface.old_prefixes.append(self.allocator, .{
                    .prefix = maskPrefix(g.a, 64),
                    .valid = OLD_PIO_VALID,
                }) catch {};
                changed = true;
                log.notice("v6 {s}：前缀 {x} 已消失，以 preferred=0 降级宣告", .{ iface.conf.ifname, fmtPrefix(g.a) });
            }
        }
        // 新出现的 /64 前缀
        for (fresh.items) |g| {
            if (g.plen != 64) continue;
            if (!hasP64(iface.globals.items, g.a)) {
                changed = true;
                log.notice("v6 {s}：新前缀 {x} 出现，立即重发 RA", .{ iface.conf.ifname, fmtPrefix(g.a) });
            }
        }

        // 原子替换地址表
        iface.globals.clearRetainingCapacity();
        for (fresh.items) |g| iface.globals.append(self.allocator, g) catch {};
        if (new_ll) |ll| iface.link_local = ll;

        // 降级 PIO 倒计时
        var i: usize = 0;
        while (i < iface.old_prefixes.items.len) {
            iface.old_prefixes.items[i].valid -= REFRESH_SECS;
            if (iface.old_prefixes.items[i].valid <= 0) {
                _ = iface.old_prefixes.swapRemove(i);
                continue;
            }
            i += 1;
        }

        if (changed and iface.icmp_fd >= 0) _ = self.sendRA(iface);
        return changed;
    }

    // -----------------------------------------------------------------
    // netlink 事件（前缀/路由变化的**触发式**跟随）
    // -----------------------------------------------------------------

    // RTNLGRP_IPV6_IFADDR = 9 → 1<<8；RTNLGRP_IPV6_ROUTE = 11 → 1<<10
    const GRP_IPV6_IFADDR: u32 = 1 << 8;
    const GRP_IPV6_ROUTE: u32 = 1 << 10;

    /// 订阅 IPv6 地址与路由变化。失败只降级到 60s 兜底轮询，不影响服务。
    fn openEventSocket() posix.fd_t {
        const fd = net.socketCreate(posix.AF.NETLINK, posix.SOCK.RAW, 0) catch |e| {
            log.warning("v6：netlink 事件 socket 建立失败（{s}），退化为 60s 轮询", .{@errorName(e)});
            return -1;
        };
        var sa = system.sockaddr.nl{ .pid = 0, .groups = GRP_IPV6_IFADDR | GRP_IPV6_ROUTE };
        const rc = system.bind(fd, @ptrCast(&sa), @sizeOf(system.sockaddr.nl));
        if (net.errno(rc) != .SUCCESS) {
            log.warning("v6：netlink 事件 bind 失败，退化为 60s 轮询", .{});
            net.close(fd);
            return -1;
        }
        log.notice("v6：已订阅 netlink 地址/路由事件（前缀变化即时跟随）", .{});
        return fd;
    }

    /// 事件 socket 可读：排干内核推送，置标记（真正的活儿在 tick 里合并干）。
    fn drainEvents(self: *V6Runtime) void {
        var buf: [65536]u8 = undefined;
        const MSG_DONTWAIT: u32 = 0x40;
        while (true) {
            const n = net.recv(self.event_fd, &buf, MSG_DONTWAIT) catch |e| switch (e) {
                error.WouldBlock => return,
                else => {
                    log.warning("v6：netlink 事件读取失败: {s}", .{@errorName(e)});
                    return;
                },
            };
            if (n == 0) return;
            var off: usize = 0;
            while (off + 16 <= n) {
                const mlen: usize = std.mem.readInt(u32, buf[off..][0..4], .little);
                if (mlen < 16 or off + mlen > n) break;
                const mtype = std.mem.readInt(u16, buf[off + 4 ..][0..2], .little);
                switch (parseNetlinkEvent(buf[off..][0..mlen], mtype)) {
                    .ifaddr6 => self.pending_refresh = true,
                    .default_route6 => self.pending_ra_all = true,
                    .ignore => {},
                }
                off += (mlen + 3) & ~@as(usize, 3);
            }
        }
    }

    fn openIcmp(self: *V6Runtime, iface: *V6Iface) bool {
        const fd = net.socketCreate(posix.AF.INET6, posix.SOCK.RAW, @intCast(IPPROTO_ICMPV6)) catch |e| {
            log.warning("v6 {s}：raw ICMPv6 socket 失败: {s}", .{ iface.conf.ifname, @errorName(e) });
            return false;
        };
        // 收包要知道「从哪个接口进来的」→ 回包定 scope_id 用（per-fd 场景
        // 其实可以省，但保留与 odhcpd 一致，也为将来 relay 合 socket 做准备）
        setV6Int(fd, system.IPV6.RECVPKTINFO, 1) catch {};
        // RA/NA 的 hoplimit 必须是 255（RFC 4861 要求，内核会校验收包方向）
        setV6Int(fd, system.IPV6.UNICAST_HOPS, 255) catch {};
        setV6Int(fd, system.IPV6.MULTICAST_HOPS, 255) catch {};
        // 不吃自己发的组播（第二个防自环手段；第一个是过滤器挡 134）
        setV6Int(fd, system.IPV6.MULTICAST_LOOP, 0) catch {};
        // 只放行 RS/NS/NA —— 绝不放行 134(RA)，否则会处理自己发的 RA
        const filter = icmp6FilterPassOnly(&.{ router.ICMPV6_RS, router.ICMPV6_NS, router.ICMPV6_NA });
        setsockoptRaw(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filter) catch |e| {
            log.warning("v6 {s}：ICMP6_FILTER 失败: {s}", .{ iface.conf.ifname, @errorName(e) });
        };
        bindToDevice(fd, iface.conf.ifname);
        var sa = net.anyAddr(.ip6, 0);
        net.bind(fd, &sa) catch |e| {
            log.warning("v6 {s}：bind(::) 失败: {s}", .{ iface.conf.ifname, @errorName(e) });
            net.close(fd);
            return false;
        };
        // 加入 ff02::2（收 RS）—— ff02::1 的组播 NA 目标不经过它也能收到
        // 单播/被请求节点组播；NDP 代理需要的被请求节点组播在分配时逐地址加入。
        self.join(fd, router.AllRouters, iface.ifindex) catch |e| {
            log.warning("v6 {s}：加入 ff02::2 失败: {s}（收不到 RS）", .{ iface.conf.ifname, @errorName(e) });
        };
        iface.icmp_fd = fd;
        return true;
    }

    fn openUdp(self: *V6Runtime, iface: *V6Iface) bool {
        const fd = net.socketCreate(posix.AF.INET6, posix.SOCK.DGRAM, posix.IPPROTO.UDP) catch |e| {
            log.warning("v6 {s}：UDPv6 socket 失败: {s}", .{ iface.conf.ifname, @errorName(e) });
            return false;
        };
        net.setReuseAddr(fd) catch {};
        setV6Int(fd, system.IPV6.MULTICAST_HOPS, 255) catch {};
        setV6Int(fd, system.IPV6.MULTICAST_LOOP, 0) catch {};
        bindToDevice(fd, iface.conf.ifname);
        var sa = net.anyAddr(.ip6, dhcpv6.SERVER_PORT);
        net.bind(fd, &sa) catch |e| {
            log.warning("v6 {s}：bind(547) 失败: {s}（端口被占？）", .{ iface.conf.ifname, @errorName(e) });
            net.close(fd);
            return false;
        };
        self.join(fd, AllDhcpServers, iface.ifindex) catch |e| {
            log.warning("v6 {s}：加入 ff02::1:2 失败: {s}", .{ iface.conf.ifname, @errorName(e) });
        };
        iface.udp_fd = fd;
        return true;
    }

    // ff02::1:2 —— 同样必须带 FF02 前缀（曾因丢前缀被内核 EINVAL）
    const AllDhcpServers: [16]u8 = .{ 0xFF, 2 } ++ [_]u8{0} ** 10 ++ .{ 0, 1, 0, 2 };

    fn join(_: *V6Runtime, fd: posix.fd_t, group: [16]u8, ifindex: u32) !void {
        const mreq = std.mem.toBytes(Ipv6Mreq{ .multiaddr = group, .ifindex = ifindex });
        const rc = system.setsockopt(fd, posix.IPPROTO.IPV6, system.IPV6.ADD_MEMBERSHIP, &mreq, mreq.len);
        const e = net.errno(rc);
        if (e != .SUCCESS) {
            log.warning("join errno={s}({d}) ifindex={d}", .{ @tagName(e), @intFromEnum(e), ifindex });
            return error.JoinFailed;
        }
    }

    /// 给分配出去的地址加被请求节点组播 —— 别的客户端 NS 它时我们才能
    /// 代理应答（内核不知道这个地址的存在）。
    fn joinSolicited(self: *V6Runtime, fd: posix.fd_t, a: *const [16]u8, ifindex: u32) void {
        var group = SOLICITED_NODE_PREFIX;
        group[13] = a[13];
        group[14] = a[14];
        group[15] = a[15];
        self.join(fd, group, ifindex) catch {};
    }

    // -----------------------------------------------------------------
    // poll 集成
    // -----------------------------------------------------------------

    /// 把 v6 的 fd 填进 poll 数组（返回填了多少个）。event_fd 在最前，
    /// dispatch 按同样顺序对账。
    pub fn fillFds(self: *V6Runtime, out: []posix.pollfd) usize {
        var n: usize = 0;
        if (self.event_fd >= 0 and n < out.len) {
            out[n] = .{ .fd = self.event_fd, .events = posix.POLL.IN, .revents = 0 };
            n += 1;
        }
        for (self.ifaces.items) |*i| {
            if (i.icmp_fd >= 0 and n < out.len) {
                out[n] = .{ .fd = i.icmp_fd, .events = posix.POLL.IN, .revents = 0 };
                n += 1;
            }
            if (i.udp_fd >= 0 and n < out.len) {
                out[n] = .{ .fd = i.udp_fd, .events = posix.POLL.IN, .revents = 0 };
                n += 1;
            }
        }
        return n;
    }

    /// 事件到达时按 fd 分发。idx 相对 fillFds 的输出。
    pub fn dispatch(self: *V6Runtime, fds: []const posix.pollfd) void {
        var idx: usize = 0;
        if (self.event_fd >= 0 and idx < fds.len) {
            if ((fds[idx].revents & posix.POLL.IN) != 0) self.drainEvents();
            idx += 1;
        }
        for (self.ifaces.items) |*i| {
            if (i.icmp_fd >= 0 and idx < fds.len) {
                if ((fds[idx].revents & posix.POLL.IN) != 0) self.handleIcmp(i);
                idx += 1;
            }
            if (i.udp_fd >= 0 and idx < fds.len) {
                if ((fds[idx].revents & posix.POLL.IN) != 0) self.handleDhcp6(i);
                idx += 1;
            }
        }
    }

    /// 每秒被调：处理 netlink 事件标记（≤1s 延迟）、到点兜底重拉、
    /// 发周期 RA、清过期的 v6 租约。
    pub fn tick(self: *V6Runtime) void {
        const now = util.dnsmasqTime();
        if (self.pending_refresh) {
            self.pending_refresh = false;
            // 降为 debug：地址事件在开机/前缀续期时会密集出现（实测每 1-2 秒一条），
            // 默认级别（info）下不再刷屏；排查前缀问题时把 log.level 调到 debug 即可看到。
            log.debug("v6：netlink 地址事件，刷新接口前缀", .{});
            for (self.ifaces.items) |*i| _ = self.refreshIface(i);
        }
        if (self.pending_ra_all) {
            // ::/0 路由增删：RA lifetime 要跟着变，全部立即重发
            self.pending_ra_all = false;
            log.notice("v6：netlink 默认路由事件，重发 RA", .{});
            for (self.ifaces.items) |*i| {
                if (i.raActive()) _ = self.sendRA(i);
            }
        }
        if (now >= self.next_refresh) {
            self.next_refresh = now + REFRESH_SECS;
            for (self.ifaces.items) |*i| _ = self.refreshIface(i);
        }
        for (self.ifaces.items) |*i| {
            if (!i.raActive()) continue;
            if (i.next_ra != 0 and now >= i.next_ra) {
                _ = self.sendRA(i);
                i.next_ra = now + @as(i64, @intCast(i.conf.ra_maxinterval));
            }
        }
        // 租约过期清理（确定性哈希分配意味着过期重查会得到同一个地址，
        // 所以这里清不清都不影响正确性，只是省内存）
        for (self.leases[0..MAX_V6_LEASES]) |*l| {
            if (l.duid_len != 0 and l.valid_until < now) l.duid_len = 0; // 标记为空槽
        }
    }

    // -----------------------------------------------------------------
    // RA
    // -----------------------------------------------------------------

    /// 组装并发送一条 RA。返回是否发出去了。
    pub fn sendRA(self: *V6Runtime, iface: *V6Iface) bool {
        var pio_buf: [12]router.Pio = undefined;
        var pios: []router.Pio = pio_buf[0..0];
        for (iface.globals.items) |g| {
            if (pios.len == pio_buf.len) break;
            if (g.plen != 64) continue; // SLAAC 只对 /64 成立
            if (isLinkLocal(g.a)) continue;
            pio_buf[pios.len] = .{
                .prefix = maskPrefix(g.a, 64),
                .len = 64,
                .valid = iface.conf.max_valid_lifetime,
                .preferred = iface.conf.max_preferred_lifetime,
            };
            pios.len += 1;
        }
        // 消失的旧前缀：preferred=0（地址马上停用），valid 走倒计时，
        // 客户端据此把旧 SLAAC 地址标为 deprecated 并逐步移除。
        for (iface.old_prefixes.items) |op| {
            if (pios.len == pio_buf.len) break;
            pio_buf[pios.len] = .{
                .prefix = op.prefix,
                .len = 64,
                .valid = @intCast(@max(op.valid, 60)),
                .preferred = 0,
            };
            pios.len += 1;
        }

        // DNS：接口没配 list dns 就通告「本接口自己的可路由地址」。
        //
        // 严格对照 odhcpd `odhcpd.c:362-405 odhcpd_get_interface_dns_addr6()`：
        // 它在**全部**已配置地址里挑，**链路本地只是最后兜底**，规则顺序是
        //   1) valid_lt <= now 的丢掉（已失效）
        //   2) 已选地址 preferred 还有效、而候选的 preferred 已过期 → 候选让位
        //   3) ULA 优先（候选是 ULA 而已选不是 → 换；已选是 ULA 而候选不是 → 跳过）
        //   4) 同条件下取 preferred_lt 最长的
        //   5) 一条都挑不出（m<0）才回退链路本地
        //
        // 时间语义按内核实际行为处理（剩余秒数），理由见 pickRdnsAddr 注释。
        //
        // 早先这里直接取 link_local，跳过了 1~4。后果：br-lan 明明有全局地址
        // `240e:...:26d0::1`，RA 却通告 `fe80::...` —— 与 odhcpd 不一致，
        // 且链路本地在客户端侧需要 scope、部分实现支持不佳。
        var dns_buf: [4][16]u8 = undefined;
        var dns: []const [16]u8 = iface.conf.dns;
        if (dns.len == 0) {
            if (pickRdnsAddr(iface.globals.items)) |pick| {
                dns_buf[0] = pick;
                dns = dns_buf[0..1];
            } else if (!isAny(&iface.link_local)) {
                dns_buf[0] = iface.link_local;
                dns = dns_buf[0..1];
            }
        }

        const mtu: u32 = if (iface.conf.ra_mtu != 0) iface.conf.ra_mtu else readSysMtu(iface.conf.ifname) orelse 0;

        var out: [1280]u8 = undefined;
                // 默认路由宣告（严格对照 odhcpd router.c:701-717 / 878-886）：
        //   default_route = UCI ra_default > 0 **或** 系统（/proc/net/ipv6_route）
        //   存在非 lo 的 IPv6 默认路由 —— 上游 odhcpd 在 ra_default=0 时也会
        //   自动检测，这里必须照抄，否则客户端拿不到 IPv6 默认路由；
        //   valid_prefix = 有可宣告的 PIO，或 ra_default > 1 强制。
        //   两者同时成立才宣告 lifetime，否则 0。
        const default_route = iface.conf.ra_default > 0 or hasDefaultRoute();
        const valid_prefix = pios.len > 0 or iface.conf.ra_default > 1;
        const rl: u32 = if (default_route and valid_prefix) calcRaLifetime(iface) else blk: {
            if (default_route and !valid_prefix)
                log.warning("v6 {s}：有默认路由但无公网前缀，router lifetime 置 0", .{iface.conf.ifname});
            break :blk 0;
        };
        const n = router.buildRA(&out, &iface.conf, pios, dns, iface.conf.dns_search, iface.mac, mtu, rl);
        if (n == 0) return false;
        // RA 发往 ff02::1（所有节点）。
        // 用 sendmsg + IPV6_PKTINFO 指定出口接口（对齐上游 odhcpd_send_with_src），
        // 并且失败时带 errno 名 —— 早先 @errorName 的 else 兜底把
        // ENETUNREACH/EADDRNOTAVAIL（br-lan 还在 STP listening、IPv6 栈未就绪）
        // 全归成一句「Unexpected」，排障时根本看不出根因。
        var dst = addr.SockAddr.fromIp6(router.AllNodes, 0, iface.ifindex);
        const sent = net.sendMsg6(iface.icmp_fd, &dst, out[0..n], iface.ifindex);
        switch (sent) {
            .sent => {},
            .failed => |err| {
                log.warning("v6 {s}：RA 发送失败: {s}（{d} 字节未送出）", .{ iface.conf.ifname, err, n });
                return false;
            },
        }
        if (sent.sent == 0) {
            log.warning("v6 {s}：RA 发送返回 0", .{iface.conf.ifname});
            return false;
        }
        self.packets_out += 1;
        log.debug("v6 {s}：RA 已发（{d} PIO，{d} RDNSS）", .{ iface.conf.ifname, pios.len, dns.len });
        return true;
    }

    // -----------------------------------------------------------------
    // ICMPv6 收包
    // -----------------------------------------------------------------

    fn handleIcmp(self: *V6Runtime, iface: *V6Iface) void {
        var buf: [1500]u8 = undefined;
        var from = addr.SockAddr{};
        const n = net.recvfrom(iface.icmp_fd, &buf, &from, 0) catch return;
        if (n < 8) return;
        const ty = buf[0];
        if (!from.isIp6()) return;
        const src = (in6Of(&from)).addr;
        // 自环保护：raw socket 收到自己发的包（NA 也可能自环），直接丢
        if (std.mem.eql(u8, &src, &iface.link_local)) return;

        switch (ty) {
            router.ICMPV6_RS => {
                // RFC 4861：RS 只处理 hoplimit==255 的（防跨网段伪造），内核
                // 已经替我们过滤了 hoplimit，这里不再重复。
                _ = self.sendRA(iface);
            },
            router.ICMPV6_NS => {
                if (n < 24) return;
                const target = buf[8..24][0..16].*;
                // 自己的地址内核会答；我们只代理「分配出去的客户端地址」
                if (self.findLeaseByAddr(&target)) |l| {
                    _ = l;
                    var out: [80]u8 = undefined;
                    const on = router.buildNA(&out, target, iface.mac, true);
                    var dst = addr.SockAddr.fromIp6(src, 0, iface.ifindex);
                    _ = net.sendto(iface.icmp_fd, out[0..on], &dst, 0) catch 0;
                    self.packets_out += 1;
                }
            },
            else => {},
        }
    }

    // -----------------------------------------------------------------
    // DHCPv6
    // -----------------------------------------------------------------

    fn handleDhcp6(self: *V6Runtime, iface: *V6Iface) void {
        var buf: [1500]u8 = undefined;
        var from = addr.SockAddr{};
        const n = net.recvfrom(iface.udp_fd, &buf, &from, 0) catch return;
        if (!from.isIp6()) return;
        const src = (in6Of(&from)).addr;
        if (std.mem.eql(u8, &src, &iface.link_local)) return; // 自环
        if (n < 4) return;
        self.packets_in += 1;

        var opts: [64]dhcpv6.RawOpt = undefined;
        const msg = dhcpv6.parse(buf[0..n], &opts) catch return;
        const client_id = msg.find(dhcpv6.Opt.client_id) orelse return;
        if (client_id.len == 0 or client_id.len > 32) return;

        // server_id 校验：SOLICIT/INFORMATION-REQUEST 可以没有；REQUEST 等
        // 必须指名道姓是我们，否则忽略（RFC 8415 §16）
        if (msg.find(dhcpv6.Opt.server_id)) |sid| {
            if (!std.mem.eql(u8, sid, self.server_duid[0..self.duid_len])) return;
        } else {
            switch (msg.msg_type) {
                .solicit, .info_request => {},
                else => return,
            }
        }

        switch (msg.msg_type) {
            .solicit, .request, .renew, .rebind, .info_request => {},
            .release, .decline => {
                // 确定性分配下没有可释放的状态，礼貌性 REPLY success
                self.replySimple(iface, &src, msg.tid, client_id);
                return;
            },
            else => return,
        }

        // IA_NA：只处理第一个。地址 = DUID+IAID 的确定性哈希 → /64 内接口 ID。
        var assigned: ?[16]u8 = null;
        var iaid: u32 = 0;
        if (msg.msg_type != .info_request) {
            if (msg.find(dhcpv6.Opt.ia_na)) |ia_data| {
                if (dhcpv6.parseIaNa(ia_data)) |ia| {
                    iaid = ia.iaid;
                    assigned = self.assign(iface, client_id, ia.iaid);
                }
            }
            // IA_PD 暂不支持：不做处理（客户端会重试，最终退回 SLAAC）
        }

        // DNS 缺省通告自己（同 RA 的规则）；INFORMATION-REQUEST 就是为这个来的
        var dns_buf: [4][16]u8 = undefined;
        var dns: []const [16]u8 = iface.conf.dns;
        if (dns.len == 0 and !isAny(&iface.link_local)) {
            dns_buf[0] = iface.link_local;
            dns = dns_buf[0..1];
        }

        const reply_type: dhcpv6.MsgType = blk: {
            if (msg.msg_type == .solicit and !msg.hasRapidCommit()) break :blk .advertise;
            break :blk .reply;
        };

        var out: [1500]u8 = undefined;
        const rn = buildReply(&out, reply_type, msg.tid, client_id, self.server_duid[0..self.duid_len], assigned, iaid, msg.hasRapidCommit(), dns, iface.conf.dns_search);
        if (rn == 0) return;
        // 应答目的：客户端链路本地地址 :546，scope_id 定接口
        var dst = addr.SockAddr.fromIp6(src, dhcpv6.CLIENT_PORT, iface.ifindex);
        const sent = net.sendto(iface.udp_fd, out[0..rn], &dst, 0) catch 0;
        if (sent > 0) self.packets_out += 1;
        log.debug("v6 {s}：{s} -> {s}", .{ iface.conf.ifname, @tagName(reply_type), @tagName(msg.msg_type) });
    }

    fn replySimple(self: *V6Runtime, iface: *V6Iface, src: *const [16]u8, tid: [3]u8, client_id: []const u8) void {
        var out: [512]u8 = undefined;
        const rn = buildReply(&out, .reply, tid, client_id, self.server_duid[0..self.duid_len], null, 0, false, &.{}, &.{});
        if (rn == 0) return;
        var dst = addr.SockAddr.fromIp6(src.*, dhcpv6.CLIENT_PORT, iface.ifindex);
        _ = net.sendto(iface.udp_fd, out[0..rn], &dst, 0) catch 0;
    }

    /// 查表 / 分配地址。确定性：同一 (DUID, IAID) 永远同一地址。
    fn assign(self: *V6Runtime, iface: *V6Iface, client_duid: []const u8, iaid: u32) ?[16]u8 {
        // 找一个可作为分配池的全局 /64 前缀
        var prefix: ?[16]u8 = null;
        for (iface.globals.items) |g| {
            if (g.plen == 64) {
                prefix = maskPrefix(g.a, 64);
                break;
            }
        }
        const p = prefix orelse return null;

        const now = util.dnsmasqTime();
        // 查已有
        var empty_slot: ?usize = null;
        for (self.leases[0..MAX_V6_LEASES], 0..) |*l, i| {
            if (l.duid_len == 0) {
                if (empty_slot == null) empty_slot = i;
                continue;
            }
            if (l.iaid == iaid and l.duid_len == client_duid.len and
                std.mem.eql(u8, l.duid[0..l.duid_len], client_duid))
            {
                // 前缀变了（PD 重下发）：主机部分保持不变，整体搬到新前缀。
                // 客户端在 renew 时拿到新地址，旧前缀那边 RA 已经在降级。
                if (!std.mem.eql(u8, l.addr[0..8], p[0..8])) {
                    var na = p;
                    @memcpy(na[8..16], l.addr[8..16]);
                    l.addr = na;
                    if (iface.icmp_fd >= 0) self.joinSolicited(iface.icmp_fd, &na, iface.ifindex);
                }
                l.valid_until = now + IA_VALID;
                self.dirty = true; // 续约也刷新状态文件里的到期时间
                return l.addr;
            }
        }

        // 新分配
        const slot = empty_slot orelse blk: {
            if (self.lease_count < MAX_V6_LEASES) {
                self.lease_count += 1;
                break :blk self.lease_count - 1;
            }
            return null; // 表满：至少 RDNSS/RA 还能工作
        };
        const l = &self.leases[slot];
        var addr_out = p;
        // 接口 ID = Wyhash(DUID ++ IAID)，并清掉 U/L 位与组播位，
        // 避开 EUI-64 SLAAC 地址（它们 U/L 位是 1）的碰撞空间
        var h = std.hash.Wyhash.init(0);
        h.update(client_duid);
        h.update(std.mem.asBytes(&iaid));
        const digest = h.final();
        std.mem.writeInt(u64, addr_out[8..16], digest, .big);
        addr_out[8] &= ~@as(u8, 0x03);
        if (addr_out[8] == 0 and addr_out[9] == 0) addr_out[8] = 0x42; // 别撞上保留段

        @memcpy(l.duid[0..client_duid.len], client_duid);
        l.duid_len = @intCast(client_duid.len);
        l.iaid = iaid;
        l.addr = addr_out;
        l.valid_until = now + IA_VALID;
        if (iface.icmp_fd >= 0) self.joinSolicited(iface.icmp_fd, &addr_out, iface.ifindex);
        self.dirty = true; // 触发状态文件重写（LuCI 的 DHCPv6 租约页读它）
        return addr_out;
    }

    fn findLeaseByAddr(self: *V6Runtime, target: *const [16]u8) ?*Lease6 {
        for (self.leases[0..MAX_V6_LEASES]) |*l| {
            if (l.duid_len != 0 and std.mem.eql(u8, &l.addr, target)) return l;
        }
        return null;
    }
    /// 把 v6 分配记录按 odhcpd statefiles.c:539 的格式追加到状态文件缓冲：
    /// `# <iface> <hexduid> <hexiaid> <hostname|-> <valid_until> <hex_hostid> 128 <addr>/128`
    /// LuCI 的「已分配的 DHCPv6 租约」页（luci-rpc getDHCPLeases）解析这个文件。
    /// 注意：只有 IA_NA 分配才算租约 —— SLAAC（other-config 模式）不产生记录，
    /// 这与原版 odhcpd 行为一致。
    pub fn appendStateLines(
        self: *V6Runtime,
        out: *std.ArrayListUnmanaged(u8),
        allocator: Allocator,
        ifname: []const u8,
        now: i64,
    ) void {
        for (self.leases[0..MAX_V6_LEASES]) |*l| {
            if (l.duid_len == 0) continue;
            if (l.valid_until <= now) continue;
            var line: [512]u8 = undefined;
            var n: usize = 0;
            n += (std.fmt.bufPrint(line[n..], "# {s} ", .{ifname}) catch break).len;
            for (l.duid[0..l.duid_len]) |b| {
                n += (std.fmt.bufPrint(line[n..], "{x:0>2}", .{b}) catch break).len;
            }
            n += (std.fmt.bufPrint(line[n..], " {x} - {d} {x} 128 ", .{ l.iaid, l.valid_until, std.mem.readInt(u64, l.addr[8..16], .big) }) catch break).len;
            var ab: [64]u8 = undefined;
            const at = addr.writeIp6(&ab, &l.addr);
            n += (std.fmt.bufPrint(line[n..], "{s}/128\n", .{at}) catch break).len;
            out.appendSlice(allocator, line[0..n]) catch {};
        }
    }
};

// ---------------------------------------------------------------------------
// DHCPv6 应答构造（纯函数，便于单测）
// ---------------------------------------------------------------------------

/// 构造 ADVERTISE / REPLY。`assigned == null` 时不带 IA_NA。
/// DNS / 域名按「配了就带」的原则附加（用户 2026-09-20 规则：缺省通告自己，
/// 这个替换在调用方已完成）。
pub fn buildReply(
    out: []u8,
    mt: dhcpv6.MsgType,
    tid: [3]u8,
    client_id: []const u8,
    server_duid: []const u8,
    assigned: ?[16]u8,
    iaid: u32,
    rapid_commit: bool,
    dns: []const [16]u8,
    domains: []const []const u8,
) usize {
    var off: usize = 0;
    if (out.len < 8) return 0;
    dhcpv6.appendHeader(out, &off, mt, tid);
    dhcpv6.appendOpt(out, &off, dhcpv6.Opt.client_id, client_id);
    dhcpv6.appendOpt(out, &off, dhcpv6.Opt.server_id, server_duid);
    if (rapid_commit) dhcpv6.appendOpt(out, &off, dhcpv6.Opt.rapid_commit, "");

    if (assigned) |a| {
        // IA_NA = iaid(4) + T1(4) + T2(4) + IAADDR(24)
        var ia: [12]u8 = undefined;
        std.mem.writeInt(u32, ia[0..4], iaid, .big);
        std.mem.writeInt(u32, ia[4..8], IA_T1, .big);
        std.mem.writeInt(u32, ia[8..12], IA_T2, .big);
        var body: [12 + 24]u8 = ia ++ [_]u8{0} ** 24;
        const addr_bytes = dhcpv6.iaAddrBytes(a, IA_PREFERRED, IA_VALID);
        @memcpy(body[12..][0..24], &addr_bytes);
        dhcpv6.appendOpt(out, &off, dhcpv6.Opt.ia_na, &body);
    }

    if (dns.len > 0) {
        var payload: [4 * 16]u8 = undefined;
        for (dns, 0..) |d, i| {
            if (i * 16 >= payload.len) break;
            @memcpy(payload[i * 16 ..][0..16], &d);
        }
        dhcpv6.appendOpt(out, &off, dhcpv6.Opt.dns_servers, payload[0 .. dns.len * 16]);
    }
    if (domains.len > 0) {
        var names: [512]u8 = undefined;
        const nl = dhcpv6.encodeDomainList(&names, domains);
        if (nl.len > 0) dhcpv6.appendOpt(out, &off, dhcpv6.Opt.domain_search, nl);
    }
    return off;
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// netlink 事件解析（纯函数，便于单测）
// ---------------------------------------------------------------------------

pub const NetEvent = union(enum) {
    /// IPv6 地址增删（RTM_NEWADDR/RTM_DELADDR，family=AF_INET6）
    ifaddr6: struct { ifindex: u32 },
    /// IPv6 默认路由（dst_len=0）增删（RTM_NEWROUTE/RTM_DELROUTE）
    default_route6: struct { added: bool },
    ignore,
};

const NL_RTM_NEWADDR: u16 = 20;
const NL_RTM_DELADDR: u16 = 21;
const NL_RTM_NEWROUTE: u16 = 24;
const NL_RTM_DELROUTE: u16 = 25;
const NL_AF_INET6: u8 = 10;

/// 解析单条 netlink 消息。nlmsg 是 host 字节序（小端）。
pub fn parseNetlinkEvent(msg: []const u8, mtype: u16) NetEvent {
    if (msg.len < 16) return .ignore;
    switch (mtype) {
        NL_RTM_NEWADDR, NL_RTM_DELADDR => {
            // nlmsghdr(16) + ifaddrmsg：family(1) prefixlen(1) flags(1) scope(1) ifindex(4)
            if (msg.len < 24) return .ignore;
            if (msg[16] != NL_AF_INET6) return .ignore;
            const ifindex = std.mem.readInt(u32, msg[20..24], .little);
            return .{ .ifaddr6 = .{ .ifindex = ifindex } };
        },
        NL_RTM_NEWROUTE, NL_RTM_DELROUTE => {
            // nlmsghdr(16) + rtmsg：family(1) dst_len(1) src_len(1) tos(1)
            //   table(1) proto(1) scope(1) type(1) flags(4)
            if (msg.len < 28) return .ignore;
            if (msg[16] != NL_AF_INET6) return .ignore;
            if (msg[17] != 0) return .ignore; // dst_len=0 才是 ::/0
            return .{ .default_route6 = .{ .added = mtype == NL_RTM_NEWROUTE } };
        },
        else => return .ignore,
    }
}

fn setV6Int(fd: posix.fd_t, name: u32, value: c_int) !void {
    const bytes = std.mem.toBytes(value);
    const rc = system.setsockopt(fd, posix.IPPROTO.IPV6, name, &bytes, @sizeOf(c_int));
    if (net.errno(rc) != .SUCCESS) return error.SockOptFailed;
}

fn setsockoptRaw(fd: posix.fd_t, level: i32, name: u32, data: []const u8) !void {
    const rc = system.setsockopt(fd, level, name, data.ptr, @intCast(data.len));
    if (net.errno(rc) != .SUCCESS) return error.SockOptFailed;
}

fn bindToDevice(fd: posix.fd_t, ifname: []const u8) void {
    const rc = system.setsockopt(fd, posix.SOL.SOCKET, posix.SO.BINDTODEVICE, ifname.ptr, @intCast(ifname.len));
    if (net.errno(rc) != .SUCCESS) {
        log.warning("v6：SO_BINDTODEVICE({s}) 失败，将监听所有网卡", .{ifname});
    }
}

fn in6Of(sa: *const addr.SockAddr) *const posix.sockaddr.in6 {
    return @ptrCast(&sa.store);
}

/// /proc/net/ipv6_route 里是否存在**非 lo 设备**的 IPv6 默认路由。
/// 对照 odhcpd router.c:310 parse_routes —— 每行开头是「目的地址(32hex) 目的
/// 前缀长(2hex)」，::/0 即 "00000000000000000000000000000000 00"；行尾最后
/// 一个字段是出接口名。
pub fn hasDefaultRoute() bool {
    const fd = posix.openat(posix.AT.FDCWD, "/proc/net/ipv6_route", .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0) catch return false;
    defer net.close(fd);
    var buf: [8192]u8 = undefined;
    var rest: []const u8 = buf[0..0];
    var carry: [512]u8 = undefined;
    var carry_len: usize = 0;
    while (true) {
        const n = posix.read(fd, &buf) catch return false;
        if (n == 0) break;
        const data = buf[0..n];
        // 简单按行扫（行可能跨 read 边界，用 carry 缓存）
        var chunk: [1024 + 512]u8 = undefined;
        if (carry_len > 0) {
            @memcpy(chunk[0..carry_len], carry[0..carry_len]);
            @memcpy(chunk[carry_len .. carry_len + n], data);
            rest = chunk[0 .. carry_len + n];
        } else {
            rest = data;
        }
        carry_len = 0;
        while (rest.len > 0) {
            const nl = std.mem.indexOfScalar(u8, rest, '\n') orelse {
                // 半行：缓存起来
                const take = @min(rest.len, carry.len);
                @memcpy(carry[0..take], rest[rest.len - take ..]);
                carry_len = take;
                break;
            };
            const line = rest[0..nl];
            rest = rest[nl + 1 ..];
            if (checkDefaultRouteLine(line)) return true;
        }
        if (n < buf.len) break;
    }
    if (carry_len > 0 and checkDefaultRouteLine(carry[0..carry_len])) return true;
    return false;
}

fn checkDefaultRouteLine(line0: []const u8) bool {
    const line = std.mem.trim(u8, line0, " \r");
    const DEFAULT_HEAD = "00000000000000000000000000000000 00";
    if (!std.mem.startsWith(u8, line, DEFAULT_HEAD)) return false;
    // 行尾最后一个字段是设备名
    const sp = std.mem.lastIndexOfScalar(u8, line, ' ') orelse return false;
    const dev = std.mem.trim(u8, line[sp + 1 ..], " \r");
    return !std.mem.eql(u8, dev, "lo");
}

const ROUTER_LIFETIME_MAX: u32 = 5400; // odhcpd router.h: #define RouterLifetime 5400

/// 对照 odhcpd router.c:377 calc_ra_lifetime
fn calcRaLifetime(iface: *const V6Iface) u32 {
    var lifetime: u32 = iface.conf.max_preferred_lifetime;
    if (iface.conf.ra_lifetime > 0) lifetime = iface.conf.ra_lifetime;
    const maxival: u32 = @max(iface.conf.ra_maxinterval, 1);
    if (lifetime > 0 and lifetime < maxival) lifetime = maxival;
    if (lifetime > ROUTER_LIFETIME_MAX) lifetime = ROUTER_LIFETIME_MAX;
    return lifetime;
}

pub fn isLinkLocal(a: [16]u8) bool {
    return a[0] == 0xFE and (a[1] & 0xC0) == 0x80;
}

/// `IN6_IS_ADDR_ULA` —— fc00::/7。odhcpd 在 RDNSS 优选里给 ULA 更高优先级。
pub fn isUla(a: [16]u8) bool {
    return (a[0] & 0xFE) == 0xFC;
}

/// RDNSS 的地址优选，对照 odhcpd
/// `odhcpd.c:362-405 odhcpd_get_interface_dns_addr6()` 的**判定顺序**。
///
/// 与上游的唯一实质差别在「时间语义」：上游把 `preferred_lt`/`valid_lt`
/// 当作**绝对墙钟秒**与 `now` 比较（`valid_lt <= now` 即视为失效），
/// 但 .1 实测表明内核（OpenWrt 6.x / Linux 6.x）的 `IFA_CACHEINFO`
/// 回传的是**剩余秒数** —— 拿到的 `valid=176456` 与
/// `ip -6 addr` 的 `valid_lft 176447sec` 同步递减，同一量纲。
/// 若照抄上游的 `<= now`，任何正常地址都会被判成「早已过期」而全部丢弃，
/// 结果永远回退链路本地（这正是补齐前线上 RA 通告 fe80:: 的原因）。
///
/// 因此这里按真实语义比较：剩余秒数 > 0 即为有效，`0xFFFFFFFF`（forever）
/// 天然满足。判定顺序仍与上游逐条对齐。
///
/// 返回 null 表示「一条都挑不出」，调用方应回退链路本地。
pub fn pickRdnsAddr(addrs: []const V6Iface.GlobalAddr) ?[16]u8 {
    var m: ?usize = null;

    for (addrs, 0..) |cur, i| {
        if (cur.valid == 0) continue; // 剩余有效期为 0 → 已失效

        const best = m orelse {
            m = i;
            continue;
        };

        // 已选的 preferred 还有效、而候选已过期 → 候选让位
        if (addrs[best].preferred > 0 and cur.preferred == 0) continue;

        // ULA 优先
        if (isUla(cur.self_addr)) {
            if (!isUla(addrs[best].self_addr)) {
                m = i;
                continue;
            }
        } else if (isUla(addrs[best].self_addr)) continue;

        // 同条件下取 preferred 更长
        if (cur.preferred > addrs[best].preferred) m = i;
    }

    const idx = m orelse return null;
    if (isAny(&addrs[idx].self_addr)) return null;
    return addrs[idx].self_addr;
}

/// 地址 a 是否落在某个 /64 前缀集合里（比较前 8 字节）。
fn hasP64(list: []const V6Iface.GlobalAddr, a: [16]u8) bool {
    for (list) |g| {
        if (g.plen == 64 and std.mem.eql(u8, g.a[0..8], a[0..8])) return true;
    }
    return false;
}

/// 日志用：把前 8 字节打成 16 个 hex（/64 前缀）
fn fmtPrefix(a: [16]u8) u64 {
    return std.mem.readInt(u64, a[0..8], .big);
}

fn isAny(a: *const [16]u8) bool {
    for (a) |b| if (b != 0) return false;
    return true;
}

/// 取前缀部分（主机位清零），用于 PIO 与分配池。
pub fn maskPrefix(a: [16]u8, plen: u8) [16]u8 {
    var out = a;
    const full = plen / 8;
    if (full < 16) {
        @memset(out[full..], 0);
        const rem = plen % 8;
        if (rem > 0) out[full] &= @as(u8, 0xFF) << @intCast(8 - rem);
    }
    return out;
}

/// 读 /sys/class/net/<name>/address。odhcpd applet 不在 ujail 里（它的 init
/// 没有 procd_add_jail），/sys 可用；DNS 那条 ujail 线的教训不适用于这里。
pub fn readMacFromSys(ifname: []const u8) ?[6]u8 {
    var pathbuf: [128]u8 = undefined;
    const path = std.fmt.bufPrint(&pathbuf, "/sys/class/net/{s}/address", .{ifname}) catch return null;
    var fbuf: [64]u8 = undefined;
    const fd = posix.openat(posix.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0) catch return null;
    defer net.close(fd);
    const n = posix.read(fd, &fbuf) catch return null;
    return parseMac(fbuf[0..n]);
}

pub fn parseMac(s0: []const u8) ?[6]u8 {
    var out: [6]u8 = undefined;
    var got: usize = 0;
    var hi: ?u8 = null;
    for (s0) |c| {
        const v: u8 = switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            else => continue,
        };
        if (hi) |h| {
            if (got >= 6) return null;
            out[got] = h << 4 | v;
            got += 1;
            hi = null;
        } else hi = v;
    }
    if (got != 6) return null;
    return out;
}

pub fn readSysMtu(ifname: []const u8) ?u32 {
    var pathbuf: [128]u8 = undefined;
    const path = std.fmt.bufPrint(&pathbuf, "/sys/class/net/{s}/mtu", .{ifname}) catch return null;
    var fbuf: [32]u8 = undefined;
    const fd = posix.openat(posix.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0) catch return null;
    defer net.close(fd);
    const n = posix.read(fd, &fbuf) catch return null;
    const text = std.mem.trim(u8, fbuf[0..n], " \t\r\n");
    return std.fmt.parseInt(u32, text, 10) catch null;
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

const t = std.testing;

test "v6rt：ICMP6_FILTER 位图（置位=丢弃）" {
    const f = icmp6FilterPassOnly(&.{ 133, 135, 136 });
    // 134 (RA) 必须被挡（否则会处理自己发的 RA）
    try t.expect((f[134 / 8] >> @intCast(134 % 8)) & 1 == 1);
    try t.expect((f[133 / 8] >> @intCast(133 % 8)) & 1 == 0);
    try t.expect((f[135 / 8] >> @intCast(135 % 8)) & 1 == 0);
    try t.expect((f[136 / 8] >> @intCast(136 % 8)) & 1 == 0);
    // 其余类型全挡
    try t.expect((f[128 / 8] >> @intCast(128 % 8)) & 1 == 1);
}

test "v6rt：确定性分配 —— 同 DUID+IAID 同地址，且不撞 EUI-64 位" {
    var rt = V6Runtime.init(t.allocator);
    var iface = V6Iface{
        .conf = .{ .name = "lan", .ifname = "br-lan", .ra = .server },
        .ifindex = 1,
        .icmp_fd = -1,
        .udp_fd = -1,
    };
    iface.globals.append(t.allocator, .{ .a = .{ 0x24, 0x0E } ++ [_]u8{0} ** 12 ++ .{ 0x01, 0x02 }, .plen = 64 }) catch unreachable;
    const duid = [_]u8{ 0x00, 0x03, 0, 1, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const a1 = rt.assign(&iface, &duid, 0x1234).?;
    const a2 = rt.assign(&iface, &duid, 0x1234).?;
    try t.expectEqualSlices(u8, &a1, &a2);
    // 前缀部分 = 全局地址 /64
    try t.expectEqual(@as(u8, 0x24), a1[0]);
    try t.expectEqual(@as(u8, 0x0E), a1[1]);
    for (a1[2..8]) |b| try t.expectEqual(@as(u8, 0), b);
    // U/L 位与组播位已清
    try t.expectEqual(@as(u8, 0), a1[8] & 0x03);
    // 不同 IAID 不同地址
    const a3 = rt.assign(&iface, &duid, 0x5678).?;
    try t.expect(!std.mem.eql(u8, &a1, &a3));
    iface.globals.deinit(t.allocator);
}

test "v6rt：maskPrefix 与 isLinkLocal" {
    try t.expectEqualSlices(u8, &([_]u8{ 0x24, 0x0E, 0xFF, 9, 9, 9, 9, 9 } ++ [_]u8{0} ** 8), &maskPrefix([_]u8{ 0x24, 0x0E, 0xFF } ++ [_]u8{9} ** 13, 64));
    try t.expect(isLinkLocal([_]u8{ 0xFE, 0x80 } ++ [_]u8{0} ** 14));
    try t.expect(!isLinkLocal([_]u8{ 0x24, 0x0E } ++ [_]u8{0} ** 14));
}

test "v6rt：isUla（fc00::/7，odhcpd 的 IN6_IS_ADDR_ULA）" {
    try t.expect(isUla([_]u8{ 0xFC, 0x00 } ++ [_]u8{0} ** 14));
    try t.expect(isUla([_]u8{ 0xFD, 0x12 } ++ [_]u8{0} ** 14));
    try t.expect(!isUla([_]u8{ 0xFE, 0x80 } ++ [_]u8{0} ** 14)); // 链路本地不是 ULA
    try t.expect(!isUla([_]u8{ 0x24, 0x0E } ++ [_]u8{0} ** 14)); // 公网不是 ULA
}

test "v6rt：RDNSS 优选 —— 有全局地址时绝不选链路本地" {
    // 生命周期是**剩余秒数**（内核 IFA_CACHEINFO 的真实语义），
    // 不是绝对墙钟 —— 这正是补齐前线上一直回退 fe80:: 的根因。
    var globals = [_]V6Iface.GlobalAddr{
        .{
            .a = .{ 0x24, 0x0E, 0x03, 0x98, 0x40, 0xE0, 0x26, 0xD0 } ++ [_]u8{0} ** 8,
            .plen = 64,
            .self_addr = .{ 0x24, 0x0E, 0x03, 0x98, 0x40, 0xE0, 0x26, 0xD0 } ++ [_]u8{0} ** 7 ++ .{1},
            .preferred = 90132,
            .valid = 176532,
        },
    };
    const pick = pickRdnsAddr(&globals).?;
    try t.expectEqualSlices(u8, &globals[0].self_addr, &pick);
    try t.expect(!isLinkLocal(pick)); // 关键断言：不是链路本地
}

test "v6rt：RDNSS 优选 —— 全部失效才回 null（调用方回退链路本地）" {
    var globals = [_]V6Iface.GlobalAddr{
        .{
            .a = [_]u8{ 0x24, 0x0E } ++ [_]u8{0} ** 14,
            .plen = 64,
            .self_addr = [_]u8{ 0x24, 0x0E } ++ [_]u8{0} ** 14,
            .preferred = 0,
            .valid = 0, // 剩余有效期为 0 = 已失效
        },
    };
    try t.expectEqual(@as(?[16]u8, null), pickRdnsAddr(&globals));
    // 空表同理
    try t.expectEqual(@as(?[16]u8, null), pickRdnsAddr(&[_]V6Iface.GlobalAddr{}));
}

test "v6rt：RDNSS 优选 —— forever(0xFFFFFFFF) 视为永不过期" {
    const g = [_]u8{ 0x24, 0x0E, 0x77 } ++ [_]u8{0} ** 13;
    var a = [_]V6Iface.GlobalAddr{
        .{ .a = g, .plen = 64, .self_addr = g, .preferred = 0xFFFFFFFF, .valid = 0xFFFFFFFF },
    };
    try t.expectEqualSlices(u8, &g, &pickRdnsAddr(&a).?);
}

test "v6rt：RDNSS 优选 —— ULA 优先，其次 preferred 更长者" {
    const ula = [_]u8{ 0xFD, 0x00 } ++ [_]u8{0} ** 14;
    const gua = [_]u8{ 0x24, 0x0E } ++ [_]u8{0} ** 14;

    // 公网在前、ULA 在后 —— ULA 应胜出（odhcpd 规则 3）
    var a = [_]V6Iface.GlobalAddr{
        .{ .a = gua, .plen = 64, .self_addr = gua, .preferred = 100, .valid = 200 },
        .{ .a = ula, .plen = 64, .self_addr = ula, .preferred = 50, .valid = 200 },
    };
    try t.expectEqualSlices(u8, &ula, &pickRdnsAddr(&a).?);

    // 两个都是公网 —— 取 preferred 更长的（规则 4）
    const g2 = [_]u8{ 0x24, 0x0E, 1 } ++ [_]u8{0} ** 13;
    var b = [_]V6Iface.GlobalAddr{
        .{ .a = g2, .plen = 64, .self_addr = g2, .preferred = 500, .valid = 900 },
        .{ .a = g2, .plen = 64, .self_addr = g2, .preferred = 100, .valid = 200 },
    };
    try t.expectEqualSlices(u8, &g2, &pickRdnsAddr(&b).?);
}

test "v6rt：RDNSS 优选 —— 已选新鲜 / 候选已过期时不让位" {
    const fresh = [_]u8{ 0x24, 0x0E, 0xAA } ++ [_]u8{0} ** 13;
    const stale = [_]u8{ 0x24, 0x0E, 0xBB } ++ [_]u8{0} ** 13;
    var a = [_]V6Iface.GlobalAddr{
        .{ .a = fresh, .plen = 64, .self_addr = fresh, .preferred = 1000, .valid = 2000 },
        // 候选 preferred 已过期（remaining=0），但 valid 还没到 —— 不该顶掉新鲜的
        .{ .a = stale, .plen = 64, .self_addr = stale, .preferred = 0, .valid = 5000 },
    };
    try t.expectEqualSlices(u8, &fresh, &pickRdnsAddr(&a).?);
}

test "v6rt：buildReply 的 IA_NA / DNS / rapid-commit" {
    var out: [512]u8 = undefined;
    const client = [_]u8{ 0x00, 0x01, 0xAA, 0xBB };
    const server = [_]u8{ 0x00, 0x03, 0, 1, 1, 2, 3, 4, 5, 6 };
    const dns1: [16]u8 = .{ 0xFE, 0x80 } ++ [_]u8{0} ** 13 ++ .{ 1 };
    const n = buildReply(&out, .advertise, .{ 1, 2, 3 }, &client, &server, .{ 0x24, 0x0E } ++ [_]u8{0} ** 12 ++ .{ 0, 1 }, 0x1234, false, &.{dns1}, &.{});

    // 头
    try t.expectEqual(@as(u8, 2), out[0]); // advertise
    try t.expectEqualSlices(u8, &.{ 1, 2, 3 }, out[1..4]);
    var i: usize = 4;
    var saw_client = false;
    var saw_server = false;
    var saw_ia = false;
    var saw_dns = false;
    var saw_rapid = false;
    while (i + 4 <= n) {
        const code = std.mem.readInt(u16, out[i..][0..2], .big);
        const len = std.mem.readInt(u16, out[i + 2 ..][0..2], .big);
        const body = out[i + 4 ..][0..len];
        if (code == 1) {
            saw_client = true;
            try t.expectEqualSlices(u8, &client, body);
        }
        if (code == 2) {
            saw_server = true;
            try t.expectEqualSlices(u8, &server, body);
        }
        if (code == 3) {
            saw_ia = true;
            try t.expectEqual(@as(u32, 0x1234), std.mem.readInt(u32, body[0..4], .big));
            const iaaddr = body[12..][0..24];
            try t.expectEqual(@as(u8, 0x24), iaaddr[0]);
            try t.expectEqual(@as(u32, IA_VALID), std.mem.readInt(u32, iaaddr[20..24], .big));
        }
        if (code == 23) {
            saw_dns = true;
            try t.expectEqualSlices(u8, &dns1, body[0..16]);
        }
        if (code == 14) saw_rapid = true;
        if (len == 0) break;
        i += 4 + len;
    }
    try t.expect(saw_client and saw_server and saw_ia and saw_dns);
    try t.expect(!saw_rapid); // advertise 不该带 rapid commit

    // REPLY + rapid commit 回显
    const n2 = buildReply(&out, .reply, .{ 4, 5, 6 }, &client, &server, null, 0, true, &.{}, &.{});
    try t.expectEqual(@as(u8, 7), out[0]);
    i = 4;
    saw_rapid = false;
    while (i + 4 <= n2) {
        const code = std.mem.readInt(u16, out[i..][0..2], .big);
        const len = std.mem.readInt(u16, out[i + 2 ..][0..2], .big);
        if (code == 14) saw_rapid = true;
        if (len == 0) break;
        i += 4 + len;
    }
    try t.expect(saw_rapid);
}

test "v6rt：netlink 事件解析（ifaddr/route/ignore）" {
    // 构造 RTM_NEWADDR：nlmsghdr(16) + ifaddrmsg(8) + IFA_ADDRESS rtattr(4+16)
    var m: [44]u8 = undefined;
    std.mem.writeInt(u32, m[0..4], 44, .little); // nlmsg_len
    std.mem.writeInt(u16, m[4..6], 20, .little); // RTM_NEWADDR
    m[16] = 10; // AF_INET6
    m[17] = 64; // prefixlen
    std.mem.writeInt(u32, m[20..24], 9, .little); // ifindex br-lan
    std.mem.writeInt(u16, m[24..26], 20, .little); // rta_len
    std.mem.writeInt(u16, m[26..28], 1, .little); // IFA_ADDRESS
    @memset(m[28..], 0x24);
    switch (parseNetlinkEvent(&m, 20)) {
        .ifaddr6 => |e| try t.expectEqual(@as(u32, 9), e.ifindex),
        else => return error.TestUnexpectedResult,
    }
    // DELADDR 同样命中
    std.mem.writeInt(u16, m[4..6], 21, .little);
    try t.expect(parseNetlinkEvent(&m, 21) == .ifaddr6);
    // IPv4 地址事件（family=2）忽略
    m[16] = 2;
    try t.expect(parseNetlinkEvent(&m, 20) == .ignore);

    // RTM_NEWROUTE ::/0：nlmsghdr(16) + rtmsg(12)
    var r: [28]u8 = undefined;
    std.mem.writeInt(u32, r[0..4], 28, .little);
    std.mem.writeInt(u16, r[4..6], 24, .little); // RTM_NEWROUTE
    r[16] = 10; // AF_INET6
    r[17] = 0; // dst_len=0 → ::/0
    switch (parseNetlinkEvent(&r, 24)) {
        .default_route6 => |e| try t.expect(e.added),
        else => return error.TestUnexpectedResult,
    }
    // DELROUTE
    std.mem.writeInt(u16, r[4..6], 25, .little);
    switch (parseNetlinkEvent(&r, 25)) {
        .default_route6 => |e| try t.expect(!e.added),
        else => return error.TestUnexpectedResult,
    }
    // 非默认路由（dst_len=64）忽略
    r[17] = 64;
    try t.expect(parseNetlinkEvent(&r, 24) == .ignore);
    // 别的消息类型忽略（RTM_NEWLINK=16）
    std.mem.writeInt(u16, r[4..6], 16, .little);
    try t.expect(parseNetlinkEvent(&r, 16) == .ignore);
}

test "v6rt：v6 租约状态行格式（statefiles.c:539）" {
    var rt = V6Runtime.init(t.allocator);
    var iface = V6Iface{
        .conf = .{ .name = "lan", .ifname = "br-lan", .dhcpv6 = .server },
        .ifindex = 1,
        .icmp_fd = -1,
        .udp_fd = -1,
    };
    iface.globals.append(t.allocator, .{ .a = .{ 0x24, 0x0E } ++ [_]u8{0} ** 12 ++ .{ 0x01, 0x02 }, .plen = 64 }) catch unreachable;
    const duid = [_]u8{ 0x00, 0x03, 0, 1, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
    const a1 = rt.assign(&iface, &duid, 0x1234).?;
    defer iface.globals.deinit(t.allocator);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(t.allocator);
    rt.appendStateLines(&buf, t.allocator, "br-lan", 0);
    try t.expect(buf.items.len > 0);
    // 行首：# <iface> <hexduid>
    try t.expect(std.mem.startsWith(u8, buf.items, "# br-lan 0003000" ++ "1aabbccddeeff "));
    // 主机名占位与固定长度字段
    try t.expect(std.mem.indexOf(u8, buf.items, " - ") != null);
    try t.expect(std.mem.indexOf(u8, buf.items, " 128 ") != null);
    // hostid 字段 == 地址接口 ID 的大端 hex
    const hostid = std.mem.readInt(u64, a1[8..16], .big);
    var hb: [16]u8 = undefined;
    const hs = std.fmt.bufPrint(&hb, "{x}", .{hostid}) catch unreachable;
    try t.expect(std.mem.indexOf(u8, buf.items, hs) != null);
    try t.expect(std.mem.indexOf(u8, buf.items, "/128") != null);
}

test "v6rt：ipv6_route 默认路由行识别" {
    // ::/0 且出接口非 lo → 命中（odhcpd parse_routes 的判定）
    try t.expect(checkDefaultRouteLine("00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000 00000040 00000000 000000ff 00000000 00000000 0000ffff eth0"));
    // lo 上的默认路由不算
    try t.expect(!checkDefaultRouteLine("00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000 00000040 00000000 000000ff 00000000 00000000 0000ffff lo"));
    // 非默认路由
    try t.expect(!checkDefaultRouteLine("240e039840e026d00000000000000000 40 00000000000000000000000000000000 00 00000000 00000040 00000000 00000001 00000000 00000000 0000ffff br-lan"));
}

test "v6rt：parseMac 吃得下 sysfs 与冒号两种写法" {
    try t.expectEqual([6]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, parseMac("aa:bb:cc:dd:ee:ff\n").?);
    try t.expectEqual([6]u8{ 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC }, parseMac("12-34-56-78-9A-BC").?);
    try t.expectEqual(@as(?[6]u8, null), parseMac("abc"));
}
