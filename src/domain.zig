// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! domain.zig — 对应 C 源码 src/domain-match.c 的核心逻辑（服务器数组构建、
//! 域名最长后缀匹配、服务器分组筛选、本地应答判定、以及 --server 重载时的
//! 增删管理）。
//!
//! 与 C 版本的差异（适配本工程的 daemon.Daemon）：
//!   * C 用独立的 `daemon->servers` 与 `daemon->local_domains` 两条链，本工程的
//!     `Daemon.servers` 把二者合并（通过 `Server.local` / `Server.flags` 区分），
//!     所以 buildServerArray 直接遍历 `d.servers`。
//!   * 本文件对外返回单个匹配到的服务器（而非 C 的 [low, high] 区间）；分组区间
//!     由 `filterServers` 单独提供。
//!   * 排序严格复刻 C 的 order / order_servers / order_qsort（按 domain_len 从长
//!     到短，同长按字典序，再按 wildcard / 字面地址掩码 / 原插入顺序稳定排序）。

const std = @import("std");
const protocol = @import("protocol.zig");
const name = @import("name.zig");
const daemon = @import("daemon.zig");
const log = @import("log.zig");
const addr = @import("addr.zig");

/// 对应 C: lookup_domain 里用到的 daemon->server_has_wildcard（模块级镜像）
var server_has_wildcard: bool = false;
/// 对应 C: add_update_server 里用到的 maybe_free_servers（标记是否可能存在可复用记录）
var maybe_free_servers: bool = false;

/// 对应 C: SERV_LOCAL_ADDRESS 掩码（filter_servers 里用于识别“返回本地 RR”的服务器）
const SERV_LOCAL_ADDRESS = protocol.SERV_6ADDR | protocol.SERV_4ADDR | protocol.SERV_ALL_ZEROS;

// ---------------------------------------------------------------------------
// order / order_servers / order_qsort（domain-match.c:512-577）
// ---------------------------------------------------------------------------

/// 对应 C 的 order(qdomain, qlen, serv)：比较“查询子串”与某台服务器的 domain。
/// 返回 0 = 完全相等；-1 = 查询更长（或服务器为 nodots，总排最后）；1 = 查询更短。
fn order(qdomain: []const u8, qlen: usize, serv: *daemon.Server) i32 {
    // 无点名字服务器（//）始终排到最后，且对带点的查询不构成“等长”匹配
    if (serv.for_nodots) return -1;

    const dlen = serv.domain_len;
    if (qlen < dlen) return 1;
    if (qlen > dlen) return -1;

    const q = if (qlen == 0) "" else qdomain[0..qlen];
    const dom = serv.domain orelse "";
    return name.hostnameOrder(q, dom);
}

/// 对应 C 的 order_servers(s1, s2)：两台服务器之间的排序比较（用于分组与稳定排序）。
fn orderServers(s1: *daemon.Server, s2: *daemon.Server) i32 {
    // nodots 服务器之间相等；否则 nodots 排在非 nodots 之后
    if (s1.for_nodots) return if (s2.for_nodots) 0 else 1;

    const rc = order(s1.domain orelse "", s1.domain_len, s2);
    if (rc != 0) return rc;

    // 相同域名时，通配（*）服务器排在普通服务器之后
    if (s1.wildcard) return if (s2.wildcard) 0 else 1;
    if (s2.wildcard) return -1;

    return 0;
}

/// 对应 C 的 order_qsort(a, b)：qsort 用的最终比较器。
/// idx1/idx2 是两台服务器在 d.servers 中的原始插入顺序（等价于 C 的 serial，
/// 用于 --strict-order 下的稳定次序）。
fn orderQsort(s1: *daemon.Server, s2: *daemon.Server, idx1: usize, idx2: usize) i32 {
    var rc = orderServers(s1, s2);

    // 相同域名时，按字面地址掩码排序：IPv6 < IPv4 < all-zeros < NXDOMAIN < use-resolv
    if (rc == 0) {
        const mask = SERV_LOCAL_ADDRESS | protocol.SERV_USE_RESOLV;
        rc = @as(i32, @intCast(s2.flags & mask)) - @as(i32, @intCast(s1.flags & mask));
    }

    // 仍相等且都不是“本地”服务器时，按原始插入顺序排序（--strict-order）
    if (rc == 0) {
        const is_local1 = (s1.flags & (protocol.SERV_USE_RESOLV | protocol.SERV_LITERAL_ADDRESS)) != 0 or s1.local;
        const is_local2 = (s2.flags & (protocol.SERV_USE_RESOLV | protocol.SERV_LITERAL_ADDRESS)) != 0 or s2.local;
        if (!is_local1 and !is_local2) {
            rc = @as(i32, @intCast(idx1)) - @as(i32, @intCast(idx2));
        }
    }

    return rc;
}

/// 排序用的临时索引结构（把原始插入顺序一并带入比较器）
const Idx = struct {
    s: *daemon.Server,
    idx: usize,
};

fn orderQsortLess(_: void, a: Idx, b: Idx) bool {
    return orderQsort(a.s, b.s, a.idx, b.idx) < 0;
}

// ---------------------------------------------------------------------------
// build_server_array（domain-match.c:26）
// ---------------------------------------------------------------------------

/// 对应 build_server_array()：把所有服务器按 domain 从长到短排序后放入 d.serverarray，
/// 无 domain 的服务器排在最后（作为默认上游）。同时维护 server_has_wildcard。
pub fn buildServerArray(d: *daemon.Daemon) !void {
    server_has_wildcard = false;

    // 复算 domain_len，并探测是否存在通配服务器
    for (d.servers.items) |s| {
        s.domain_len = if (s.domain) |dom| dom.len else 0;
        if (s.wildcard) server_has_wildcard = true;
    }

    // 构造带原始序号的索引数组，便于稳定排序（--strict-order 用）
    var indexed: std.ArrayList(Idx) = .empty;
    defer indexed.deinit(d.allocator);
    for (d.servers.items, 0..) |s, i| {
        try indexed.append(d.allocator, .{ .s = s, .idx = i });
    }

    // 稳定排序：等长优先、字典序、wildcard/字面地址/插入次序
    std.mem.sort(Idx, indexed.items, {}, orderQsortLess);

    d.serverarray.clearRetainingCapacity();
    for (indexed.items, 0..) |it, pos| {
        // 对应 C 版 build_server_array() 里的 `srv->arrayposn = i`
        // —— forward.c 靠它把「已发送的服务器」映射回数组下标。
        it.s.arrayposn = pos;
        try d.serverarray.append(d.allocator, it.s);
    }

    log.debug("build_server_array: {d} servers, wildcard={any}", .{ d.serverarray.items.len, server_has_wildcard });
}

// ---------------------------------------------------------------------------
// 内部匹配辅助
// ---------------------------------------------------------------------------

/// 在 serverarray（已按 domain_len 降序排好）中二分查找：domain 恰好等于 qdomain[0..qlen]
/// 的第一台服务器索引；没有则返回 null。
fn findExact(d: *daemon.Daemon, q: []const u8, qlen: usize) ?usize {
    const arr = d.serverarray.items;
    const n = arr.len;
    if (n == 0) return null;

    var low: usize = 0;
    var high: usize = n;
    while (low < high) {
        const mid = (low + high) / 2;
        const rc = order(q, qlen, arr[mid]);
        if (rc == 0) {
            // 向前回退到同一域名组的第一个
            var i = mid;
            while (i > 0 and order(q, qlen, arr[i - 1]) == 0) i -= 1;
            return i;
        } else if (rc < 0) {
            // 当前服务器 domain 比查询短（或 nodots），说明更长的在更靠前
            high = mid;
        } else {
            low = mid + 1;
        }
    }
    return null;
}

/// 处理“空查询”（默认上游 / nodots / 通配）的匹配：返回 domain_len==0 这一组中
/// 合适的服务器。dotless 为 true 时优先 nodots 服务器，否则优先普通默认服务器。
/// 注意不能用 findExact("", 0)：因为 order() 对 nodots 服务器恒返回 -1，会漏掉纯
/// nodots 的空域组，故直接从数组末尾扫描（按 domain_len 降序，空域组必在末尾）。
fn matchEmpty(d: *daemon.Daemon, dotless: bool) ?*daemon.Server {
    const arr = d.serverarray.items;

    // 回退到空域组的起始位置
    var i = arr.len;
    while (i > 0 and arr[i - 1].domain_len == 0) i -= 1;

    var default_s: ?*daemon.Server = null;
    var nodots_s: ?*daemon.Server = null;
    while (i < arr.len and arr[i].domain_len == 0) {
        const s = arr[i];
        if (s.for_nodots) {
            nodots_s = s;
        } else if (default_s == null) {
            default_s = s;
        }
        i += 1;
    }

    if (dotless and nodots_s != null) return nodots_s;
    return default_s;
}

/// 内部：返回 name（规范域名，不带尾点）在 serverarray 中“最长后缀匹配”到的服务器索引；
/// 无匹配（也没有默认上游）时返回 null。flags 仅用于 F_DS / F_DNSSECOK 的少量语义。
fn matchIndex(d: *daemon.Daemon, dn: []const u8, flags: u32) ?usize {
    const arr = d.serverarray.items;
    if (arr.len == 0) return null;

    // DS 查询应从父域取（对应 C 的 F_DS 处理）
    var qstart: usize = 0;
    if ((flags & protocol.F_DS) != 0) {
        if (std.mem.indexOfScalar(u8, dn, '.')) |pos| qstart = pos + 1 else qstart = dn.len;
    }

    // 从最长后缀到最短后缀（仅取标签边界）依次尝试
    var start = qstart;
    while (true) {
        const cand = dn[start..];
        if (cand.len > 0) {
            if (findExact(d, cand, cand.len)) |idx| {
                const s = arr[idx];
                // 命中“use resolv.conf”服务器：继续以空查询找默认上游（对应 C 逻辑）
                if ((s.flags & protocol.SERV_USE_RESOLV) != 0) {
                    // fallthrough to empty-query handling
                } else {
                    return idx;
                }
            }
        }
        const dot = std.mem.indexOfScalar(u8, dn[start..], '.');
        if (dot == null) break;
        start = start + dot.? + 1;
    }

    // 空查询：默认上游 / nodots / 通配
    const tail = dn[qstart..];
    const dotless = !std.mem.containsAtLeast(u8, tail, 1, ".");
    if (matchEmpty(d, dotless)) |s| {
        for (arr, 0..) |x, i| if (x == s) return i;
    }
    return null;
}

// ---------------------------------------------------------------------------
// lookup_domain（domain-match.c:106）
// ---------------------------------------------------------------------------

/// 对应 lookup_domain()：在 serverarray 中做“最长后缀匹配”，返回匹配到的 server
/// （供 answer_request / forward 决定本地应答还是转发）。dn 为规范化的域名
/// （不带尾点）。flags 传入要匹配的域名类型（可用 SERV_* / F_* 组合，或 0）。
///
/// 说明：本工程对外接口只返回单个服务器；若设置了 OPT_ORDER（--strict-order）也
/// 同样返回该组中排序最靠前的一台（与 C 的“不轮询”语义一致）。
pub fn lookupDomain(d: *daemon.Daemon, dn: []const u8, flags: u32) ?*daemon.Server {
    const idx = matchIndex(d, dn, flags) orelse return null;
    return d.serverarray.items[idx];
}

// ---------------------------------------------------------------------------
// filter_servers（domain-match.c:284）
// ---------------------------------------------------------------------------

/// 服务器区间：`[first, last)`；`first == last` 表示无匹配。
///
/// 用具名类型而不是匿名结构体 —— 匿名结构体即使字段完全相同也算不同类型，
/// 跨文件返回时会因为「类型不匹配」而无法赋值。
pub const ServerRange = struct { first: usize, last: usize };

/// 对应 filter_servers()：给定 name，返回 serverarray 中“匹配同一域名组”的服务器区间
/// { first, last }（first 含，last 不含）；无匹配时 first == last。
/// flags 用于按地址类型收窄（F_CONFIG / F_IPV4 / F_IPV6 / F_SERVER / F_DOMAINSRV），
/// 传 0 时返回整组（不含字面地址类服务器，与 C 行为一致）。
pub fn filterServers(d: *daemon.Daemon, flags: u32, nm: []const u8) ServerRange {
    const arr = d.serverarray.items;
    const n = arr.len;

    const seed = matchIndex(d, nm, flags) orelse return .{ .first = n, .last = n };

    // 1) 向两侧扩展，覆盖所有“同一域名组”的记录
    var nlow = seed;
    while (nlow > 0 and orderServers(arr[nlow - 1], arr[nlow]) == 0) nlow -= 1;
    var nhigh = seed;
    while (nhigh < n - 1 and orderServers(arr[nhigh], arr[nhigh + 1]) == 0) nhigh += 1;
    nhigh += 1;

    // 2) 依据 flags 收窄（忠实复刻 C filter_servers 的地址类型筛选）
    if ((flags & protocol.F_CONFIG) != 0) {
        // 对应 domain-match.c 的 F_CONFIG 分支：
        //     /* We're just lookin for any matches that return an RR. */
        //     for (i = nlow; i < nhigh; i++)
        //       if (daemon->serverarray[i]->flags & SERV_LOCAL_ADDRESS)
        //         break;
        //     if (i == nhigh) nhigh = nlow;   /* failed */
        // 语义是「组内**存在任一** SERV_LOCAL_ADDRESS 服务器即命中」。
        //
        // 这里曾经写成 `while (是 LOCAL_ADDRESS) i++` 再「i==nhigh 则失败」，
        // 等价于「组内**全部**都是 LOCAL_ADDRESS 才失败」—— 与 C **正好相反**：
        // 单成员组 [LOCAL_ADDRESS] 时 C 命中、本实现却失败。该分支此前无人调用
        // （唯一调用点是移植自 forward.c:796 的 NXDOMAIN->NODATA 改写），所以一直
        // 没暴露；用到它之后立刻在 code.aliyun.com 上表现为「把真 NXDOMAIN 改成了
        // NODATA」。现按 C 重写。
        var i = nlow;
        while (i < nhigh and (arr[i].flags & SERV_LOCAL_ADDRESS) == 0) i += 1;
        if (i == nhigh) nhigh = nlow; // 组内没有任何本地地址服务器 -> 失败
    } else {
        // IPv6 字面地址优先
        var i = nlow;
        while (i < nhigh and (arr[i].flags & protocol.SERV_6ADDR) != 0) i += 1;
        if ((flags & protocol.F_SERVER == 0) and (i != nlow) and (flags & protocol.F_IPV6 != 0)) {
            nhigh = i;
        } else {
            nlow = i;
            // IPv4 字面地址
            i = nlow;
            while (i < nhigh and (arr[i].flags & protocol.SERV_4ADDR) != 0) i += 1;
            if ((flags & protocol.F_SERVER == 0) and (i != nlow) and (flags & protocol.F_IPV4 != 0)) {
                nhigh = i;
            } else {
                nlow = i;
                // all-zeros 字面地址
                i = nlow;
                while (i < nhigh and (arr[i].flags & protocol.SERV_ALL_ZEROS) != 0) i += 1;
                if ((flags & protocol.F_SERVER == 0) and (i != nlow) and (flags & (protocol.F_IPV4 | protocol.F_IPV6)) != 0) {
                    nhigh = i;
                } else {
                    nlow = i;
                    // NXDOMAIN / local 字面地址
                    i = nlow;
                    while (i < nhigh and (arr[i].flags & protocol.SERV_LITERAL_ADDRESS) != 0) i += 1;
                    if ((flags & (protocol.F_DOMAINSRV | protocol.F_SERVER)) == 0 and (i != nlow)) {
                        nhigh = i;
                    } else {
                        nlow = i;
                        // use resolv.conf 服务器
                        i = nlow;
                        while (i < nhigh and (arr[i].flags & protocol.SERV_USE_RESOLV) != 0) i += 1;
                        if (i != nlow) {
                            nhigh = i;
                        } else if (nlow < n and nlow != nhigh and
                            (flags & protocol.F_DOMAINSRV != 0) and
                            arr[nlow].domain_len == 0 and !arr[nlow].for_nodots)
                        {
                            nlow = nhigh;
                        }
                    }
                }
            }
        }
    }

    return .{ .first = nlow, .last = nhigh };
}

// ---------------------------------------------------------------------------
// is_local_answer（domain-match.c:379）
// ---------------------------------------------------------------------------

/// 对应 is_local_answer()：判断该 server 是否应当由本地缓存/配置直接应答。
/// 携带 SERV_LITERAL_ADDRESS（address=/dom/、local=/dom/、server=/dom/ 无地址等）
/// 或 local 标志的服务器走本地应答。
pub fn isLocalAnswer(d: *daemon.Daemon, s: *daemon.Server, nm: []const u8) u32 {
    const flags = s.flags;

    // 只有字面地址类服务器（local=/dom/、address=/dom/ip、server=/dom/#）才算本地应答
    if ((flags & protocol.SERV_LITERAL_ADDRESS) == 0) return 0;

    if ((flags & protocol.SERV_4ADDR) != 0) return protocol.F_IPV4;
    if ((flags & protocol.SERV_6ADDR) != 0) return protocol.F_IPV6;
    if ((flags & protocol.SERV_ALL_ZEROS) != 0) return protocol.F_IPV4 | protocol.F_IPV6;

    // 走到这里说明本组服务器没有给出具体地址（典型就是 local=/dom/）。
    // 对应 C 的注释：先回退到同一域名组的首台服务器，看该组是否提供了
    // 别的类型的本地地址；否则再看这个域下有没有本地名字，
    // 有 -> NoData（F_NOERR），没有 -> NXDOMAIN。
    var first = indexOfServer(d, s) orelse {
        return if (checkForLocalDomain(d, nm)) protocol.F_NOERR else protocol.F_NXDOMAIN;
    };
    while (first > 0 and orderServers(d.serverarray.items[first - 1], d.serverarray.items[first]) == 0) first -= 1;

    const head = d.serverarray.items[first];
    if ((head.flags & SERV_LOCAL_ADDRESS) != 0 or checkForLocalDomain(d, nm))
        return protocol.F_NOERR;
    return protocol.F_NXDOMAIN;
}

/// 在 serverarray 中定位某台服务器的下标（同一指针可能出现多次，取第一个）
fn indexOfServer(d: *daemon.Daemon, s: *daemon.Server) ?usize {
    for (d.serverarray.items, 0..) |it, i| {
        if (it == s) return i;
    }
    return null;
}

/// 对应 rfc1035.c: check_for_local_domain()
///
/// 判断「这个域下是否存在本地记录」。C 版本除缓存外还会检查
/// mx / txt / interface-name / ptr / naptr 等本地记录，这些子系统尚未移植，
/// 这里只保留缓存这一条（也是实际起作用的主路径）。
pub fn checkForLocalDomain(d: *daemon.Daemon, nm: []const u8) bool {
    if (!d.cache_ready) return false;
    return d.cache.findNonTerminal(nm, now_seconds());
}

fn now_seconds() i64 {
    const util = @import("util.zig");
    return util.dnsmasqTime();
}

// ---------------------------------------------------------------------------
// mark_servers / cleanup_servers（domain-match.c:590-649）
// ---------------------------------------------------------------------------

/// 对应 mark_servers(flag)：在 --server 重载前调用，按 flag 标记所有服务器，
/// 并设置 maybe_free_servers（表示后续 add_update_server 可复用被标记记录）。
pub fn markServers(d: *daemon.Daemon, flag: u16) void {
    maybe_free_servers = flag != 0;
    for (d.servers.items) |s| {
        if ((s.flags & flag) != 0) {
            s.flags |= protocol.SERV_MARK;
        } else {
            s.flags &= ~protocol.SERV_MARK;
        }
    }
}

/// 对应 cleanup_servers()：释放并移除仍被 SERV_MARK 标记的服务器（重载时删除旧配置）。
pub fn cleanupServers(d: *daemon.Daemon) void {
    var i: usize = 0;
    while (i < d.servers.items.len) {
        const s = d.servers.items[i];
        if ((s.flags & protocol.SERV_MARK) != 0) {
            if (s.domain) |dom| d.allocator.free(dom);
            if (s.iface) |inf| d.allocator.free(inf);
            d.allocator.destroy(s);
            _ = d.servers.orderedRemove(i);
        } else {
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// add_update_server（domain-match.c:651）
// ---------------------------------------------------------------------------

/// 对应 add_update_server()：新增或复用一台服务器记录（支持 domain 前导 '*' 通配、
/// 前导 '.' 归一化、以及重载时复用被 SERV_MARK 标记的同名记录）。
pub fn addUpdateServer(
    d: *daemon.Daemon,
    flags: u16,
    addr_opt: ?addr.SockAddr,
    source_opt: ?addr.SockAddr,
    iface_opt: ?[]const u8,
    domain_opt: ?[]const u8,
    local_addr: ?addr.AllAddr,
) !void {
    _ = local_addr;

    var dom_input: []const u8 = domain_opt orelse "";
    var f = flags;

    // 去掉前导 '/' 与 '.'（调用方已剥离斜杠的情形，这里再做一次保险）
    while (dom_input.len > 0 and (dom_input[0] == '/' or dom_input[0] == '.')) dom_input = dom_input[1..];

    // 处理前导 '*'（通配）。/*/ 与 * 都表示「空 domain + 通配」；*.x 表示通配 x。
    if (dom_input.len > 0 and dom_input[0] == '*') {
        dom_input = dom_input[1..];
        f |= protocol.SERV_WILDCARD;
        while (dom_input.len > 0 and (dom_input[0] == '/' or dom_input[0] == '.')) dom_input = dom_input[1..];
    }

    var alloc_domain: ?[]u8 = null;
    if (dom_input.len != 0) {
        alloc_domain = name.canonicalise(d.allocator, dom_input) orelse return error.InvalidDomain;
    }

    // 重载场景：尝试复用被标记的同名服务器
    var serv: ?*daemon.Server = null;
    if (maybe_free_servers) {
        for (d.servers.items) |s| {
            const same_name = if (s.domain) |sd| blk: {
                break :blk if (alloc_domain) |ad| name.hostnameIsEqual(sd, ad) else false;
            } else alloc_domain == null;
            if ((s.flags & protocol.SERV_MARK) != 0 and same_name) {
                serv = s;
                break;
            }
        }
    }

    if (serv == null) {
        serv = try d.newServer();
        try d.addServer(serv.?);
    } else if (serv.?.domain) |old| {
        d.allocator.free(old);
    }

    const s = serv.?;
    s.flags = f;
    s.domain = if (alloc_domain) |ad| ad else null;
    s.domain_len = if (alloc_domain) |ad| ad.len else 0;
    s.wildcard = (f & protocol.SERV_WILDCARD) != 0;
    s.for_nodots = (f & protocol.SERV_FOR_NODOTS) != 0;
    s.local = (f & protocol.SERV_LITERAL_ADDRESS) != 0;
    if (addr_opt) |a| s.addr = a;
    if (source_opt) |a| s.source_addr = a;
    if (iface_opt) |inf| {
        s.iface = try d.allocator.dupe(u8, inf);
    }
}

// ===========================================================================
// 测试
// ===========================================================================

const testing = std.testing;

/// 用 allocator 复制域名字符串挂到服务器上（便于 deinit 时正确释放）
fn setDomain(d: *daemon.Daemon, s: *daemon.Server, dom: []const u8) !void {
    if (dom.len == 0) {
        s.domain = null;
    } else {
        s.domain = try d.allocator.dupe(u8, dom);
    }
}

test "最长后缀匹配" {
    var d = daemon.Daemon{ .allocator = testing.allocator };
    defer d.deinit();

    const a = try d.newServer();
    try setDomain(&d, a, "example.com");
    try d.addServer(a);

    const b = try d.newServer();
    try setDomain(&d, b, "com");
    try d.addServer(b);

    try buildServerArray(&d);

    const r1 = lookupDomain(&d, "www.example.com", 0);
    try testing.expectEqual(a, r1); // example.com 比 com 更具体

    const r2 = lookupDomain(&d, "something.com", 0);
    try testing.expectEqual(b, r2); // 只有 com 命中

    // 更长的域应优先于更短的：foo.bar.example.com 仍命中 example.com
    const r3 = lookupDomain(&d, "foo.bar.example.com", 0);
    try testing.expectEqual(a, r3);
}

test "根域名默认上游" {
    var d = daemon.Daemon{ .allocator = testing.allocator };
    defer d.deinit();

    const def = try d.newServer();
    try setDomain(&d, def, ""); // 无 domain 的默认上游
    try d.addServer(def);

    try buildServerArray(&d);

    const r = lookupDomain(&d, "anything.xyz", 0);
    try testing.expectEqual(def, r);

    // 一个完全无关的域名也应落到默认上游
    const r2 = lookupDomain(&d, "a.b.c.d.e", 0);
    try testing.expectEqual(def, r2);
}

test "// nodots 无点域名" {
    var d = daemon.Daemon{ .allocator = testing.allocator };
    defer d.deinit();

    const ndots = try d.newServer();
    ndots.for_nodots = true;
    try setDomain(&d, ndots, ""); // server=//1.2.3.4
    try d.addServer(ndots);

    try buildServerArray(&d);

    // 无点名字命中 nodots 服务器
    const r = lookupDomain(&d, "host", 0);
    try testing.expectEqual(ndots, r);

    // 带点的名字不应命中（也没有默认上游）→ null
    const r2 = lookupDomain(&d, "host.example", 0);
    try testing.expectEqual(@as(?*daemon.Server, null), r2);
}

test "/*/ 通配" {
    var d = daemon.Daemon{ .allocator = testing.allocator };
    defer d.deinit();

    const spec = try d.newServer();
    try setDomain(&d, spec, "example.com");
    try d.addServer(spec);

    const wild = try d.newServer();
    wild.wildcard = true;
    try setDomain(&d, wild, ""); // server=/*/1.2.3.4
    try d.addServer(wild);

    try buildServerArray(&d);

    // 具体域优先于通配
    const r1 = lookupDomain(&d, "www.example.com", 0);
    try testing.expectEqual(spec, r1);

    // 其它域名落到通配
    const r2 = lookupDomain(&d, "other.org", 0);
    try testing.expectEqual(wild, r2);
}

test "local 域判定" {
    var d = daemon.Daemon{ .allocator = testing.allocator };
    defer d.deinit();

    const local_s = try d.newServer();
    local_s.local = true; // local=/example.com/
    try setDomain(&d, local_s, "example.com");
    try d.addServer(local_s);

    const up_s = try d.newServer(); // 普通上游 server=/example.com/1.2.3.4
    try setDomain(&d, up_s, "example.com");
    try d.addServer(up_s);

    try testing.expectEqual(@as(u32, 0), isLocalAnswer(&d, local_s, "www.example.com"));
    try testing.expectEqual(@as(u32, 0), isLocalAnswer(&d, up_s, "www.example.com"));

    // 携带 SERV_LITERAL_ADDRESS 也应判为本地
    const lit = try d.newServer();
    lit.flags = protocol.SERV_LITERAL_ADDRESS;
    try setDomain(&d, lit, "example.com");
    try d.addServer(lit);
    try testing.expect(isLocalAnswer(&d, lit, "example.com") != 0);
}

test "排序稳定性" {
    var d = daemon.Daemon{ .allocator = testing.allocator };
    defer d.deinit();

    // 故意乱序加入，验证排序后按 domain_len 降序、同长按字典序
    const com = try d.newServer();
    try setDomain(&d, com, "com");
    try d.addServer(com);

    const example_com = try d.newServer();
    try setDomain(&d, example_com, "example.com");
    try d.addServer(example_com);

    const def = try d.newServer();
    try setDomain(&d, def, "");
    try d.addServer(def);

    const example_org = try d.newServer();
    try setDomain(&d, example_org, "example.org");
    try d.addServer(example_org);

    try buildServerArray(&d);

    const arr = d.serverarray.items;
    try testing.expectEqual(@as(usize, 4), arr.len);

    // 最长优先：两个 11 长度的域在前
    try testing.expect(arr[0].domain_len >= arr[1].domain_len);
    try testing.expect(arr[1].domain_len >= arr[2].domain_len);
    try testing.expect(arr[2].domain_len >= arr[3].domain_len);

    // 同长（example.com / example.org）按字典序：example.com 在前
    try testing.expectEqual(example_com, arr[0]);
    try testing.expectEqual(example_org, arr[1]);
    try testing.expectEqual(com, arr[2]);
    try testing.expectEqual(def, arr[3]);
}

test "filterServers 同一域名组" {
    var d = daemon.Daemon{ .allocator = testing.allocator };
    defer d.deinit();

    const s1 = try d.newServer();
    try setDomain(&d, s1, "example.com");
    try d.addServer(s1);

    const s2 = try d.newServer();
    try setDomain(&d, s2, "example.com");
    try d.addServer(s2);

    const other = try d.newServer();
    try setDomain(&d, other, "other.com");
    try d.addServer(other);

    try buildServerArray(&d);

    const grp = filterServers(&d, 0, "www.example.com");
    try testing.expectEqual(@as(usize, 2), grp.last - grp.first);
    // 区间应覆盖两台 example.com 服务器
    var covered: usize = 0;
    var i = grp.first;
    while (i < grp.last) : (i += 1) {
        if (d.serverarray.items[i] == s1 or d.serverarray.items[i] == s2) covered += 1;
    }
    try testing.expectEqual(@as(usize, 2), covered);
}

test "filterServers F_CONFIG：组内存在本地地址服务器即命中（回归：曾与 C 相反）" {
    // C 的 F_CONFIG 分支语义是「组内**存在任一** SERV_LOCAL_ADDRESS 即命中」；
    // 旧实现「**全为** LOCAL_ADDRESS 才失败」正好相反，单成员组会误判为不命中。
    var d = daemon.Daemon{ .allocator = testing.allocator };
    defer d.deinit();

    // 组 A：单个 server=/corp.com/10.0.0.1 —— 本地地址服务器
    const local1 = try d.newServer();
    try setDomain(&d, local1, "corp.com");
    local1.flags = protocol.SERV_4ADDR;
    try d.addServer(local1);

    // 组 B：普通上游（无本地地址标志）
    const upstream = try d.newServer();
    try setDomain(&d, upstream, "example.com");
    upstream.flags = protocol.SERV_USE_RESOLV;
    try d.addServer(upstream);

    try buildServerArray(&d);

    // corp.com 组内存在 LOCAL_ADDRESS -> 必须命中，且区间正好覆盖这台
    const grp = filterServers(&d, protocol.F_CONFIG, "www.corp.com");
    try testing.expectEqual(@as(usize, 1), grp.last - grp.first);
    try testing.expectEqual(local1, d.serverarray.items[grp.first]);

    // example.com 组没有任何 LOCAL_ADDRESS -> 必须不命中
    const grp2 = filterServers(&d, protocol.F_CONFIG, "www.example.com");
    try testing.expectEqual(@as(usize, 0), grp2.last - grp2.first);

    // 顺带确认 SERV_LOCAL_ADDRESS 掩码包含 4ADDR（避免常量被改坏）
    try testing.expect((protocol.SERV_4ADDR & SERV_LOCAL_ADDRESS) != 0);
}

test "markServers / cleanupServers 重载删除" {
    var d = daemon.Daemon{ .allocator = testing.allocator };
    defer d.deinit();

    const keep = try d.newServer();
    try setDomain(&d, keep, "keep.com");
    keep.flags = protocol.SERV_FROM_FILE;
    try d.addServer(keep);

    const drop = try d.newServer();
    try setDomain(&d, drop, "drop.com");
    drop.flags = protocol.SERV_FROM_RESOLV;
    try d.addServer(drop);

    try testing.expectEqual(@as(usize, 2), d.servers.items.len);

    // 标记 FROM_RESOLV 的记录准备删除
    markServers(&d, protocol.SERV_FROM_RESOLV);
    cleanupServers(&d);

    try testing.expectEqual(@as(usize, 1), d.servers.items.len);
    try testing.expectEqual(keep, d.servers.items[0]);
}

test "addUpdateServer 新增并匹配" {
    var d = daemon.Daemon{ .allocator = testing.allocator };
    defer d.deinit();

    try addUpdateServer(&d, 0, null, null, null, "example.com", null);
    try buildServerArray(&d);
    const r = lookupDomain(&d, "www.example.com", 0);
    try testing.expect(r != null);
    try testing.expectEqualStrings("example.com", r.?.domain.?);

    // 通配：/*/
    try addUpdateServer(&d, 0, null, null, null, "/*/", null);
    try buildServerArray(&d);
    const r2 = lookupDomain(&d, "whatever.org", 0);
    try testing.expect(r2 != null);
    try testing.expect(r2.?.wildcard);
}
