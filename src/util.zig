// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! util.zig — 对应 C 源码 util.c 中的通用工具函数
//! （随机数、时间、地址与名字辅助、发送重试、通配匹配等）

const std = @import("std");
const protocol = @import("protocol.zig");
const addr = @import("addr.zig");
const name = @import("name.zig");

// ---------------------------------------------------------------------------
// 随机数（util.c: rand_init / surf / rand16 / rand32 / rand64）
// 多线程版本：每个线程一份 PRNG，避免全局锁；种子由 Io 提供
// ---------------------------------------------------------------------------
threadlocal var rng: std.Random.Xoshiro256 = undefined;
threadlocal var rng_ready: bool = false;

pub fn randInit(seed: u64) void {
    rng = std.Random.Xoshiro256.init(seed);
    rng_ready = true;
}

/// 从 std.Io 取种子初始化本线程 PRNG
pub fn randInitFromIo(io: std.Io) void {
    var seed_bytes: [8]u8 = undefined;
    std.Io.random(io, &seed_bytes);
    randInit(std.mem.readInt(u64, &seed_bytes, .little));
}

fn ensureRng() void {
    if (!rng_ready) {
        // 兜底：用时钟与栈地址混合作为种子（main 里会先用 Io 播种）
        const now_ms = dnsmasqMilliseconds();
        const stack_addr = @intFromPtr(&rng);
        randInit(@as(u64, now_ms) ^ (stack_addr *% 0x9E3779B97F4A7C15));
    }
}

pub fn rand64() u64 {
    ensureRng();
    return rng.next();
}

pub fn rand32() u32 {
    return @truncate(rand64());
}

pub fn rand16() u16 {
    return @truncate(rand64());
}

/// 生成 [0, n) 的随机数（n 为 0 时返回 0）
pub fn randBelow(n: u32) u32 {
    if (n == 0) return 0;
    return rand32() % n;
}

// ---------------------------------------------------------------------------
// 文件辅助（0.16 移除了 std.fs.cwd()，这里直接用 posix）
// ---------------------------------------------------------------------------
/// 以「追加」方式打开（不存在则创建），失败返回 null
pub fn openAppend(path: []const u8) ?std.posix.fd_t {
    return std.posix.openat(
        std.posix.AT.FDCWD,
        path,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true },
        0o644,
    ) catch null;
}

/// 以「截断重写」方式打开（不存在则创建），失败返回 null
pub fn openTruncate(path: []const u8) ?std.posix.fd_t {
    return std.posix.openat(
        std.posix.AT.FDCWD,
        path,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
        0o644,
    ) catch null;
}

pub fn removeFile(path: []const u8) void {
    if (path.len == 0 or path.len >= 4096) return;
    var buf: [4096]u8 = undefined;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    _ = std.posix.system.unlink(buf[0..path.len :0].ptr);
}

// ---------------------------------------------------------------------------
// 时间（util.c: dnsmasq_time / dnsmasq_milliseconds）
// ---------------------------------------------------------------------------
pub fn dnsmasqTime() i64 {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(std.posix.CLOCK.REALTIME, &ts);
    return @intCast(ts.sec);
}

/// 单调时钟毫秒（i64）。0.16 移除了 std.time.milliTimestamp，
/// 超时计算统一用这个（对应 C 版 dnsmasq 里用 now*1000 做超时比较）。
pub fn monoMillis() i64 {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts);
    return @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1000000);
}

pub fn dnsmasqMilliseconds() u32 {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts);
    const ms: i64 = @as(i64, @intCast(ts.sec)) * 1000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1000000);
    return @truncate(@as(u64, @intCast(ms)));
}

/// 单调时钟微秒（i64）。动态负载均衡要测上游往返时间，
/// 毫秒精度对局域网内的 DNS 上游不够用（常常不到 1ms）。
pub fn monoMicros() i64 {
    var ts: std.posix.timespec = undefined;
    _ = std.posix.system.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts);
    return @as(i64, @intCast(ts.sec)) * 1_000_000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1000);
}

/// 对应 util.c: prettyprint_time()
pub fn prettyprintTime(buf: []u8, t: u32) []const u8 {
    var n: usize = 0;
    if (t == 0xffffffff) {
        @memcpy(buf[0..7], "forever");
        return buf[0..7];
    }

    const units = [_]struct { div: u32, suffix: u8 }{
        .{ .div = 60 * 60 * 24, .suffix = 'd' },
        .{ .div = 60 * 60, .suffix = 'h' },
        .{ .div = 60, .suffix = 'm' },
    };

    var rest = t;
    var started = false;
    for (units) |u| {
        const v = rest / u.div;
        if (v != 0 or started) {
            n += addr.writeUnsigned(buf[n..], v);
            buf[n] = u.suffix;
            n += 1;
            started = true;
        }
        rest -= v * u.div;
    }

    if (rest != 0 or !started) {
        n += addr.writeUnsigned(buf[n..], rest);
        buf[n] = 's';
        n += 1;
    }
    return buf[0..n];
}

// ---------------------------------------------------------------------------
// 其他小工具
// ---------------------------------------------------------------------------
/// 对应 util.c: memcmp_masked()
///
/// **掩码方向极易搞错**，这里与 C 逐字对齐：从**最后一个字节**开始向前扫描，
/// 每步把 mask 右移一位。于是 mask 的最低位对应 `a[len-1]`、第 k 位对应
/// `a[len-1-k]` —— 与 parseHex() 构造掩码的方向（最后一个被解析的字节落在最低位）
/// 正好配对。
///
/// 返回值语义也与 C 一致，**不是布尔**：
///   * 0        → 不匹配
///   * 非 0     → 匹配，数值 = 实际比较过的字节数 + 1
/// 这个数值被当作「特异性分数」使用（`dhcp-common.c:429` 在多条 `--dhcp-host`
/// 命中时用 `> count` 挑出最具体的一条），所以不能退化成 bool。
///
/// 之前这里的实现是「按 4 字节分组取掩码字节」（`(i & 3) * 8`），
/// 那是 IP 掩码的约定，与 C 的逐字节约定不同 —— 而且当时无任何调用点。
/// DHCP 的 MAC 通配匹配（`--dhcp-host=00:11:22:*:*:*`）必须用 C 的约定，
/// 故一并修正。
pub fn memcmpMasked(a: []const u8, b: []const u8, len: usize, mask_in: u32) i32 {
    var mask = mask_in;
    var count: i32 = 1;
    var i: usize = len;
    while (i > 0) : (mask >>= 1) {
        i -= 1;
        if ((mask & 1) == 0) {
            const x: u8 = if (i < a.len) a[i] else 0;
            const y: u8 = if (i < b.len) b[i] else 0;
            if (x == y) count += 1 else return 0;
        }
    }
    return count;
}

/// 对应 util.c: parse_hex()
///
/// 解析 `00:11:22:33:44:55` / `00-11-22` / 空格分隔 / 含 `*` 通配的硬件地址，
/// 也用于租约文件里的 client-id、DUID、vendorclass 等十六进制串。
///
/// 返回写入 `out` 的字节数；负数表示格式非法（C 里返回 -1）。
///
/// `mac_type`：C 用 `类型-地址`（如 `1-00:11:22:33:44:55`，类型以十六进制写在
/// 第一个 `-` 之前）表达非 Ethernet 的硬件类型。Zig 里用 `?*i32` 传出，
/// 未出现该前缀时保持调用方传入的 0。
///
/// `wildcard_mask`：每个 `*` 占一个字节位置，同时把掩码左移一位并置 1。
/// 因此最终掩码的**最低位对应最后一个字节**，与 memcmpMasked() 配对。
pub fn parseHex(
    in_raw: []const u8,
    out: []u8,
    maxlen: i32,
    wildcard_mask: ?*u32,
    mac_type: ?*i32,
) i32 {
    if (mac_type) |mt| mt.* = 0;

    var mask: u32 = 0;
    var i: usize = 0;
    var rest = in_raw;
    var done = false;
    // C 在把第一个 '-' 前的字段当作硬件类型解析后，会把 mac_type 指针**置 NULL**，
    // 于是后续 '-' 退化成普通分隔符。
    // 注意：光靠 `i == 0` 判断是不够的 —— 解析类型时 i 不会自增，所以第二个
    // '-' 前的字段仍然满足 `i == 0`，会被再次当成类型吞掉（"aa-bb-cc" 会退化成
    // 类型 aa、类型 bb、只解析出 1 个字节 cc）。必须真的把指针清空。
    var mt_ptr = mac_type;

    while (!done and (maxlen == -1 or i < @as(usize, @intCast(maxlen)))) {
        // 找出本段的结束位置（':' / '-' / ' ' / 结尾）
        var r: usize = 0;
        while (r < rest.len and rest[r] != ':' and rest[r] != '-' and rest[r] != ' ') : (r += 1) {
            const c = rest[r];
            if (c != '*' and !std.ascii.isHex(c)) return -1;
        }

        if (r >= rest.len) done = true;

        if (r != 0) {
            const field = rest[0..r];
            if (r < rest.len and rest[r] == '-' and i == 0 and mt_ptr != null) {
                // C 在此处把 '-' 就地置 0 后 strtol(in, 16)；此时 i == 0 说明
                // 还没解析过任何字节，field 整体就是类型号。
                const mt = mt_ptr.?;
                mt.* = std.fmt.parseInt(i32, field, 16) catch return -1;
                mt_ptr = null; // 与 C 的 `mac_type = NULL;` 对应
            } else if (std.mem.eql(u8, field, "*")) {
                mask = (mask << 1) | 1;
                i += 1;
            } else {
                // field 是若干个十六进制字节，可能紧排（"0011" == 两个字节 00 11）。
                // 注意 C 允许 `%2x` 式解析：其 bytes 按 (len+1)/2 计算。
                const bytes = (field.len + 1) / 2;
                var j: usize = 0;
                while (j < bytes) : (j += 1) {
                    const start = j * 2;
                    const end = @min(start + 2, field.len);
                    const two = field[start..end];
                    // C 的检查：同一字节里不允许混用十六进制字符与 '*'
                    if (std.mem.indexOfScalar(u8, two, '*') != null) return -1;
                    const v = std.fmt.parseInt(u8, two, 16) catch return -1;
                    out[i] = v;
                    mask <<= 1;
                    i += 1;
                    if (maxlen != -1 and i == @as(usize, @intCast(maxlen))) break;
                }
            }
        }

        // 跳到下一个字段（跳过一个分隔符）
        if (r < rest.len) {
            rest = rest[r + 1 ..];
        } else {
            rest = rest[rest.len..];
        }
    }

    if (wildcard_mask) |wm| wm.* = mask;

    return @intCast(i);
}

/// 对应 util.c: safe_strncpy()，保证 0 结尾
pub fn safeStrncpy(dest: []u8, src: []const u8) void {
    if (dest.len == 0) return;
    const n = @min(dest.len - 1, src.len);
    @memcpy(dest[0..n], src[0..n]);
    dest[n] = 0;
    if (n + 1 < dest.len) @memset(dest[n + 1 ..], 0);
}

/// 对应 util.c: wildcard_match()，"*" 与 "?" 通配
pub fn wildcardMatch(pattern: []const u8, match: []const u8) bool {
    return wildcardMatchn(pattern, match, 0);
}

pub fn wildcardMatchn(pattern: []const u8, match: []const u8, num: usize) bool {
    var p: usize = 0;
    var m: usize = 0;
    var matched: usize = 0;

    // 只比较前 num 段（num == 0 表示整串）
    while (p < pattern.len and (num == 0 or matched < num)) {
        if (pattern[p] == '*') return true;
        if (m >= match.len) return false;
        if (pattern[p] != '?' and pattern[p] != match[m]) return false;
        if (pattern[p] == '.' or pattern[p] == '?') matched += 1;
        p += 1;
        m += 1;
    }

    return (num == 0) == (p == pattern.len and m == match.len);
}

/// 对应 util.c: check_name 的 IDN 无关简化——判断是否为合法的大小写不敏感名字
pub fn isAsciiPrintable(s: []const u8) bool {
    for (s) |c| {
        if (c < 0x20 or c == 0x7f) return false;
    }
    return true;
}

/// 名字合法性包装，便于配置解析调用
pub fn validName(s: []const u8) bool {
    return name.legalHostname(s) or canonicaliseOk(s);
}

pub fn canonicaliseOk(s: []const u8) bool {
    if (s.len == 0 or s.len > protocol.MAXDNAMESTR) return false;
    var tmp: [protocol.MAXDNAMESTR + 1]u8 = undefined;
    @memcpy(tmp[0..s.len], s);
    tmp[s.len] = 0;
    return name.checkName(tmp[0..s.len]) != 0;
}

test "random helpers" {
    randInit(0x12345678);
    const a = rand64();
    const b = rand64();
    try std.testing.expect(a != b);
    try std.testing.expect(randBelow(10) < 10);
}

test "time helpers" {
    const t = dnsmasqTime();
    try std.testing.expect(t > 1_700_000_000);
    var buf: [32]u8 = undefined;
    try std.testing.expectEqualStrings("1d2h3m4s", prettyprintTime(&buf, 86400 + 7200 + 180 + 4));
    try std.testing.expectEqualStrings("45s", prettyprintTime(&buf, 45));
    try std.testing.expectEqualStrings("forever", prettyprintTime(&buf, 0xffffffff));
}

test "safe strncpy" {
    var buf: [8]u8 = undefined;
    safeStrncpy(&buf, "abcdefghij");
    try std.testing.expectEqualStrings("abcdefg", std.mem.sliceTo(&buf, 0));
    safeStrncpy(&buf, "ab");
    try std.testing.expectEqualStrings("ab", std.mem.sliceTo(&buf, 0));
}

test "wildcard match" {
    try std.testing.expect(wildcardMatch("abc", "abc"));
    try std.testing.expect(!wildcardMatch("abc", "abd"));
    try std.testing.expect(wildcardMatch("ab*", "abcdef"));
    try std.testing.expect(wildcardMatch("a?c", "abc"));
}

// ---------------------------------------------------------------------------
// parse_hex / memcmp_masked（DHCP 硬件地址通配匹配的基础）
// ---------------------------------------------------------------------------

test "parseHex：Ethernet 地址与掩码方向（对照 C util.c:parse_hex）" {
    var out: [16]u8 = [_]u8{0} ** 16;
    var mask: u32 = 0;
    var mtype: i32 = 0;

    try std.testing.expectEqual(@as(i32, 6), parseHex("00:11:22:33:44:55", &out, 16, &mask, &mtype));
    try std.testing.expectEqual(@as(u32, 0), mask);
    try std.testing.expectEqual(@as(i32, 0), mtype);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }, out[0..6]);

    // 全通配：6 个 '*'，掩码每一位都置 1，且最低位对应**最后一个**字节
    out = [_]u8{0} ** 16;
    mask = 0;
    try std.testing.expectEqual(@as(i32, 6), parseHex("*:*:*:*:*:*", &out, 16, &mask, &mtype));
    try std.testing.expectEqual(@as(u32, 0b111111), mask);

    // 末三字节通配：mask 低 3 位为 1
    out = [_]u8{0} ** 16;
    mask = 0;
    try std.testing.expectEqual(@as(i32, 6), parseHex("00:11:22:*:*:*", &out, 16, &mask, &mtype));
    try std.testing.expectEqual(@as(u32, 0b111), mask);
    try std.testing.expectEqual(@as(u8, 0x22), out[2]);

    // '-' 与空格都算分隔符（**必须传 mac_type = null**，否则第一个 '-' 前的
    // 字段会被当成硬件类型号，见下一条用例）
    out = [_]u8{0} ** 16;
    mask = 0;
    try std.testing.expectEqual(@as(i32, 3), parseHex("aa-bb-cc", &out, 16, &mask, null));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc }, out[0..3]);

    out = [_]u8{0} ** 16;
    mask = 0;
    try std.testing.expectEqual(@as(i32, 3), parseHex("aa bb cc", &out, 16, &mask, null));
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb, 0xcc }, out[0..3]);

    // 传了 mac_type 时，第一个 '-' 前的字段是**类型号**并被吃掉，不计入字节数。
    // 回归点：类型被消费后必须把指针置空，否则每个 '-' 前的字段都会被吞掉，
    // "aa-bb-cc" 会退化成「类型 aa + 类型 bb + 1 个字节 cc」而返回 1。
    out = [_]u8{0} ** 16;
    mask = 0;
    mtype = 0;
    try std.testing.expectEqual(@as(i32, 2), parseHex("aa-bb-cc", &out, 16, &mask, &mtype));
    try std.testing.expectEqual(@as(i32, 0xaa), mtype);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xbb, 0xcc }, out[0..2]);

    // "类型-地址" 形式：1 = ARPHRD_ETHER
    out = [_]u8{0} ** 16;
    mask = 0;
    mtype = 0;
    try std.testing.expectEqual(@as(i32, 6), parseHex("1-00:11:22:33:44:55", &out, 16, &mask, &mtype));
    try std.testing.expectEqual(@as(i32, 1), mtype);

    // 非法字符必须被拒绝（返回负数）
    out = [_]u8{0} ** 16;
    try std.testing.expect(parseHex("zz:11", &out, 16, &mask, &mtype) < 0);
    // 同一字节里混用十六进制与 '*' 也非法
    try std.testing.expect(parseHex("0*:11", &out, 16, &mask, &mtype) < 0);
}

test "memcmpMasked：返回值是特异性分数而非布尔（对照 C util.c:memcmp_masked）" {
    const mac_a = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
    const mac_b = [_]u8{ 0x00, 0x11, 0x22, 0xaa, 0xbb, 0xcc };
    const mac_c = [_]u8{ 0x99, 0x11, 0x22, 0x33, 0x44, 0x55 };

    // 无通配：全部 6 字节都比，返回 6 + 1
    try std.testing.expectEqual(@as(i32, 7), memcmpMasked(&mac_a, &mac_a, 6, 0));
    try std.testing.expectEqual(@as(i32, 0), memcmpMasked(&mac_a, &mac_b, 6, 0));

    // 末三字节通配（mask = 0b111）：只比前 3 字节 → 3 + 1 = 4
    try std.testing.expectEqual(@as(i32, 4), memcmpMasked(&mac_a, &mac_b, 6, 0b111));

    // 通配掩盖了差异：不匹配的位置被 mask 跳过后应当匹配
    try std.testing.expectEqual(@as(i32, 0), memcmpMasked(&mac_a, &mac_c, 6, 0b111));

    // 掩码方向（这是最容易写反的一处）：最低位对应**最后一个**字节，
    // 想通配首字节（索引 0）必须置**最高**位。
    // mask = 0b100000 → 只跳过 byte0，其余 5 字节全等 → 5 + 1
    try std.testing.expectEqual(@as(i32, 6), memcmpMasked(&mac_a, &mac_c, 6, 0b100000));
    // 全部通配 → 一个字节都没比 → C 的 count 停在初值 1（仍算「匹配」）
    try std.testing.expectEqual(@as(i32, 1), memcmpMasked(&mac_a, &mac_c, 6, 0b111111));

    // 「更具体的那条得分更高」—— dhcp-common.c:429 就是靠这个挑配置
    const specific = memcmpMasked(&mac_a, &mac_b, 6, 0b111); // 比了 3 字节
    const loose = memcmpMasked(&mac_a, &mac_b, 6, 0b111111); // 比了 0 字节
    try std.testing.expect(specific > loose);

    // len == 0 时 C 的循环一次都不执行，返回 1（不是 0，故仍是「匹配」）
    try std.testing.expectEqual(@as(i32, 1), memcmpMasked(&mac_a, &mac_b, 0, 0));
}
