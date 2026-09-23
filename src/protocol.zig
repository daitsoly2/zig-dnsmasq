// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! protocol.zig — 对应 C 源码 src/dns-protocol.h（以及 dnsmasq.h 中 DNS 相关常量）
//!
//! 这里只放“线上格式”的常量与最底层字节序读写。dnsmasq 用 get/put_short/long 宏
//! （见 rfc1035.c 尾部）在报文缓冲上读写，本文件把它们改写为带边界检查的切片操作。

const std = @import("std");

// ---------------------------------------------------------------------------
// 报文尺寸常量（dns-protocol.h:49-54）
// ---------------------------------------------------------------------------
/// 域名 wire 格式最大长度
pub const MAXDNAME: usize = 255;
/// dnsmasq 内部 C 字符串形式的域名最大长度
pub const MAXDNAMESTR: usize = 503;
/// 传统 DNS 报文最大长度
pub const PACKETSZ: usize = 512;
/// 报文绝对上限（TCP 的 2 字节长度前缀所限），用于本地应答失败时
/// 整段保存/还原原始查询报文
pub const MAXPKT: usize = 65535;
/// RR 固定字段长度（type/class/ttl/rdlen）
pub const RRFIXEDSZ: usize = 10;
/// 单个 label 最大长度
pub const MAXLABEL: usize = 63;
/// 一个 label 压缩指针长度
pub const POINTERSZ: usize = 2;

pub const NAMESERVER_PORT: u16 = 53;
pub const IN6ADDRSZ: usize = 16;
pub const INADDRSZ: usize = 4;

/// 工作缓冲区大小：PACKETSZ + MAXDNAME + RRFIXEDSZ（dnsmasq.h 里的 PACKET_BUFF 推导）
pub const PACKET_BUFF_SZ: usize = MAXDNAME + RRFIXEDSZ + (MAXDNAME * 4);

// ---------------------------------------------------------------------------
// RCODE（dns-protocol.h:56-61）
// ---------------------------------------------------------------------------
pub const NOERROR: u8 = 0;
pub const FORMERR: u8 = 1;
pub const SERVFAIL: u8 = 2;
pub const NXDOMAIN: u8 = 3;
pub const NOTIMP: u8 = 4;
pub const REFUSED: u8 = 5;

// ---------------------------------------------------------------------------
// OPCODE（dns-protocol.h:63-）
// ---------------------------------------------------------------------------
pub const OPCODE_QUERY: u8 = 0;
pub const OPCODE_IQUERY: u8 = 1;
pub const OPCODE_STATUS: u8 = 2;
pub const OPCODE_NOTIFY: u8 = 4;
pub const OPCODE_UPDATE: u8 = 5;

// ---------------------------------------------------------------------------
// CLASS
// ---------------------------------------------------------------------------
pub const C_IN: u16 = 1;
pub const C_CHAOS: u16 = 3;
pub const C_HESIOD: u16 = 4;
pub const C_ANY: u16 = 255;

// ---------------------------------------------------------------------------
// TYPE
// ---------------------------------------------------------------------------
pub const T_A: u16 = 1;
pub const T_NS: u16 = 2;
pub const T_MD: u16 = 3;
pub const T_MF: u16 = 4;
pub const T_CNAME: u16 = 5;
pub const T_SOA: u16 = 6;
pub const T_MB: u16 = 7;
pub const T_MG: u16 = 8;
pub const T_MR: u16 = 9;
pub const T_NULL: u16 = 10;
pub const T_WKS: u16 = 11;
pub const T_PTR: u16 = 12;
pub const T_HINFO: u16 = 13;
pub const T_MINFO: u16 = 14;
pub const T_MX: u16 = 15;
pub const T_TXT: u16 = 16;
pub const T_RP: u16 = 17;
pub const T_AFSDB: u16 = 18;
pub const T_X25: u16 = 19;
pub const T_ISDN: u16 = 20;
pub const T_RT: u16 = 21;
pub const T_NSAP: u16 = 22;
pub const T_SIG: u16 = 24;
pub const T_KEY: u16 = 25;
pub const T_PX: u16 = 26;
pub const T_GPOS: u16 = 27;
pub const T_AAAA: u16 = 28;
pub const T_LOC: u16 = 29;
pub const T_NXT: u16 = 30;
pub const T_SRV: u16 = 33;
pub const T_NAPTR: u16 = 35;
pub const T_KX: u16 = 36;
pub const T_CERT: u16 = 37;
pub const T_DNAME: u16 = 39;
pub const T_OPT: u16 = 41;
pub const T_APL: u16 = 42;
pub const T_DS: u16 = 43;
pub const T_SSHFP: u16 = 44;
pub const T_RRSIG: u16 = 46;
pub const T_NSEC: u16 = 47;
pub const T_DNSKEY: u16 = 48;
pub const T_NSEC3: u16 = 50;
pub const T_TKEY: u16 = 249;
pub const T_TSIG: u16 = 250;
pub const T_AXFR: u16 = 252;
pub const T_MAILB: u16 = 253;
pub const T_MAILA: u16 = 254;
pub const T_ANY: u16 = 255;
pub const T_CAA: u16 = 257;

// ---------------------------------------------------------------------------
// 头部控制位（dns-protocol.h 头部宏）
// ---------------------------------------------------------------------------
pub const HB3_QR: u8 = 0x80;
pub const HB3_OPCODE: u8 = 0x78;
pub const HB3_AA: u8 = 0x04;
pub const HB3_TC: u8 = 0x02;
pub const HB3_RD: u8 = 0x01;

pub const HB4_RA: u8 = 0x80;
pub const HB4_AD: u8 = 0x20;
pub const HB4_CD: u8 = 0x10;
pub const HB4_RCODE: u8 = 0x0f;

/// 头部各字段的偏移（wire 格式固定）
pub const OFF_ID: usize = 0;
pub const OFF_HB3: usize = 2;
pub const OFF_HB4: usize = 3;
pub const OFF_QDCOUNT: usize = 4;
pub const OFF_ANCOUNT: usize = 6;
pub const OFF_NSCOUNT: usize = 8;
pub const OFF_ARCOUNT: usize = 10;
pub const HEADER_SIZE: usize = 12;

/// 名字转义字符：'.' 与 '\0' 在 C 字符串表示里不合法，dnsmasq 用 \001 前缀转义
pub const NAME_ESCAPE: u8 = 1;

pub inline fn isNameEscape(c: u8) bool {
    return c == 0 or c == '.' or c == NAME_ESCAPE;
}

// ---------------------------------------------------------------------------
// cache 记录标志（dnsmasq.h:515-546，节选 DNS 相关部分）
// ---------------------------------------------------------------------------
pub const F_IMMORTAL: u32 = 1 << 0;
pub const F_NAMEP: u32 = 1 << 1;
pub const F_REVERSE: u32 = 1 << 2;
pub const F_FORWARD: u32 = 1 << 3;
pub const F_DHCP: u32 = 1 << 4;
pub const F_NEG: u32 = 1 << 5;
pub const F_HOSTS: u32 = 1 << 6;
pub const F_IPV4: u32 = 1 << 7;
pub const F_IPV6: u32 = 1 << 8;
pub const F_BIGNAME: u32 = 1 << 9;
pub const F_NXDOMAIN: u32 = 1 << 10;
pub const F_CNAME: u32 = 1 << 11;
pub const F_DNSKEY: u32 = 1 << 12;
pub const F_CONFIG: u32 = 1 << 13;
pub const F_DS: u32 = 1 << 14;
pub const F_DNSSECOK: u32 = 1 << 15;
pub const F_UPSTREAM: u32 = 1 << 16;
pub const F_RRNAME: u32 = 1 << 17;
pub const F_SERVER: u32 = 1 << 18;
pub const F_QUERY: u32 = 1 << 19;
pub const F_NOERR: u32 = 1 << 20;
pub const F_AUTH: u32 = 1 << 21;
pub const F_DNSSEC: u32 = 1 << 22;
pub const F_KEYTAG: u32 = 1 << 23;
pub const F_SECSTAT: u32 = 1 << 24;
pub const F_NO_RR: u32 = 1 << 25;
pub const F_IPSET: u32 = 1 << 26;
pub const F_NOEXTRA: u32 = 1 << 27;
pub const F_DOMAINSRV: u32 = 1 << 28;
pub const F_RCODE: u32 = 1 << 29;
pub const F_RR: u32 = 1 << 30;
pub const F_STALE: u32 = 1 << 31;

/// 用于比较的“记录种类”掩码（cache_lookup 用）
pub const F_CACHED: u32 = F_FORWARD | F_REVERSE;
pub const F_HOSTS_MASK: u32 = F_HOSTS | F_DHCP | F_CONFIG;

// ---------------------------------------------------------------------------
// 上游服务器标志（dnsmasq.h: struct server.flags）
// ---------------------------------------------------------------------------
pub const SERV_USE_RESOLV: u16 = 1;
pub const SERV_LITERAL_ADDRESS: u16 = 2;
pub const SERV_ALL_ZEROS: u16 = 4;
pub const SERV_4ADDR: u16 = 8;
pub const SERV_6ADDR: u16 = 16;
pub const SERV_HAS_SOURCE: u16 = 32;
pub const SERV_FOR_NODOTS: u16 = 64;
pub const SERV_WARNED_RECURSIVE: u16 = 128;
pub const SERV_FROM_DBUS: u16 = 256;
pub const SERV_MARK: u16 = 512;
pub const SERV_WILDCARD: u16 = 1024;
pub const SERV_FROM_RESOLV: u16 = 2048;
pub const SERV_FROM_FILE: u16 = 4096;
pub const SERV_LOOP: u16 = 8192;
pub const SERV_DO_DNSSEC: u16 = 16384;
pub const SERV_GOT_TCP: u16 = 32768;

// ---------------------------------------------------------------------------
// 配置项标志（dnsmasq.h 中 OPT_*，DNS 部分节选）
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// 运行时开关位（对应 dnsmasq.h 的 #define OPT_xxx）
//
// 编号与 C 版本**完全一致**：位序号就是常量值。dnsmasq 用
//     #define option_var(x) (daemon->options[(x) / 32])
//     #define option_val(x) ((1u) << ((x) % 32))
//     #define option_bool(x) (option_var(x) & option_val(x))
// 所以这里同样用 options[3] 位图（OPT_LAST = 80）。
// 新增开关时请直接照抄 dnsmasq.h 的编号，不要另起一套。
// ---------------------------------------------------------------------------
pub const OPT_BOGUSPRIV: u32 = 0;
pub const OPT_FILTER: u32 = 1;
pub const OPT_LOG: u32 = 2;
pub const OPT_SELFMX: u32 = 3;
pub const OPT_NO_HOSTS: u32 = 4;
pub const OPT_NO_POLL: u32 = 5;
pub const OPT_DEBUG: u32 = 6;
pub const OPT_ORDER: u32 = 7;
pub const OPT_NO_RESOLV: u32 = 8;
pub const OPT_EXPAND: u32 = 9;
pub const OPT_LOCALMX: u32 = 10;
pub const OPT_NO_NEG: u32 = 11;
pub const OPT_NODOTS_LOCAL: u32 = 12;
pub const OPT_NOWILD: u32 = 13;
pub const OPT_ETHERS: u32 = 14;
pub const OPT_RESOLV_DOMAIN: u32 = 15;
pub const OPT_NO_FORK: u32 = 16;
pub const OPT_AUTHORITATIVE: u32 = 17;
pub const OPT_LOCALISE: u32 = 18;
pub const OPT_DBUS: u32 = 19;
pub const OPT_DHCP_FQDN: u32 = 20;
pub const OPT_NO_PING: u32 = 21;
pub const OPT_LEASE_RO: u32 = 22;
pub const OPT_ALL_SERVERS: u32 = 23;
pub const OPT_RELOAD: u32 = 24;
pub const OPT_LOCAL_REBIND: u32 = 25;
pub const OPT_TFTP_SECURE: u32 = 26;
pub const OPT_TFTP_NOBLOCK: u32 = 27;
pub const OPT_LOG_OPTS: u32 = 28;
pub const OPT_TFTP_APREF_IP: u32 = 29;
pub const OPT_NO_OVERRIDE: u32 = 30;
pub const OPT_NO_REBIND: u32 = 31;
pub const OPT_ADD_MAC: u32 = 32;
pub const OPT_DNSSEC_PROXY: u32 = 33;
pub const OPT_CONSEC_ADDR: u32 = 34;
pub const OPT_CONNTRACK: u32 = 35;
pub const OPT_FQDN_UPDATE: u32 = 36;
pub const OPT_RA: u32 = 37;
pub const OPT_TFTP_LC: u32 = 38;
pub const OPT_CLEVERBIND: u32 = 39;
pub const OPT_TFTP: u32 = 40;
pub const OPT_CLIENT_SUBNET: u32 = 41;
pub const OPT_QUIET_DHCP: u32 = 42;
pub const OPT_QUIET_DHCP6: u32 = 43;
pub const OPT_QUIET_RA: u32 = 44;
pub const OPT_DNSSEC_VALID: u32 = 45;
pub const OPT_DNSSEC_TIME: u32 = 46;
pub const OPT_DNSSEC_DEBUG: u32 = 47;
pub const OPT_DNSSEC_IGN_NS: u32 = 48;
pub const OPT_LOCAL_SERVICE: u32 = 49;
pub const OPT_LOOP_DETECT: u32 = 50;
pub const OPT_EXTRALOG: u32 = 51;
pub const OPT_TFTP_NO_FAIL: u32 = 52;
pub const OPT_SCRIPT_ARP: u32 = 53;
pub const OPT_MAC_B64: u32 = 54;
pub const OPT_MAC_HEX: u32 = 55;
pub const OPT_TFTP_APREF_MAC: u32 = 56;
pub const OPT_RAPID_COMMIT: u32 = 57;
pub const OPT_UBUS: u32 = 58;
pub const OPT_IGNORE_CLID: u32 = 59;
pub const OPT_SINGLE_PORT: u32 = 60;
pub const OPT_LEASE_RENEW: u32 = 61;
pub const OPT_LOG_DEBUG: u32 = 62;
pub const OPT_UMBRELLA: u32 = 63;
pub const OPT_UMBRELLA_DEVID: u32 = 64;
pub const OPT_CMARK_ALST_EN: u32 = 65;
pub const OPT_QUIET_TFTP: u32 = 66;
pub const OPT_STRIP_ECS: u32 = 67;
pub const OPT_STRIP_MAC: u32 = 68;
pub const OPT_NORR: u32 = 69;
pub const OPT_NO_IDENT: u32 = 70;
pub const OPT_CACHE_RR: u32 = 71;
pub const OPT_LOCALHOST_SERVICE: u32 = 72;
pub const OPT_LOG_PROTO: u32 = 73;
pub const OPT_NO_0x20: u32 = 74;
pub const OPT_DO_0x20: u32 = 75;
pub const OPT_AUTH_LOG: u32 = 76;
pub const OPT_LEASEQUERY: u32 = 77;
pub const OPT_LOG_ONLY_FAILED: u32 = 78;
pub const OPT_LOG_MALLOC: u32 = 79;
pub const OPT_LAST: u32 = 80;

/// options 位图的字数（对应 OPTION_SIZE）
pub const OPTION_BITS: u32 = 32;
pub const OPTION_WORDS: usize = (OPT_LAST / OPTION_BITS) + @intFromBool((OPT_LAST % OPTION_BITS) != 0);

/// 对应 option_val(x) / option_var(x)
pub inline fn optBit(opt: u32) u32 {
    return @as(u32, 1) << @intCast(opt % OPTION_BITS);
}

/// 解析位序号（用于 --help 与调试输出）
pub fn optName(opt: u32) ?[]const u8 {
    return switch (opt) {
        OPT_BOGUSPRIV => "bogus-priv",
        OPT_FILTER => "filterwin2k",
        OPT_LOG => "log-queries",
        OPT_SELFMX => "selfmx",
        OPT_NO_HOSTS => "no-hosts",
        OPT_NO_POLL => "no-poll",
        OPT_DEBUG => "debug",
        OPT_ORDER => "strict-order",
        OPT_NO_RESOLV => "no-resolv",
        OPT_EXPAND => "expand-hosts",
        OPT_LOCALMX => "localmx",
        OPT_NO_NEG => "no-negcache",
        OPT_NODOTS_LOCAL => "domain-needed",
        OPT_NOWILD => "nowild",
        OPT_NO_FORK => "no-daemon",
        OPT_AUTHORITATIVE => "authoritative",
        OPT_LOCALISE => "localise-queries",
        OPT_NO_PING => "no-ping",
        OPT_ALL_SERVERS => "all-servers",
        OPT_NO_REBIND => "stop-dns-rebind",
        OPT_DNSSEC_VALID => "dnssec",
        OPT_DNSSEC_TIME => "dnssec-debug",
        OPT_DNSSEC_DEBUG => "dnssec-debug",
        OPT_LOCAL_SERVICE => "local-service",
        OPT_LOOP_DETECT => "dns-loop-detect",
        OPT_EXTRALOG => "log-extra",
        OPT_NORR => "no-round-robin",
        OPT_CACHE_RR => "cache-rr",
        OPT_LOG_PROTO => "log-protocol",
        OPT_AUTH_LOG => "auth-log",
        else => null,
    };
}
/// 本地应答默认 TTL
pub const LOCAL_TTL: u32 = 0;
pub const NEG_TTL: u32 = 3600;
pub const AUTH_TTL: u32 = 600;
pub const MAXTTL_BOUND: u32 = 604800;

// ---------------------------------------------------------------------------
// config.h 中的运行常量（括号内为 C 源码位置）
// ---------------------------------------------------------------------------
/// config.h: CACHESIZ —— 默认缓存条数
pub const CACHESIZ: usize = 150;
/// config.h: EDNS_PKTSZ —— EDNS0 默认 UDP 报文上限（/dnsflagday.net/2020 推荐值）
pub const EDNS_PKTSZ: u16 = 1232;
/// 本移植内部使用：EDNS OPT 记录里宣告的接收缓冲大小（等价 daemon->edns_pktsz 的默认值）
pub const OPT_PKTSZ: u16 = EDNS_PKTSZ;
/// config.h: CNAME_CHAIN —— CNAME 链最大长度，超过则丢弃（防环）
pub const CNAME_CHAIN: usize = 10;
/// config.h: FTABSIZ —— 并发转发请求默认上限
pub const FTABSIZ: usize = 150;
/// config.h: TIMEOUT —— UDP 查询超时（秒）。这是**一次查询的总预算**，
/// 不是「单台上游的等待时间」。
pub const TIMEOUT: u32 = 10;
/// config.h: DEFAULT_FAST_RETRY —— 单台上游的等待时间（毫秒）。
///
/// dnsmasq 默认（未开 --fast-dns-retry）会一直等到 TIMEOUT 才换服务器；
/// 打开后每 1000ms 就换一台上游重试，在 TIMEOUT 内可以试很多台。
/// 本移植从压测出发默认启用这个语义：把 10s 总预算按「每台 1s」切分，
/// 否则一台挂掉的上游会让每个查询都白等 10s/候选数。
pub const DEFAULT_FAST_RETRY_MS: i32 = 1000;
/// --fast-dns-retry 允许的最小值（对齐 option.c:3559 的 retry < 50 检查）
pub const MIN_FAST_RETRY_MS: i32 = 50;
/// --fast-dns-retry 允许的最大值（毫秒）
pub const MAX_FAST_RETRY_MS: i32 = 30_000;
/// config.h: TCP_TIMEOUT —— 连接上游 TCP 的超时（秒）。
/// 注意：等待 TCP 应答的时间是它的两倍（见 dnsmasq 注释）。
pub const TCP_TIMEOUT: u32 = 5;
/// 便于直接用作毫秒超时
pub const TCP_TIMEOUT_MS: i32 = @intCast(TCP_TIMEOUT * 1000);
/// config.h: FORWARD_TEST / FORWARD_TIME —— 上游服务器健康度复检周期
pub const FORWARD_TEST: u64 = 50;
pub const FORWARD_TIME: u64 = 20;

// ---------------------------------------------------------------------------
// 多上游并发查询（本移植扩展，dnsmasq 无对应常量）
//
// dnsmasq 是单线程事件循环，所以「同时发给多台上游、谁先回来用谁」是天然行为
// （见 forward.c:511-570 的 forwardall 机制）。本移植用线程池 + 每查询一个
// 处理线程，因此需要在线程内部用 poll 把多台 socket 一起等，才能达到同样效果。
// ---------------------------------------------------------------------------
/// 一次并发竞速最多同时持有的上游 socket 数
pub const MAX_CONCURRENT_UPSTREAMS: usize = 8;
/// 一次转发最多纳入的候选服务器数
pub const MAX_FORWARD_CANDIDATES: usize = 16;
/// --concurrent-servers 的上限
pub const MAX_CONCURRENT_OPT: usize = 64;
/// --hedge-after 允许的最大值（毫秒）
pub const MAX_HEDGE_MS: i32 = 5000;

// ---------------------------------------------------------------------------
// 动态负载均衡参数（本移植扩展）
// ---------------------------------------------------------------------------
/// 熔断触发阈值：连续失败达到该次数即进入冷却
pub const SERVER_FAIL_THRESHOLD: u32 = 3;
/// 熔断基准冷却时长（毫秒），实际按失败次数退避
pub const SERVER_COOLDOWN_DEFAULT_MS: i64 = 1000;
/// 熔断冷却上限（毫秒）。
///
/// 压测教训：这个值曾经是 60s，结果是「上游恢复后长时间收不到任何流量」——
/// 因为冷却中的上游会被 usable() 整段排除，只要还有别的上游能答就永远轮不到它。
/// 冷却应该是「短暂隔离」而非「长期放逐」，因此封顶放到秒级。
pub const SERVER_COOLDOWN_MAX_MS: i64 = 4000;
/// 退避的最大倍率指数（2 表示最多 4 倍基准）。
/// 指数退避在「上游整体故障」时会变成惩罚放大器，这里保持温和。
pub const SERVER_COOLDOWN_BACKOFF_MAX: u6 = 2;
/// --server-cooldown 选项允许的最大值（毫秒）。
/// 比 SERVER_COOLDOWN_MAX_MS 宽：后者是「默认配置下的总封顶」，
/// 而显式配置的基准值应当被尊重（总封顶会按 base 的 4 倍自动放宽）。
pub const SERVER_COOLDOWN_OPT_MAX_MS: i64 = 60_000;
/// EWMA 的时间衰减常数（毫秒）。
///
/// 被冷落的上游采样机会很少，若只用固定平滑系数（1/2^SHIFT），一个陈旧的高
/// 延迟估计要十几个样本才能被拉回来 —— 而它本来就没几次采样机会，等于「上游
/// 变快了」这件事要很久才反映出来。
///
/// 因此权重取「固定平滑」与「时间衰减」两者中较大的那个：
///     alpha = max(1/2^EWMA_ALPHA_SHIFT, dt / (dt + EWMA_TAU_MS))
///   * 样本密集（hot 上游，dt 几毫秒）：退化回固定 1/8 平滑，抑制抖动优先
///   * 样本稀疏（被冷落的上游，dt 几百毫秒）：新样本权重显著提高
///   * 间隔超过 5*tau：视为「旧估计已失效」，直接采用新样本
pub const EWMA_TAU_MS: u64 = 300;
/// 动态策略的「探索预算」：被冷落的上游每被跳过这么多次查询，就获得一次
/// 重采样机会（此时它的打分被临时视为最优）。
///
/// 为什么按查询次数而不是按挂钟时间：探测开销必须与查询量成比例。
///   * 按时间（早期实现是「距上次采样超过 3s 就给一次探测」）会有两个毛病：
///       流量大时重采样太稀疏 —— 每次探测要等 3 秒，而上游从 150ms 变快
///       到 1ms 需要好几次探测，实测重适应要 15 秒才收敛；
///       流量小时又太频繁 —— 每秒只有几笔查询时，陈旧的慢上游会把每一笔
///       查询都抢走，延迟最优性荡然无存。
///   * 按次数则天然自适应：每 50 笔查询里最多有 1 笔用于探测某台被冷落的
///     上游（4 台全被冷落时上限 8% 流量），而 240qps 下每台每 200ms
///     就能重采样一次，重适应在 1~2 秒内完成。
pub const SERVER_PROBE_GAP: u64 = 40;

/// 半开探测间隔（毫秒）：处于冷却期的上游，每隔这么久放行一次探测查询。
///
/// 熔断器的标准「half-open」语义：不靠时钟到期被动恢复，而是主动探测。
/// 冷却期到点只是「可以恢复」，而有流量经过才真的恢复 —— 若冷却期一过就
/// 无条件回流，长时间没有流量的上游会永远停留在「冷却已过但没人用」的状态
/// （压测阶段 3/4 就是这个现象）。探测频率远低于正常流量，不会打爆抖动上游。
pub const SERVER_PROBE_INTERVAL_MS: i64 = 500;
/// EWMA 权重：新样本占比 1/8（经典 TCP SRTT 的做法）
pub const EWMA_ALPHA_SHIFT: u6 = 3;
/// config.h: UDP_TEST_TIME —— 复位「最大报文尺寸」认知的间隔（秒）
pub const UDP_TEST_TIME: u32 = 60;
/// config.h: SMALLDNAME —— 大多数域名小于该长度
pub const SMALLDNAME: usize = 75;

// ---------------------------------------------------------------------------
// 字节序读写（对应 rfc1035.c 的 get/put_short/long 宏）
// ---------------------------------------------------------------------------
pub inline fn getShort(p: []const u8, off: usize) u16 {
    return (@as(u16, p[off]) << 8) | @as(u16, p[off + 1]);
}

pub inline fn getLong(p: []const u8, off: usize) u32 {
    return (@as(u32, p[off]) << 24) | (@as(u32, p[off + 1]) << 16) |
        (@as(u32, p[off + 2]) << 8) | @as(u32, p[off + 3]);
}

pub inline fn putShort(p: []u8, off: usize, v: u16) void {
    p[off] = @truncate(v >> 8);
    p[off + 1] = @truncate(v);
}

pub inline fn putLong(p: []u8, off: usize, v: u32) void {
    p[off] = @truncate(v >> 24);
    p[off + 1] = @truncate(v >> 16);
    p[off + 2] = @truncate(v >> 8);
    p[off + 3] = @truncate(v);
}

// ---------------------------------------------------------------------------
// 头部访问（对应 struct dns_header + 宏）
// ---------------------------------------------------------------------------
pub inline fn headerId(p: []const u8) u16 {
    return getShort(p, OFF_ID);
}

pub inline fn headerHb3(p: []const u8) u8 {
    return p[OFF_HB3];
}

pub inline fn headerHb4(p: []const u8) u8 {
    return p[OFF_HB4];
}

pub inline fn qdcount(p: []const u8) u16 {
    return getShort(p, OFF_QDCOUNT);
}

pub inline fn ancount(p: []const u8) u16 {
    return getShort(p, OFF_ANCOUNT);
}

pub inline fn nscount(p: []const u8) u16 {
    return getShort(p, OFF_NSCOUNT);
}

pub inline fn arcount(p: []const u8) u16 {
    return getShort(p, OFF_ARCOUNT);
}

pub inline fn setQdcount(p: []u8, v: u16) void {
    putShort(p, OFF_QDCOUNT, v);
}

pub inline fn setAncount(p: []u8, v: u16) void {
    putShort(p, OFF_ANCOUNT, v);
}

pub inline fn setNscount(p: []u8, v: u16) void {
    putShort(p, OFF_NSCOUNT, v);
}

pub inline fn setArcount(p: []u8, v: u16) void {
    putShort(p, OFF_ARCOUNT, v);
}

// 头部位操作（对应 HB3_/HB4_ 宏）
pub inline fn isResponse(hb3: u8) bool {
    return (hb3 & HB3_QR) != 0;
}

pub inline fn opcode(hb3: u8) u8 {
    return (hb3 & HB3_OPCODE) >> 3;
}

pub inline fn rcode(hb4: u8) u8 {
    return hb4 & HB4_RCODE;
}

pub inline fn setOpcode(hb3: *u8, code: u8) void {
    hb3.* = (hb3.* & ~HB3_OPCODE) | ((code & 0x0f) << 3);
}

pub inline fn setRcode(hb4: *u8, code: u8) void {
    hb4.* = (hb4.* & ~HB4_RCODE) | (code & HB4_RCODE);
}

/// 对应 header->id 的写入（PUTSHORT(header->id, ...)）
pub inline fn setId(p: []u8, id: u16) void {
    putShort(p, OFF_ID, id);
}

/// 名字压缩指针标志
pub const NAME_PTR_MASK: u8 = 0xC0;
/// 扩展 label（DNSSEC 用）
pub const NAME_EXT_MASK: u8 = 0x40;

/// RR 类型的短名，对应 cache.c 的 `typestr[]` 表（日志里用）。
/// 表中没有的类型返回 null。
pub fn rrTypeName(t: u16) ?[]const u8 {
    return switch (t) {
        T_A => "A",
        T_NS => "NS",
        T_MD => "MD",
        T_MF => "MF",
        T_CNAME => "CNAME",
        T_SOA => "SOA",
        T_MB => "MB",
        T_MG => "MG",
        T_MR => "MR",
        T_NULL => "NULL",
        T_WKS => "WKS",
        T_PTR => "PTR",
        T_HINFO => "HINFO",
        T_MINFO => "MINFO",
        T_MX => "MX",
        T_TXT => "TXT",
        T_RP => "RP",
        T_AFSDB => "AFSDB",
        T_X25 => "X25",
        T_ISDN => "ISDN",
        T_RT => "RT",
        T_NSAP => "NSAP",
        T_SIG => "SIG",
        T_KEY => "KEY",
        T_PX => "PX",
        T_GPOS => "GPOS",
        T_AAAA => "AAAA",
        T_LOC => "LOC",
        T_NXT => "NXT",
        T_SRV => "SRV",
        T_NAPTR => "NAPTR",
        T_KX => "KX",
        T_CERT => "CERT",
        T_DNAME => "DNAME",
        T_OPT => "OPT",
        T_APL => "APL",
        T_DS => "DS",
        T_SSHFP => "SSHFP",
        T_RRSIG => "RRSIG",
        T_NSEC => "NSEC",
        T_DNSKEY => "DNSKEY",
        T_NSEC3 => "NSEC3",
        T_TKEY => "TKEY",
        T_TSIG => "TSIG",
        T_AXFR => "AXFR",
        T_MAILB => "MAILB",
        T_MAILA => "MAILA",
        T_ANY => "ANY",
        T_CAA => "CAA",
        else => null,
    };
}

test "protocol byte helpers" {
    var buf: [8]u8 = undefined;
    putShort(&buf, 0, 0x1234);
    try std.testing.expectEqual(@as(u16, 0x1234), getShort(&buf, 0));
    putLong(&buf, 0, 0xdeadbeef);
    try std.testing.expectEqual(@as(u32, 0xdeadbeef), getLong(&buf, 0));

    var hdr: [12]u8 = [_]u8{0} ** 12;
    setQdcount(&hdr, 1);
    try std.testing.expectEqual(@as(u16, 1), qdcount(&hdr));
    var hb3: u8 = 0;
    setOpcode(&hb3, OPCODE_QUERY);
    try std.testing.expectEqual(OPCODE_QUERY, opcode(hb3));
}
