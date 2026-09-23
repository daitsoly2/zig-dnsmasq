#!/usr/bin/env python3
"""zig-dnsmasq 异步转发引擎端到端验证。

与 e2e.py 的区别：那个验证的是 dnsmasq 的**语义**，这个验证的是异步引擎的
**并发模型**与**收尾正确性**。重点覆盖本地假上游测不出来的东西：

  1. 并发度 —— 慢上游下，N 个并发查询的总耗时应该 ≈ 单个 RTT，而不是 N/线程数 × RTT。
     这是整个改造的核心指标。
  2. 共享上游 socket + txid 解复用的正确性 —— 大并发下每个应答必须回到它自己的
     客户端，且 txid 必须被还原成客户端原始值（拿名字派生的 IP 逐条核对）。
  3. 多 A 记录全部应答（实机曾发现缓存命中后只回第一条）。
  4. CNAME 链：CNAME + 目标 A 都要在应答里，且命中缓存后依然完整。
  5. UDP 截断 -> 自动改走 TCP 上游。
  6. TCP 客户端查询的完整路径（引擎接管连接，非阻塞读写）。
  7. 上游完全不应答 -> SERVFAIL；上游 REFUSED -> 透传。
"""
import concurrent.futures
import os
import select
import socket
import struct
import sys
import threading
import time

UP_PORT = 15355
SRV_PORT = 15353
SERVER = ("127.0.0.1", SRV_PORT)

# 慢上游：每个 slowN.test 延迟这么久才应答
DELAY = 0.4
# 并发度测试用的查询条数
CONC_N = 100

stop_flag = threading.Event()
upstream_hits = []
hits_lock = threading.Lock()

MULTI_IPS = ["1.1.1.1", "1.1.1.2", "1.1.1.3"]
TRUNC_IPS = ["2.2.2.1", "2.2.2.2", "2.2.2.3", "2.2.2.4"]


# 查询类型常量（避免到处写魔法数字）
class protocol_qtype:
    A = 1
    NS = 2
    CNAME = 5
    SOA = 6
    PTR = 12
    MX = 15
    TXT = 16
    AAAA = 28
    SRV = 33
    ANY = 255


# ---------------------------------------------------------------------------
# 报文构造 / 解析
# ---------------------------------------------------------------------------
def encode_name(name: str) -> bytes:
    out = b""
    for part in name.split("."):
        if part:
            out += bytes([len(part)]) + part.encode()
    return out + b"\x00"


def parse_question(query: bytes):
    tid = struct.unpack("!H", query[:2])[0]
    p = 12
    labels = []
    while query[p] != 0:
        ln = query[p]
        labels.append(query[p + 1:p + 1 + ln].decode("latin-1"))
        p += 1 + ln
    p += 1
    qtype, qclass = struct.unpack("!HH", query[p:p + 4])
    return tid, ".".join(labels), qtype, query[12:p + 4]


def rr_ptr(ip: str) -> bytes:
    return b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)


def rr_a_own(name: str, ip: str) -> bytes:
    return encode_name(name) + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)


def rr_cname(target: str) -> bytes:
    rd = encode_name(target)
    return b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(rd)) + rd


def rr_mx(pref: int, host: str) -> bytes:
    rd = struct.pack("!H", pref) + encode_name(host)
    return b"\xc0\x0c" + struct.pack("!HHIH", 15, 1, 60, len(rd)) + rd


def rr_aaaa_own(name: str, ip6: str) -> bytes:
    rd = socket.inet_pton(socket.AF_INET6, ip6)
    return encode_name(name) + struct.pack("!HHIH", 28, 1, 60, len(rd)) + rd


def make_reply(query: bytes, tc: bool = False, answers=None, rcode: int = 0) -> bytes:
    tid, qname, _qtype, question = parse_question(query)
    if answers is None:
        answers = []
    flags = 0x8180 | (rcode & 0xF)
    if tc:
        flags |= 0x0200
    hdr = struct.pack("!HHHHHH", tid, flags, 1, len(answers), 0, 0)
    return hdr + question + b"".join(answers)


def slow_ip(idx: int) -> str:
    return f"10.0.{(idx >> 8) & 0xFF}.{idx & 0xFF}"


def decide(query: bytes, over_tcp: bool):
    """返回 (reply_bytes or None, delay_seconds)。None 表示故意不应答。"""
    _tid, qname, qtype, _q = parse_question(query)

    if qname == "multi.test":
        return make_reply(query, answers=[rr_ptr(ip) for ip in MULTI_IPS]), 0.0

    if qname == "mixed.test":
        # 同一个名字、不同查询类型必须各答各的。
        # 回归背景：实机（ImmortalWrt 上的 dnsmasq 2.90）A/B 对比发现，缓存查找
        # 误把 F_FORWARD 掺进类型掩码，交集判空导致 AAAA 查询命中 A 记录、
        # MX 查询命中已缓存的 A 记录后回 NODATA。本地套件只查 A，看不到这个问题。
        if qtype == protocol_qtype.A:
            return make_reply(query, answers=[rr_ptr("1.1.1.1")]), 0.0
        if qtype == protocol_qtype.AAAA:
            return make_reply(query, answers=[rr_aaaa_own(qname, "2001:db8::1")]), 0.0
        if qtype == protocol_qtype.MX:
            return make_reply(query, answers=[rr_mx(10, "mail.mixed.test")]), 0.0
        # 其余类型回 NODATA
        return make_reply(query), 0.0

    if qname == "cname.test":
        return make_reply(query, answers=[rr_cname("target.test")] + [rr_ptr("9.9.9.9")]), 0.0

    if qname == "trunc.test":
        if over_tcp:
            return make_reply(query, answers=[rr_ptr(ip) for ip in TRUNC_IPS]), 0.0
        # UDP 上故意截断：置 TC 位、不带任何记录，逼客户端改走 TCP
        return make_reply(query, tc=True), 0.0

    if qname == "dead.test":
        return None, 0.0

    if qname == "refused.test":
        return make_reply(query, rcode=5), 0.0  # REFUSED

    if qname.startswith("slow") and qname.endswith(".test"):
        try:
            idx = int(qname[4:-5])
        except ValueError:
            idx = 0
        return make_reply(query, answers=[rr_ptr(slow_ip(idx))]), DELAY

    return make_reply(query, rcode=3), 0.0  # NXDOMAIN


# ---------------------------------------------------------------------------
# 假上游：UDP 侧用「非阻塞 + 定时发送队列」实现并发延迟，避免慢查询互相阻塞
# ---------------------------------------------------------------------------
class FakeUpstream:
    def __init__(self):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.bind(("127.0.0.1", UP_PORT))
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("127.0.0.1", UP_PORT))
        self.tcp.listen(16)

    def udp_loop(self):
        scheduled = []  # (due, peer, payload)
        self.udp.setblocking(False)
        while not stop_flag.is_set():
            now = time.time()
            keep = []
            for due, peer, payload in scheduled:
                if due <= now:
                    try:
                        self.udp.sendto(payload, peer)
                    except OSError:
                        pass
                else:
                    keep.append((due, peer, payload))
            scheduled = keep

            r, _, _ = select.select([self.udp], [], [], 0.005)
            if r:
                try:
                    data, peer = self.udp.recvfrom(4096)
                except OSError:
                    continue
                with hits_lock:
                    upstream_hits.append(data)
                reply, delay = decide(data, over_tcp=False)
                if reply is None:
                    continue
                scheduled.append((time.time() + delay, peer, reply))
            elif not scheduled:
                time.sleep(0.002)

    def tcp_loop(self):
        self.tcp.settimeout(0.3)
        while not stop_flag.is_set():
            try:
                conn, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._serve_tcp, args=(conn,), daemon=True).start()

    def _serve_tcp(self, conn):
        try:
            conn.settimeout(5)
            hdr = self._recv_exact(conn, 2)
            if not hdr:
                return
            plen = struct.unpack("!H", hdr)[0]
            msg = self._recv_exact(conn, plen)
            if not msg:
                return
            with hits_lock:
                upstream_hits.append(msg)
            reply, _delay = decide(msg, over_tcp=True)
            if reply is None:
                return
            conn.sendall(struct.pack("!H", len(reply)) + reply)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _recv_exact(conn, n):
        buf = b""
        while len(buf) < n:
            try:
                chunk = conn.recv(n - len(buf))
            except OSError:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf


# ---------------------------------------------------------------------------
# 客户端
# ---------------------------------------------------------------------------
def udp_query(name, qtype=1, timeout=8.0, tid=0x1234):
    msg = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    msg += encode_name(name) + struct.pack("!HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, SERVER)
        data, _ = s.recvfrom(4096)
    finally:
        s.close()
    return data


def tcp_query(name, qtype=1, timeout=8.0, tid=0x4321):
    msg = struct.pack("!HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    msg += encode_name(name) + struct.pack("!HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect(SERVER)
    s.sendall(struct.pack("!H", len(msg)) + msg)
    hdr = FakeUpstream._recv_exact(s, 2)
    total = struct.unpack("!H", hdr)[0]
    buf = FakeUpstream._recv_exact(s, total)
    s.close()
    return buf


def read_name(data, p):
    labels = []
    hops = 0
    end = None
    while True:
        if data[p] & 0xC0 == 0xC0:
            if end is None:
                end = p + 2
            p = ((data[p] & 0x3F) << 8) | data[p + 1]
            hops += 1
            if hops > 20:
                break
            continue
        ln = data[p]
        if ln == 0:
            if end is None:
                end = p + 1
            break
        labels.append(data[p + 1:p + 1 + ln].decode("latin-1"))
        p += 1 + ln
    return ".".join(labels), end


def parse(data):
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0xF
    tc = bool(flags & 0x0200)
    p = 12
    qname = ""
    for _ in range(qd):
        qname, p = read_name(data, p)
        p += 4
    rrs = []
    for _ in range(an):
        owner, p = read_name(data, p)
        rtype, _rclass, ttl, rdlen = struct.unpack("!HHIH", data[p:p + 10])
        rd_off = p + 10
        p += 10 + rdlen
        if rtype == 1:
            val = socket.inet_ntoa(data[rd_off:rd_off + 4])
        elif rtype == 28:
            val = socket.inet_ntop(socket.AF_INET6, data[rd_off:rd_off + 16])
        elif rtype == 5:
            val, _ = read_name(data, rd_off)
        elif rtype == 15:
            pref = struct.unpack("!H", data[rd_off:rd_off + 2])[0]
            host, _ = read_name(data, rd_off + 2)
            val = f"{pref} {host}"
        else:
            val = data[rd_off:rd_off + rdlen].hex()
        rrs.append((owner, rtype, val))
    return dict(tid=tid, rcode=rcode, tc=tc, qname=qname, rrs=rrs, raw=data)


results = []


def check(desc, ok, detail=""):
    results.append((desc, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {desc}" + (f"   -> {detail}" if detail else ""), flush=True)


def hits():
    with hits_lock:
        return len(upstream_hits)


def a_values(rrs):
    return [v for (_o, t, v) in rrs if t == 1]


def main():
    up = FakeUpstream()
    threading.Thread(target=up.udp_loop, daemon=True).start()
    threading.Thread(target=up.tcp_loop, daemon=True).start()
    time.sleep(0.3)

    # ---- 1. 多 A 记录：冷查询与缓存命中都要完整 ----
    before = hits()
    r = parse(udp_query("multi.test"))
    ok = r["rcode"] == 0 and sorted(a_values(r["rrs"])) == sorted(MULTI_IPS)
    check("多 A 记录冷查询全部返回（3 条）", ok, f"rcode={r['rcode']} A={a_values(r['rrs'])}")
    check("冷查询确实打到了上游", hits() > before, f"hits {before} -> {hits()}")

    h1 = hits()
    r = parse(udp_query("multi.test"))
    ok = r["rcode"] == 0 and sorted(a_values(r["rrs"])) == sorted(MULTI_IPS)
    check("多 A 记录缓存命中仍返回全部 3 条", ok and hits() == h1,
          f"A={a_values(r['rrs'])} hits={hits() - h1}")

    # ---- 2. CNAME 链 ----
    r = parse(udp_query("cname.test"))
    cnames = [v for (_o, t, v) in r["rrs"] if t == 5]
    ok = r["rcode"] == 0 and cnames and "9.9.9.9" in a_values(r["rrs"])
    check("CNAME 链：应答同时含 CNAME 与目标 A", ok,
          f"rcode={r['rcode']} CNAME={cnames} A={a_values(r['rrs'])}")

    h1 = hits()
    r = parse(udp_query("cname.test"))
    cnames = [v for (_o, t, v) in r["rrs"] if t == 5]
    ok = r["rcode"] == 0 and cnames and "9.9.9.9" in a_values(r["rrs"])
    check("CNAME 链命中缓存后仍完整（不丢目标）", ok and hits() == h1,
          f"CNAME={cnames} A={a_values(r['rrs'])}")

    # ---- 3. txid 还原 ----
    r = parse(udp_query("multi.test", tid=0xABCD))
    check("应答 txid 还原成客户端原始值", r["tid"] == 0xABCD, f"tid={r['tid']:#x}")

    # ---- 3b. 同一名字的不同查询类型必须互不串台 ----
    # 这一组是实机 A/B 对比（ImmortalWrt 上 dnsmasq 2.90 vs 本移植）才暴露出来的：
    # 缓存查找把 F_FORWARD 掺进了类型掩码，而匹配是「交集判空」，于是
    #   * AAAA 查询命中已缓存的 A 记录 -> 用 IPv4 地址回答 AAAA
    #   * MX 查询命中已缓存的 A 记录 -> 回 NODATA（“这个域名没有 MX”）
    # 两种都是「应答看起来正常、内容却错」的静默错误。
    h0 = hits()
    r = parse(udp_query("mixed.test", qtype=protocol_qtype.A))
    a_rrs = [v for (_o, t, v) in r["rrs"] if t == protocol_qtype.A]
    check("混合类型：A 冷查询返回 A 记录", r["rcode"] == 0 and a_rrs == ["1.1.1.1"] and hits() > h0,
          f"A={a_rrs} 上游 {h0} -> {hits()}")

    r = parse(udp_query("mixed.test", qtype=protocol_qtype.AAAA))
    aaaa_rrs = [v for (_o, t, v) in r["rrs"] if t == protocol_qtype.AAAA]
    v4_in_aaaa = [v for (_o, t, v) in r["rrs"] if t == protocol_qtype.A]
    check("混合类型：AAAA 查询不得用 A 记录充数",
          r["rcode"] == 0 and aaaa_rrs == ["2001:db8::1"] and not v4_in_aaaa,
          f"AAAA={aaaa_rrs} 混入的A={v4_in_aaaa}")

    r = parse(udp_query("mixed.test", qtype=protocol_qtype.MX))
    mx_rrs = [v for (_o, t, v) in r["rrs"] if t == protocol_qtype.MX]
    check("混合类型：MX 查询不得被已缓存的 A 记录压成 NODATA",
          r["rcode"] == 0 and mx_rrs == ["10 mail.mixed.test"],
          f"MX={mx_rrs} ancount={len(r['rrs'])}")

    # 三种类型各自独立记账：
    #   A / AAAA 是地址记录，会写进缓存 -> 第二轮上游命中应为 0；
    #   MX 是「非地址记录」，与 dnsmasq 一致不进缓存 -> 第二轮必然再打一次上游。
    # 断言必须按类型分别验证，不能笼统地要求「上游命中不变」，否则会把
    # dnsmasq 本身的设计当成缺陷。
    hm = hits()
    m1 = parse(udp_query("mixed.test", qtype=protocol_qtype.A))
    d_a = hits() - hm
    m2 = parse(udp_query("mixed.test", qtype=protocol_qtype.AAAA))
    d_aaaa = hits() - hm - d_a
    m3 = parse(udp_query("mixed.test", qtype=protocol_qtype.MX))
    d_mx = hits() - hm - d_a - d_aaaa

    ok = (d_a == 0 and d_aaaa == 0 and d_mx == 1
          and m1["rcode"] == 0 and m2["rcode"] == 0 and m3["rcode"] == 0
          and [v for (_o, t, v) in m1["rrs"] if t == protocol_qtype.A] == ["1.1.1.1"]
          and [v for (_o, t, v) in m2["rrs"] if t == protocol_qtype.AAAA] == ["2001:db8::1"]
          and [v for (_o, t, v) in m3["rrs"] if t == protocol_qtype.MX] == ["10 mail.mixed.test"])
    check("混合类型：A/AAAA 各自命中缓存、MX 按 dnsmasq 语义不缓存", ok,
          f"上游增量 A={d_a} AAAA={d_aaaa} MX={d_mx}")

    # ---- 4. UDP 截断 -> TCP 上游回退 ----
    r = parse(udp_query("trunc.test"))
    ok = r["rcode"] == 0 and sorted(a_values(r["rrs"])) == sorted(TRUNC_IPS) and not r["tc"]
    check("UDP 截断应答自动改走 TCP 上游（拿到 4 条 A）", ok,
          f"rcode={r['rcode']} tc={r['tc']} A={a_values(r['rrs'])}")

    # ---- 5. TCP 客户端查询（引擎接管连接）----
    r = parse(tcp_query("multi.test"))
    ok = r["rcode"] == 0 and sorted(a_values(r["rrs"])) == sorted(MULTI_IPS)
    check("TCP 客户端查询走完整异步路径", ok, f"rcode={r['rcode']} A={a_values(r['rrs'])}")

    r = parse(tcp_query("trunc.test"))
    ok = r["rcode"] == 0 and sorted(a_values(r["rrs"])) == sorted(TRUNC_IPS)
    check("TCP 客户端查询 + 上游截断回退", ok, f"A={a_values(r['rrs'])}")

    # ---- 6. 上游不应答 -> SERVFAIL；REFUSED -> 透传 ----
    t0 = time.time()
    r = parse(udp_query("dead.test", timeout=12))
    dt = time.time() - t0
    check("上游完全不应答 -> SERVFAIL", r["rcode"] == 2, f"rcode={r['rcode']} 耗时={dt:.2f}s")

    r = parse(udp_query("refused.test"))
    check("上游 REFUSED 透传", r["rcode"] == 5, f"rcode={r['rcode']}")

    # ---- 7. 并发度：这是整个改造的核心指标 ----
    names = [f"slow{i}.test" for i in range(CONC_N)]
    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=CONC_N) as ex:
        outs = list(ex.map(lambda n: parse(udp_query(n, timeout=20)), names))
    dt = time.time() - t0

    mismatched = []
    for i, (n, o) in enumerate(zip(names, outs)):
        want = slow_ip(i)
        got = a_values(o["rrs"])
        if o["rcode"] != 0 or got != [want]:
            mismatched.append((n, o["rcode"], got, want))

    ideal = DELAY
    bound = CONC_N / 8 * DELAY  # 8 个阻塞线程时的理论下限
    check(f"{CONC_N} 个并发查询在 {dt:.2f}s 内全部完成（单 RTT={ideal}s，阻塞模型下限≈{bound:.1f}s）",
          dt < bound * 0.5 and not mismatched,
          f"耗时={dt:.2f}s 加速比≈{bound / dt:.1f}x 错配={len(mismatched)}")
    if mismatched:
        print("   前 3 条错配:", mismatched[:3], flush=True)

    # ---- 8. 同一时间窗内并发命中同一批名字（共享 socket 上的多路复用）----
    # 交错发 40 条「不同名但同一上游 socket」的快速查询，检查无串台
    fast_names = [f"n{i}.test" for i in range(40)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as ex:
        outs = list(ex.map(lambda n: (n, parse(udp_query(n))), fast_names))
    bad = [n for n, o in outs if o["rcode"] != 3]
    check("40 条并发 NXDOMAIN 查询互不串台（共享 socket 多路复用）", not bad, f"异常={bad[:5]}")

    stop_flag.set()
    time.sleep(0.2)
    try:
        up.udp.close()
        up.tcp.close()
    except OSError:
        pass

    failed = [r for r in results if not r[1]]
    print(f"\n=== 结果: {len(results) - len(failed)}/{len(results)} 通过 ===", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
