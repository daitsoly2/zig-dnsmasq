#!/usr/bin/env python3
"""zig-dnsmasq 端到端验证。

起一个假上游（127.0.0.1:15354），然后向 zig-dnsmasq（127.0.0.1:15353）
发真实 DNS 报文，逐条核对 dnsmasq 的语义。
"""
import concurrent.futures
import socket
import struct
import sys
import threading
import time

UPSTREAM_PORT = 15354
SERVER_PORT = 15353
SERVER = ("127.0.0.1", SERVER_PORT)

UPSTREAM = {
    "forward.test": "1.2.3.4",
    "cache.test": "5.6.7.8",
}
upstream_hits = []
stop_flag = threading.Event()


def build_reply(query: bytes) -> bytes:
    tid = struct.unpack("!H", query[:2])[0]
    p = 12
    labels = []
    while query[p] != 0:
        ln = query[p]
        labels.append(query[p + 1:p + 1 + ln].decode())
        p += 1 + ln
    qname = ".".join(labels)
    p += 1
    qtype, qclass = struct.unpack("!HH", query[p:p + 4])
    qend = p + 4

    ip = UPSTREAM.get(qname)
    if ip is None:
        return struct.pack("!HHHHHH", tid, 0x8183, 1, 0, 0, 0) + query[12:qend]
    hdr = struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return hdr + query[12:qend] + answer


def upstream_loop(sock: socket.socket):
    while not stop_flag.is_set():
        try:
            sock.settimeout(0.3)
            data, peer = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            return
        upstream_hits.append(data)
        sock.sendto(build_reply(data), peer)


def encode_name(name: str) -> bytes:
    out = b""
    for part in name.split("."):
        if part:
            out += bytes([len(part)]) + part.encode()
    return out + b"\x00"


def query(name, qtype=1, timeout=5.0):
    msg = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    msg += encode_name(name) + struct.pack("!HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(msg, SERVER)
    data, _ = s.recvfrom(4096)
    s.close()
    return data


def _read_name(data, p):
    labels = []
    hops = 0
    end = None
    while True:
        if data[p] & 0xC0 == 0xC0:
            # 压缩指针：只跳转一次，并记住「指针之后」的位置
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


def parse_answer(data):
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    rcode = flags & 0xF
    p = 12
    for _ in range(qd):
        _, p = _read_name(data, p)
        p += 4
    rrs = []
    for _ in range(an):
        _, p = _read_name(data, p)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[p:p + 10])
        rd = data[p + 10:p + 10 + rdlen]
        p += 10 + rdlen
        if rtype == 1:
            val = socket.inet_ntoa(rd)
        elif rtype == 28:
            val = socket.inet_ntop(socket.AF_INET6, rd)
        elif rtype in (5, 12):
            val, _ = _read_name(data, p - rdlen)
        else:
            val = rd.hex()
        rrs.append((rtype, val, ttl))
    return rcode, rrs


results = []


def check(desc, ok, detail=""):
    results.append((desc, ok, detail))
    print(f"[{'PASS' if ok else 'FAIL'}] {desc}" + (f"   -> {detail}" if detail else ""), flush=True)


def main():
    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    up.bind(("127.0.0.1", UPSTREAM_PORT))
    threading.Thread(target=upstream_loop, args=(up,), daemon=True).start()
    time.sleep(0.2)

    rcode, rrs = parse_answer(query("zigtest.local"))
    check("hosts 正查 zigtest.local -> 10.1.2.3",
          rcode == 0 and any(v == "10.1.2.3" for _, v, _ in rrs), str(rrs))

    rcode, rrs = parse_answer(query("alias.zigtest.local"))
    check("hosts 别名 alias.zigtest.local -> 10.1.2.3",
          rcode == 0 and any(v == "10.1.2.3" for _, v, _ in rrs), str(rrs))

    rcode, rrs = parse_answer(query("ipv6.local", 28))
    check("hosts IPv6 正查 ipv6.local -> fd00::1",
          rcode == 0 and any(v == "fd00::1" for _, v, _ in rrs), str(rrs))

    rcode, rrs = parse_answer(query("3.2.1.10.in-addr.arpa", 12))
    check("hosts 反查 10.1.2.3 -> zigtest.local",
          rcode == 0 and any(v.startswith("zigtest.local") for _, v, _ in rrs), str(rrs))

    rcode, rrs = parse_answer(query("ads.local"))
    check("address=/ads.local/0.0.0.0 -> 0.0.0.0",
          rcode == 0 and any(v == "0.0.0.0" for _, v, _ in rrs), str(rrs))

    rcode, rrs = parse_answer(query("blocked.local"))
    check("local=/blocked.local/ -> NXDOMAIN", rcode == 3, f"rcode={rcode}")

    rcode, rrs = parse_answer(query("nodots"))
    check("domain-needed: 'nodots' -> NXDOMAIN", rcode == 3, f"rcode={rcode}")

    before = len(upstream_hits)
    rcode, rrs = parse_answer(query("forward.test"))
    check("转发 forward.test -> 1.2.3.4（来自上游）",
          rcode == 0 and any(v == "1.2.3.4" for _, v, _ in rrs), str(rrs))
    hits1 = len(upstream_hits)
    check("第一次查询确实打到了上游", hits1 > before, f"hits {before} -> {hits1}")

    rcode, rrs = parse_answer(query("forward.test"))
    hits2 = len(upstream_hits)
    check("第二次查询命中缓存（上游计数不变）",
          rcode == 0 and any(v == "1.2.3.4" for _, v, _ in rrs) and hits2 == hits1,
          f"hits {hits1} -> {hits2}")

    rcode, rrs = parse_answer(query("doesnotexist.test"))
    check("上游 NXDOMAIN 透传", rcode == 3, f"rcode={rcode}")

    rcode, rrs = parse_answer(query("nothing.local"))
    check("未配置的 local 域名走默认上游（NXDOMAIN）", rcode == 3, f"rcode={rcode}")

    # TCP
    msg = struct.pack("!HHHHHH", 0x5678, 0x0100, 1, 0, 0, 0)
    msg += encode_name("zigtest.local") + struct.pack("!HH", 1, 1)
    ts = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ts.settimeout(4)
    ts.connect(SERVER)
    ts.sendall(struct.pack("!H", len(msg)) + msg)
    total = struct.unpack("!H", ts.recv(2))[0]
    buf = b""
    while len(buf) < total:
        buf += ts.recv(total - len(buf))
    ts.close()
    rcode, rrs = parse_answer(buf)
    check("TCP 查询 zigtest.local -> 10.1.2.3",
          rcode == 0 and any(v == "10.1.2.3" for _, v, _ in rrs), str(rrs))

    # TCP 跨段重组：把「长度前缀 + 正文」拆成每次 3 字节多次发送（必然跨多个 TCP 段），
    # 守护进程必须自己拼装完整 —— 对应 C 的 read_write()「读满 len 字节才返回」语义。
    msg2 = struct.pack("!HHHHHH", 0x5679, 0x0100, 1, 0, 0, 0)
    msg2 += encode_name("zigtest.local") + struct.pack("!HH", 1, 1)
    payload = struct.pack("!H", len(msg2)) + msg2
    ts2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ts2.settimeout(6)
    ts2.connect(SERVER)
    for i in range(0, len(payload), 3):
        ts2.sendall(payload[i:i + 3])
        time.sleep(0.02)
    total2 = struct.unpack("!H", ts2.recv(2))[0]
    buf2 = b""
    while len(buf2) < total2:
        buf2 += ts2.recv(total2 - len(buf2))
    ts2.close()
    rcode2, rrs2 = parse_answer(buf2)
    check("TCP 跨段重组（拆成 3 字节多次发送）-> 10.1.2.3",
          rcode2 == 0 and any(v == "10.1.2.3" for _, v, _ in rrs2), str(rrs2))

    before = len(upstream_hits)
    names = ["zigtest.local"] * 20 + ["forward.test"] * 20
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        outs = list(ex.map(lambda n: parse_answer(query(n)), names))
    served_ok = all(rc == 0 and rrs for rc, rrs in outs)
    hits = len(upstream_hits) - before
    check(f"40 个并发查询全部成功（forward.test 命中缓存，新增上游请求 {hits}）",
          served_ok and hits == 0, f"hits={hits}")

    stop_flag.set()
    up.close()

    failed = [r for r in results if not r[1]]
    print(f"\n=== 结果: {len(results) - len(failed)}/{len(results)} 通过 ===", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
