#!/usr/bin/env python3
"""验证「多线程查询」确实并行。

思路：让假上游对每个请求故意慢 300ms 才应答（模拟慢上游 / 丢包重试），
然后并发发 N 个**互不相同**的域名（不能命中缓存）。
* 单线程串行：总耗时 ≈ N × 300ms
* 4 线程并行：总耗时 ≈ N/4 × 300ms（约 4 倍加速）

同时统计上游侧观察到的「同时在处理的请求数」峰值，若 > 1 即证明真并行。
"""
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

UPSTREAM_PORT = 15354
SERVER = ("127.0.0.1", 15353)
DELAY = 0.30          # 每个上游请求的处理耗时
N = 16                # 并发查询数

inflight = 0
peak = 0
lock = threading.Lock()


def build_reply(query: bytes, ip: str) -> bytes:
    tid = struct.unpack("!H", query[:2])[0]
    p = 12
    while query[p] != 0:
        p += 1 + query[p]
    p += 1
    qend = p + 4
    hdr = struct.pack("!HHHHHH", tid, 0x8180, 1, 1, 0, 0)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    return hdr + query[12:qend] + answer


def upstream_loop(sock: socket.socket, stop: threading.Event):
    global inflight, peak
    while not stop.is_set():
        try:
            sock.settimeout(0.3)
            data, peer = sock.recvfrom(4096)
        except socket.timeout:
            continue
        except OSError:
            return
        with lock:
            inflight += 1
            peak = max(peak, inflight)
        # 在工作线程里慢处理，好让别的请求同时进来
        threading.Timer(DELAY, _delayed_reply, args=(sock, peer, data, stop)).start()


def _delayed_reply(sock, peer, data, stop):
    global inflight
    with lock:
        inflight -= 1
    if stop.is_set():
        return
    try:
        sock.sendto(build_reply(data, "9.9.9.9"), peer)
    except OSError:
        pass


def encode_name(name: str) -> bytes:
    out = b""
    for part in name.split("."):
        if part:
            out += bytes([len(part)]) + part.encode()
    return out + b"\x00"


def query(name):
    msg = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    msg += encode_name(name) + struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(15)
    s.sendto(msg, SERVER)
    data, _ = s.recvfrom(4096)
    s.close()
    return data


def main():
    stop = threading.Event()
    up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    up.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    up.bind(("127.0.0.1", UPSTREAM_PORT))
    threading.Thread(target=upstream_loop, args=(up, stop), daemon=True).start()
    time.sleep(0.2)

    # 让缓存先热起来，避免首个请求把缓存填充的耗时算进来
    names = [f"h{i}.slow.test" for i in range(N)]

    t0 = time.time()
    with ThreadPoolExecutor(max_workers=N) as ex:
        outs = list(ex.map(query, names))
    dt = time.time() - t0

    ok = all(len(o) > 12 and struct.unpack("!H", o[:2])[0] == 0x1234 for o in outs)

    # 串行基准：单线程（--threads=1）时理论耗时
    serial = N * DELAY
    speedup = serial / dt if dt else 0

    print(f"并发 {N} 个查询，上游每个慢 {DELAY*1000:.0f}ms")
    print(f"  全部应答成功      : {'是' if ok else '否'}")
    print(f"  上游侧并行峰值     : {peak}")
    print(f"  实际总耗时         : {dt*1000:.0f} ms")
    print(f"  单线程理论耗时     : {serial*1000:.0f} ms")
    print(f"  加速比             : {speedup:.1f}x")

    stop.set()
    up.close()

    good = ok and peak > 1 and speedup > 1.8
    print(f"\n=== 结论: {'多线程查询生效' if good else '未观察到并行（检查 --threads）'} ===")
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
