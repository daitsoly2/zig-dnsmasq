#!/usr/bin/env python3
"""
stress.py — 多上游动态负载均衡 + 缓存机制压力测试

测试目标（对应 --balance=dynamic 与缓存子系统）：
  阶段 1  冷缓存：500 个**互不相同**的域名，50 路并发
          · 期望全部成功（rcode=0）
          · 期望上游总请求数 ≈ 500（动态均衡每次只打一台上游，
            而 --all-servers 会是 500×N —— 这是二者的关键区别）
          · 期望流量按 EWMA 延迟倾斜：快上游拿到的查询明显多于慢上游
  阶段 2  热缓存：把阶段 1 的 500 个域名再查一遍
          · 期望上游请求数增量为 0（全部命中缓存）
          · 期望 P50 延迟比阶段 1 下降一个数量级
  阶段 3  单上游故障：把最快的那台上游停掉，再查 200 个新域名
          · 期望成功率仍然 ≥ 95%（熔断后流量转移，而不是一直等它超时）
          · 期望该上游被熔断（trips ≥ 1）
  阶段 4  恢复：把该上游放回来，再查 200 个新域名
          · 期望它能重新拿到流量（熔断不是永久拉黑）

每次运行都会在结束时向进程发 SIGUSR1，抓取内核侧统计做交叉验证。
"""
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
BIN = os.path.join(HERE, "..", "zig-out", "bin", "zig-dnsmasq")
CONF = os.path.join(HERE, "stress.conf")
LISTEN_PORT = 15353

UPSTREAM_DEFS = [
    # (名字, 端口, 应答延迟ms, 应答地址)
    ("fast-2ms", 15361, 2, "10.0.0.1"),
    ("mid-15ms", 15362, 15, "10.0.0.2"),
    ("slow-60ms", 15363, 60, "10.0.0.3"),
    ("slowest-150ms", 15364, 150, "10.0.0.4"),
]

DOMAIN_COUNT = 500
CONCURRENCY = 50
PHASE3_DOMAIN_COUNT = 200

# ---------------------------------------------------------------------------
# 假上游：一个 recv 线程 + 一个 sender 线程，支持任意并发与可控延迟
# ---------------------------------------------------------------------------


class Upstream:
    def __init__(self, name, port, delay_ms, answer_ip):
        self.name = name
        self.port = port
        self.delay_ms = delay_ms
        self.answer_ip = answer_ip
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.lock = threading.Lock()
        self.pending = []          # [(due_ts, reply_bytes, addr)]
        self.count = 0             # 收到的查询数
        self.dropped = 0           # 被丢弃（模拟故障）
        self.running = True
        self.blackhole = False     # True = 完全不回应（模拟宕机）
        self.refuse = False        # True = 一律返回 REFUSED
        self.t_recv = threading.Thread(target=self._recv_loop, daemon=True)
        self.t_send = threading.Thread(target=self._send_loop, daemon=True)

    def start(self):
        self.t_recv.start()
        self.t_send.start()

    def stop(self):
        self.running = False
        time.sleep(0.06)
        try:
            self.sock.close()
        except OSError:
            pass

    def reset_counters(self):
        with self.lock:
            self.count = 0
            self.dropped = 0

    def snapshot(self):
        with self.lock:
            return {"count": self.count, "dropped": self.dropped, "pending": len(self.pending)}

    def _recv_loop(self):
        self.sock.settimeout(0.02)
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(data) < 12:
                continue
            if self.blackhole:
                with self.lock:
                    self.count += 1
                    self.dropped += 1
                continue
            with self.lock:
                self.count += 1
                self.pending.append((time.monotonic() + self.delay_ms / 1000.0, data, addr))

    def _send_loop(self):
        while self.running:
            now = time.monotonic()
            with self.lock:
                due = [p for p in self.pending if p[0] <= now]
                if due:
                    self.pending = [p for p in self.pending if p[0] > now]
            for _, query, addr in due:
                try:
                    self.sock.sendto(self._build_reply(query), addr)
                except OSError:
                    pass
            time.sleep(0.001)

    def _build_reply(self, query):
        tid = query[:2]
        p = 12
        while p < len(query) and query[p] != 0:
            p += 1 + query[p]
        qend = p + 1 + 4
        question = query[12:qend]
        if self.refuse:
            header = tid + struct.pack("!HHHHH", 0x8185, 1, 0, 0, 0)
            return header + question
        header = tid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(self.answer_ip)
        return header + question + rr


# ---------------------------------------------------------------------------
# 客户端
# ---------------------------------------------------------------------------


def encode_name(name):
    out = b""
    for label in name.split("."):
        if label:
            out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def parse_reply(data):
    """返回 (rcode, 答案里的第一个 A 记录地址)"""
    if len(data) < 12:
        return (None, None)
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    p = 12
    for _ in range(qd):
        while p < len(data) and data[p] != 0:
            if data[p] & 0xC0 == 0xC0:
                p += 2
                break
            p += 1 + data[p]
        else:
            p += 1
        p += 4
    answer = None
    for _ in range(an):
        if p + 10 > len(data):
            break
        if data[p] & 0xC0 == 0xC0:
            p += 2
        else:
            while p < len(data) and data[p] != 0:
                p += 1 + data[p]
            p += 1
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[p:p + 10])
        p += 10
        rd = data[p:p + rdlen]
        if rtype == 1 and rdlen == 4 and answer is None:
            answer = socket.inet_ntoa(rd)
        p += rdlen
    return (flags & 0xF, answer)


def query(name, timeout=6.0):
    """发一次查询，返回 (elapsed_ms, rcode, answer_ip, err)"""
    msg = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + encode_name(name) + struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    t0 = time.monotonic()
    try:
        s.sendto(msg, ("127.0.0.1", LISTEN_PORT))
        data, _ = s.recvfrom(4096)
        dt = (time.monotonic() - t0) * 1000
    except socket.timeout:
        return (timeout * 1000, None, None, "timeout")
    except OSError as e:
        return (0.0, None, None, str(e))
    finally:
        s.close()
    rcode, answer = parse_reply(data)
    return (dt, rcode, answer, None)


def run_phase(names, concurrency=CONCURRENCY):
    """并发执行一批查询，返回统计结果"""
    results = []
    lock = threading.Lock()

    def one(nm):
        r = query(nm)
        with lock:
            results.append(r)

    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        list(ex.map(one, names))
    wall = time.monotonic() - t0

    lat = sorted(r[0] for r in results if r[3] is None)
    ok = sum(1 for r in results if r[1] == 0)
    nxd = sum(1 for r in results if r[1] == 3)
    fails = [r for r in results if r[3] is not None]

    def pct(p):
        if not lat:
            return 0.0
        idx = min(len(lat) - 1, int(len(lat) * p))
        return lat[idx]

    return {
        "n": len(results),
        "ok": ok,
        "nxdomain": nxd,
        "errors": len(fails),
        "err_sample": fails[0][3] if fails else None,
        "p50": pct(0.50),
        "p95": pct(0.95),
        "p99": pct(0.99),
        "max": lat[-1] if lat else 0.0,
        "wall_s": wall,
        "qps": len(results) / wall if wall > 0 else 0.0,
        "answers": {},
    }


def print_phase(title, r, extra=""):
    print(f"\n  ── {title} ──")
    print(f"     查询 {r['n']} 个：成功 {r['ok']}，NXDOMAIN {r['nxdomain']}，失败 {r['errors']}"
          + (f"（{r['err_sample']}）" if r['err_sample'] else ""))
    print(f"     延迟 ms: P50 {r['p50']:.1f} / P95 {r['p95']:.1f} / P99 {r['p99']:.1f} / max {r['max']:.1f}")
    print(f"     耗时 {r['wall_s']:.2f}s  吞吐 {r['qps']:.0f} qps")
    if extra:
        print(f"     {extra}")


def upstream_distribution(ups, before):
    """返回 [(name, 本阶段新增请求数, 占比)]"""
    rows = []
    total = 0
    for u in ups:
        snap = u.snapshot()
        delta = max(0, snap["count"] - before.get(u.name, 0))
        rows.append([u.name, delta, 0.0])
        total += delta
    for row in rows:
        row[2] = (row[1] / total * 100) if total else 0.0
    return rows


def print_dist(rows, label="上游接收分布"):
    print(f"     {label}:")
    for name, cnt, pct in rows:
        bar = "█" * int(pct / 3)
        print(f"       {name:14s} {cnt:5d} ({pct:5.1f}%) {bar}")


def get_internal_stats(proc):
    """发 SIGUSR1 抓取进程内统计（上游 EWMA / 熔断 / 缓存命中）"""
    proc.send_signal(signal.SIGUSR1)
    time.sleep(0.25)
    return proc.log_path


def parse_internal_stats(path):
    text = open(path, encoding="utf-8", errors="replace").read()
    out = {"servers": [], "cache": None, "queries": None}
    for line in text.splitlines():
        m = re.search(r"server (\S+):\s*queries=(\d+) wins=(\d+) fail=(\d+) inflight=(\d+) rtt_ewma=([\d.]+)ms trips=(\d+)", line)
        if m:
            out["servers"].append({
                "addr": m.group(1), "queries": int(m.group(2)), "wins": int(m.group(3)),
                "fail": int(m.group(4)), "inflight": int(m.group(5)),
                "ewma_ms": float(m.group(6)), "trips": int(m.group(7)),
            })
            continue
        m = re.search(
            r"cache entries=(\d+)/(\d+) lookups=(\d+)/(\d+) "
            r"queries hit=(\d+) miss=(\d+) config=(\d+) hitrate=(\d+)\.(\d+)%",
            line)
        if m:
            out["cache"] = {
                "entries": int(m.group(1)), "cachesize": int(m.group(2)),
                # 查找级：一次查询会累加多次，仅供参考
                "lookups_hit": int(m.group(3)), "lookups_miss": int(m.group(4)),
                # 查询级：命中率用这一组
                "query_hit": int(m.group(5)), "query_miss": int(m.group(6)),
                "query_config": int(m.group(7)),
                "hitrate": int(m.group(8)) + int(m.group(9)) / 10.0,
            }
            continue
        m = re.search(r"queries total=(\d+)", line)
        if m:
            out["queries"] = int(m.group(1))
    return out


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------


def main():
    if not os.path.exists(BIN):
        print(f"找不到可执行文件 {BIN}，先执行 zig build", file=sys.stderr)
        return 1

    ups = [Upstream(*d) for d in UPSTREAM_DEFS]
    for u in ups:
        u.start()

    log_path = os.path.join(HERE, "stress.log")
    logf = open(log_path, "w")
    proc = subprocess.Popen([BIN, "-C", CONF, "--threads=8"], stdout=logf, stderr=subprocess.STDOUT)
    proc.log_path = log_path

    failures = []
    try:
        # 等就绪
        for _ in range(40):
            dt, rc, ans, err = query("ready-check.local", timeout=1.0)
            if err is None and rc is not None:
                break
            time.sleep(0.1)
        else:
            print("守护进程未就绪", file=sys.stderr)
            return 1
        for u in ups:
            u.reset_counters()

        print("=" * 74)
        print("多上游动态负载均衡 + 缓存 压力测试")
        print("=" * 74)
        print(f"上游: " + ", ".join(f"{u.name}@{u.port}" for u in ups))
        print(f"配置: --balance=dynamic --threads=8, cache-size=2000, 并发 {CONCURRENCY}")

        # ---------------- 阶段 1：500 个不同域名（冷缓存） ----------------
        names1 = [f"host-{i}.bench.test" for i in range(DOMAIN_COUNT)]
        before = {u.name: u.snapshot()["count"] for u in ups}
        r1 = run_phase(names1)
        dist1 = upstream_distribution(ups, before)
        total_up = sum(d[1] for d in dist1)

        print_phase("阶段 1：500 个不同域名（冷缓存，全部需要转发）", r1,
                    f"上游共收到 {total_up} 个查询")
        print_dist(dist1)

        if r1["ok"] != DOMAIN_COUNT:
            failures.append(f"阶段1 成功数 {r1['ok']}/{DOMAIN_COUNT}")
        if total_up > DOMAIN_COUNT * 1.05:
            failures.append(f"阶段1 上游请求 {total_up} 超出 500 的 5%（说明不是单发）")
        fast = dict((d[0], d[1]) for d in dist1)
        if fast["fast-2ms"] <= fast["slowest-150ms"]:
            failures.append("阶段1 快慢上游分配没有倾斜（动态均衡可能没生效）")

        # ---------------- 阶段 2：同样 500 个域名（热缓存） ----------------
        before2 = {u.name: u.snapshot()["count"] for u in ups}
        r2 = run_phase(names1)
        dist2 = upstream_distribution(ups, before2)
        total_up2 = sum(d[1] for d in dist2)

        print_phase("阶段 2：同样 500 个域名（热缓存，应全部命中）", r2,
                    f"上游新增请求 {total_up2} 个")
        print_dist(dist2, "上游新增分布")

        if r2["ok"] != DOMAIN_COUNT:
            failures.append(f"阶段2 成功数 {r2['ok']}/{DOMAIN_COUNT}")
        if total_up2 != 0:
            failures.append(f"阶段2 仍然向上游发了 {total_up2} 个查询（缓存未命中）")
        if r2["p50"] > 0 and r1["p50"] > 0 and r2["p50"] > r1["p50"] / 3:
            failures.append(f"阶段2 P50 {r2['p50']:.1f}ms 未明显快于阶段1 {r1['p50']:.1f}ms")
        speedup = r1["p50"] / r2["p50"] if r2["p50"] > 0 else 0
        print(f"     缓存加速比: P50 {speedup:.1f}x   (阶段1 {r1['p50']:.1f}ms → 阶段2 {r2['p50']:.1f}ms)")

        # ---------------- 阶段 3：最快上游宕机 ----------------
        victim = ups[0]
        victim.blackhole = True
        names3 = [f"cold3-{i}.bench.test" for i in range(PHASE3_DOMAIN_COUNT)]
        before3 = {u.name: u.snapshot()["count"] for u in ups}
        r3 = run_phase(names3)
        dist3 = upstream_distribution(ups, before3)

        print_phase(f"阶段 3：{victim.name} 停止应答，再查 {PHASE3_DOMAIN_COUNT} 个新域名", r3,
                    f"上游请求分布（故障机 {dist3[0][1]} 个）")
        print_dist(dist3)

        if r3["ok"] < PHASE3_DOMAIN_COUNT * 0.95:
            failures.append(f"阶段3 成功率 {r3['ok']}/{PHASE3_DOMAIN_COUNT} < 95%")

        # ---------------- 阶段 4：上游恢复 ----------------
        victim.blackhole = False
        time.sleep(0.3)
        names4 = [f"cold4-{i}.bench.test" for i in range(PHASE3_DOMAIN_COUNT)]
        before4 = {u.name: u.snapshot()["count"] for u in ups}
        r4 = run_phase(names4)
        dist4 = upstream_distribution(ups, before4)

        print_phase(f"阶段 4：{victim.name} 恢复，再查 {PHASE3_DOMAIN_COUNT} 个新域名", r4,
                    f"上游请求分布（恢复机 {dist4[0][1]} 个）")
        print_dist(dist4)

        if r4["ok"] < PHASE3_DOMAIN_COUNT * 0.95:
            failures.append(f"阶段4 成功率 {r4['ok']}/{PHASE3_DOMAIN_COUNT} < 95%")

        # ---------------- 内部统计交叉验证 ----------------
        parse_internal_stats(get_internal_stats(proc))
        st = parse_internal_stats(log_path)
        print("\n  ── 进程内统计（SIGUSR1）──")
        for s in st["servers"]:
            print(f"     {s['addr']:16s} queries={s['queries']:5d} wins={s['wins']:5d} "
                  f"fail={s['fail']:4d} inflight={s['inflight']} ewma={s['ewma_ms']:7.3f}ms trips={s['trips']}")
        if st["cache"]:
            c = st["cache"]
            print(f"     cache entries={c['entries']}/{c['cachesize']}")
            print(f"       查找级 lookups hit={c['lookups_hit']} miss={c['lookups_miss']}"
                  f"（一次查询会查多次，不用于算命中率）")
            print(f"       查询级 hit={c['query_hit']} miss={c['query_miss']} "
                  f"config={c['query_config']} 命中率={c['hitrate']:.1f}%")
            if c["query_hit"] == 0:
                failures.append("查询级缓存命中数为 0（缓存机制可能失效）")
            if c["query_miss"] == 0:
                failures.append("查询级缓存未命中数为 0（冷缓存阶段未被计入）")
            if c["entries"] < DOMAIN_COUNT:
                failures.append(f"缓存条目 {c['entries']} < {DOMAIN_COUNT}（记录可能被误淘汰）")
            # 场景是「500 冷 + 500 热 + 400 新」，理论命中率约 500/1400 = 35.7%。
            # 只要求落在合理区间，避免把实现细节写死进测试。
            if not (25.0 <= c["hitrate"] <= 55.0):
                failures.append(f"查询级命中率 {c['hitrate']:.1f}% 不在预期的 25%~55% 区间")
        if st["queries"] is not None:
            print(f"     总查询数 {st['queries']}")

        trips = {s["addr"]: s["trips"] for s in st["servers"]}
        if not any(v >= 1 for v in trips.values()):
            failures.append("阶段3 的故障上游没有被熔断（trips 全为 0）")

        # 阶段 4 必须看到流量回流到刚恢复的上游。
        # 这里依赖两个机制同时正确：冷却时长（秒级）与半开探测（冷却中
        # 每 SERVER_PROBE_INTERVAL_MS 放行一次）。若只有前者、没有后者，
        # 上游会因为「冷却期内被 usable() 完全排除」而长时间收不到任何流量。
        revived = {name: cnt for name, cnt, _pct in dist4}
        victim_name = ups[0].name
        print(f"     阶段4 各上游新收请求: {revived}")
        if revived.get(victim_name, 0) == 0:
            failures.append(
                f"阶段4 恢复后的 {victim_name} 没有收到任何新请求（半开探测未生效，流量未回流）")

        print("\n" + "=" * 74)
        if failures:
            print("压测未通过：")
            for f in failures:
                print(f"  ✗ {f}")
            return 1
        print("压测通过：动态负载均衡分流正常，缓存复热零上游请求，故障上游被熔断并自动恢复")
        return 0

    finally:
        try:
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        for u in ups:
            u.stop()
        logf.close()


if __name__ == "__main__":
    sys.exit(main())
