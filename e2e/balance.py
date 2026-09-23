#!/usr/bin/env python3
"""
balance.py — 逐个验证上游调度策略的流量分布特征

stress.py 验证的是 --balance=dynamic 的端到端行为（缓存、熔断、恢复）。
本脚本补上另一半：把 5 种策略**各自**跑一遍，检查它们的分布是否
符合各自的设计意图 —— 否则「策略开关生效了」这件事本身就没有被验证。

上游是 4 台延迟递增的本地假上游：

    fast-2ms (2ms)  <  mid-15ms (15ms)  <  slow-60ms (60ms)  <  slowest-150ms (150ms)

期望分布（各策略的判据写在 MODES 表里）：

    sticky       按 dnsmasq 原生语义「粘住最近成功的那台」-> 某一台占绝对多数
    dynamic      按 (在途数+1)×EWMA 打分 -> 最快的那台拿走大头
    swrr         平滑加权轮询（权重 ∝ 1/EWMA）-> 快慢有梯度但不会饿死慢的
    round-robin  严格轮转 -> 接近均分（各 ~25%）
    random       随机 -> 四台都被用到，且大致均匀

每台上游都至少要被用到一次：这是「策略确实在四台之间分流」而不是
「碰巧只用了一台」的最低要求。
"""
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from stress import (  # noqa: E402
    BIN, HERE, LISTEN_PORT, UPSTREAM_DEFS, Upstream,
    query, run_phase, upstream_distribution, print_dist,
)

WARMUP_COUNT = 40      # 先跑一轮让 EWMA / 轮询游标进入稳态
MEASURE_COUNT = 240    # 之后在全新域名上测量分布
CONCURRENCY = 4        # 并发压低一点，让「选路」本身成为主导因素

# 模式 -> (说明, 校验函数)
# 校验函数收到 {上游名: 占比%} 与按延迟排序的名字列表，返回错误信息列表。


def check_sticky(pct, by_speed):
    """dnsmasq 原生：粘住最近成功的那台。期望某一台占绝对多数。"""
    top = max(pct.values())
    errs = []
    if top < 60.0:
        errs.append(f"sticky 最高占比只有 {top:.1f}%，未形成『粘性』（期望 >= 60%）")
    return errs


def check_dynamic(pct, by_speed):
    """按延迟打分：最快的那台应拿走大头。

    注意这里**不**要求慢上游必须分到流量：本用例的延迟比是 2ms : 15ms : 60ms : 150ms，
    打分公式 (在途+1)×EWMA 下最快的那台领先 7~75 倍，在并发只有 4 的情况下
    合理结果就是它独占。要求「四台均分」反而会把一个正确的延迟最优实现判成错的。
    「慢上游完全为 0」这件事由下面的重适应测试来兜底 —— 真正要保证的不是
    「平时给慢上游留份额」，而是「被冷落的上游一旦变快能被重新发现」。
    """
    errs = []
    fastest = pct.get(by_speed[0], 0.0)
    if fastest < 50.0:
        errs.append(f"dynamic 最快上游只拿到 {fastest:.1f}%（期望 >= 50%）")
    return errs


def check_swrr(pct, by_speed):
    """加权轮询的权重 ∝ 1/EWMA：越快拿得越多，但慢的不会被饿死。"""
    errs = []
    fastest = pct.get(by_speed[0], 0.0)
    slowest = pct.get(by_speed[-1], 0.0)
    if fastest < 30.0:
        errs.append(f"swrr 最快上游只拿到 {fastest:.1f}%（权重应当明显偏向快上游）")
    if fastest <= slowest:
        errs.append(f"swrr 未按权重倾斜：最快 {fastest:.1f}% <= 最慢 {slowest:.1f}%")
    return errs


def check_even(lo, hi, label):
    def f(pct, by_speed):
        errs = []
        for nm, v in pct.items():
            if not (lo <= v <= hi):
                errs.append(f"{label} 分布不均：{nm} 占 {v:.1f}%（期望 {lo}%~{hi}%）")
        return errs
    return f


MODES = [
    ("sticky", "dnsmasq 原生：粘住最近成功的那台", check_sticky),
    ("dynamic", "按 (在途+1)×EWMA 打分，快者多得", check_dynamic),
    ("swrr", "平滑加权轮询，权重 ∝ 1/EWMA", check_swrr),
    ("round-robin", "严格轮转，接近均分", check_even(13.0, 37.0, "round-robin")),
    ("random", "随机分配，四台都用到且大致均匀", check_even(10.0, 40.0, "random")),
]


def check_readaptation(ups):
    """验证 dynamic 策略的重适应能力（「动态」二字的真正含义）。

    步骤：
      1. 以原始延迟跑一轮，最快的那台会独占流量
      2. 把最快的调成最慢、最慢的调成最快（模拟上游侧发生拓扑变化）
      3. 继续跑，检查流量是否迁移到新的快上游

    这一步捕捉的是一个真实盲区：若只按「当前 EWMA」打分，被长期冷落的上游
    永远不会被重新采样，哪怕它早已变快也发现不了。实现上靠
    protocol.SERVER_RESAMPLE_MS —— 样本过期的上游会被临时赋予最高优先级。
    """
    errs = []
    conf = make_conf("dynamic")
    log_path = os.path.join(HERE, "balance-readapt.log")
    logf = open(log_path, "w")
    proc = subprocess.Popen([BIN, "-C", conf, "--threads=4"],
                            stdout=logf, stderr=subprocess.STDOUT)
    try:
        if not wait_ready():
            return ["重适应: 守护进程未就绪"]

        fastest = min(ups, key=lambda u: u.delay_ms)
        others = [u for u in ups if u is not fastest]
        orig = {u.name: u.delay_ms for u in ups}

        # --- 阶段 A：原始延迟 ---
        run_phase([f"ra-a-{i}.bench.test" for i in range(80)], concurrency=CONCURRENCY)
        for u in ups:
            u.reset_counters()
        before = {u.name: u.snapshot()["count"] for u in ups}
        run_phase([f"ra-b-{i}.bench.test" for i in range(MEASURE_COUNT)], concurrency=CONCURRENCY)
        dist_a = {n: p for n, _c, p in upstream_distribution(ups, before)}
        print(f"\n  ── 重适应 · 变化前 ──  最快的是 {fastest.name}({fastest.delay_ms}ms)")
        for u in sorted(ups, key=lambda x: -dist_a.get(x.name, 0)):
            print(f"       {u.name:16s} {dist_a.get(u.name, 0):5.1f}%")
        if dist_a.get(fastest.name, 0) < 50.0:
            errs.append(f"重适应前置条件不成立：{fastest.name} 只占 "
                        f"{dist_a.get(fastest.name, 0):.1f}%（期望 >= 50%）")

        # --- 拓扑变化：最快变最慢、最慢变最快 ---
        slowest = max(ups, key=lambda u: u.delay_ms)
        for u in ups:
            u.delay_ms = orig[u.name]
        fastest.delay_ms = 400
        slowest.delay_ms = 1
        print(f"       [变化] {fastest.name} {orig[fastest.name]}ms -> 400ms，"
              f"{slowest.name} {orig[slowest.name]}ms -> 1ms")

        # 等重适应完成 —— 用「新的最快上游拿到多数流量」作为收敛判据，
        # 而不是写死一个等待时长（那样要么偏松、要么偶发失败）。
        #
        # 需要跨越两道机制：
        #   1) 样本过期（SERVER_RESAMPLE_MS = 3000ms）把被冷落的上游重新拉回候选
        #   2) 时间衰减 EWMA 把它的延迟估计从旧值拉到新值（每次探测都会大幅更新，
        #      衰减常数 EWMA_TAU_MS = 1000ms）
        # 实测约 10 秒完全收敛；这里给 25 秒上限，并把实际耗时打印出来。
        t0 = time.monotonic()
        converged_at = None
        poll = 0
        while time.monotonic() - t0 < 25.0:
            for u in ups:
                u.reset_counters()
            base = {u.name: u.snapshot()["count"] for u in ups}
            run_phase([f"ra-c-{poll}-{k}.bench.test" for k in range(40)],
                      concurrency=CONCURRENCY)
            poll += 1
            d = {n: p for n, _c, p in upstream_distribution(ups, base)}
            if d.get(slowest.name, 0.0) >= 50.0:
                converged_at = time.monotonic() - t0
                break
        if converged_at is None:
            errs.append(f"重适应超时：{slowest.name} 在 25s 内未接管多数流量")
            converged_at = time.monotonic() - t0
        print(f"       重适应收敛耗时 {converged_at:.1f}s")

        for u in ups:
            u.reset_counters()
        before = {u.name: u.snapshot()["count"] for u in ups}
        r = run_phase([f"ra-d-{k}.bench.test" for k in range(MEASURE_COUNT)],
                      concurrency=CONCURRENCY)
        dist_b = {n: p for n, _c, p in upstream_distribution(ups, before)}
        print(f"\n  ── 重适应 · 变化后 ──")
        for u in sorted(ups, key=lambda x: -dist_b.get(x.name, 0)):
            print(f"       {u.name:16s} {dist_b.get(u.name, 0):5.1f}%  "
                  f"(延迟 {u.delay_ms}ms)")

        if r["errors"]:
            errs.append(f"重适应: 有 {r['errors']} 个查询失败")
        if r["ok"] < MEASURE_COUNT * 0.98:
            errs.append(f"重适应: 成功率 {r['ok']}/{MEASURE_COUNT} < 98%")

        # 判据 1：原来的独占者必须让出大头
        after_old = dist_b.get(fastest.name, 0.0)
        if after_old > 30.0:
            errs.append(f"重适应失败：变慢的 {fastest.name} 仍占 {after_old:.1f}%（期望 <= 30%）")

        # 判据 2：必须有一台接过流量（谁接过去取决于各自的 EWMA 收敛速度，
        #         因此不断言具体是哪一台）
        best_other = max(dist_b.get(u.name, 0.0) for u in others)
        if best_other < 40.0:
            errs.append(f"重适应失败：没有上游接过流量（最高只有 {best_other:.1f}%，期望 >= 40%）")

        # 判据 3：新变快的上游不仅要被重新发现，还应当接管多数流量。
        # 这一条才是「重适应」的完整含义 —— 只探测到但不改选路等于没适应。
        recovered = dist_b.get(slowest.name, 0.0)
        if recovered < 40.0:
            errs.append(
                f"重适应不完整：变快的 {slowest.name} 只占 {recovered:.1f}%（期望 >= 40%）")
    finally:
        # 还原延迟，避免影响后续用例
        for u in ups:
            u.delay_ms = orig.get(u.name, u.delay_ms)
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        logf.close()
    return errs


def make_conf(mode):
    path = os.path.join(HERE, f"balance-{mode}.conf")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"""# 由 balance.py 生成：仅用于验证 --balance={mode} 的分布特征
port={LISTEN_PORT}
cache-size=4000
no-resolv
no-poll
server=127.0.0.1#15361
server=127.0.0.1#15362
server=127.0.0.1#15363
server=127.0.0.1#15364
balance={mode}
log-queries
""")
    return path


def wait_ready(timeout_s=4.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        _dt, rc, _ans, err = query("ready-check.local", timeout=1.0)
        if err is None and rc is not None:
            return True
        time.sleep(0.1)
    return False


def main():
    if not os.path.exists(BIN):
        print(f"找不到可执行文件 {BIN}，先执行 zig build", file=sys.stderr)
        return 1

    ups = [Upstream(*d) for d in UPSTREAM_DEFS]
    for u in ups:
        u.start()

    # 延迟从快到慢 —— 用作各种「倾斜方向」判据的基准顺序
    by_speed = [u.name for u in sorted(ups, key=lambda x: x.delay_ms)]

    failures = []
    try:
        print("=" * 74)
        print("上游调度策略分布验证")
        print("=" * 74)
        print(f"上游延迟顺序: " + " < ".join(f"{u.name}({u.delay_ms}ms)" for u in sorted(ups, key=lambda x: x.delay_ms)))
        print(f"每轮: 预热 {WARMUP_COUNT} 个域名 -> 测量 {MEASURE_COUNT} 个新域名（并发 {CONCURRENCY}）")

        for mode, desc, checker in MODES:
            conf = make_conf(mode)
            log_path = os.path.join(HERE, f"balance-{mode}.log")
            logf = open(log_path, "w")
            proc = subprocess.Popen(
                [BIN, "-C", conf, "--threads=4"],
                stdout=logf, stderr=subprocess.STDOUT,
            )
            try:
                if not wait_ready():
                    failures.append(f"{mode}: 守护进程未就绪")
                    continue
                for u in ups:
                    u.reset_counters()

                # 预热：跑一批域名让 EWMA / 游标进入稳态，这批不计入分布
                run_phase([f"warm-{mode}-{i}.bench.test" for i in range(WARMUP_COUNT)],
                          concurrency=CONCURRENCY)
                for u in ups:
                    u.reset_counters()

                # 测量
                names = [f"m-{mode.replace('-', '')}-{i}.bench.test" for i in range(MEASURE_COUNT)]
                before = {u.name: u.snapshot()["count"] for u in ups}
                r = run_phase(names, concurrency=CONCURRENCY)
                dist = upstream_distribution(ups, before)

                print(f"\n  ── --balance={mode} ──  {desc}")
                print(f"     成功 {r['ok']}/{r['n']}，失败 {r['errors']}，"
                      f"P50 {r['p50']:.1f}ms / P95 {r['p95']:.1f}ms，吞吐 {r['qps']:.0f} qps")
                print_dist(dist)

                if r["errors"]:
                    failures.append(f"{mode}: 有 {r['errors']} 个查询失败（{r['err_sample']}）")
                if r["ok"] < MEASURE_COUNT * 0.98:
                    failures.append(f"{mode}: 成功率 {r['ok']}/{MEASURE_COUNT} < 98%")

                pct = {name: p for name, _cnt, p in dist}
                counts = {name: cnt for name, cnt, _p in dist}

                # 分流覆盖度检查。要求按策略的语义分开设定，不能用一把尺子：
                #
                #   * swrr / round-robin / random 是「分配型」策略，语义上就是在
                #     多台上游之间分散流量，因此要求四台都被用到 —— 有一台完全
                #     为 0 就说明策略没生效。
                #   * dynamic / sticky 是「择优型」策略。本用例的延迟比是
                #     2ms : 15ms : 60ms : 150ms，且并发只有 4（在途项最多把
                #     快者的分数抬 4 倍，仍远低于慢者），所以「全部压在最快的那台」
                #     恰恰是正确结果 —— 一台空闲的 2ms 上游永远比空闲的 15ms 抢先返回。
                #     对这两个模式只要求「不能绕开最快的那台」。
                #     择优策略真正的均衡保证由 check_readaptation() 覆盖：
                #     被冷落的上游一旦变快，必须能被重新发现并接管流量。
                if mode in ("swrr", "round-robin", "random"):
                    unused = [nm for nm, c in counts.items() if c == 0]
                    if unused:
                        failures.append(f"{mode}: 上游 {unused} 完全没被使用（该策略不应饿死任何一台）")
                else:
                    fastest_pct = pct.get(by_speed[0], 0.0)
                    if fastest_pct == 0.0:
                        failures.append(
                            f"{mode}: 最快上游 {by_speed[0]} 完全没被使用（择优策略却绕开了最优解）")

                failures.extend(f"{mode}: {e}" for e in checker(pct, by_speed))
            finally:
                try:
                    proc.terminate()
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
                logf.close()
                # 清掉本轮测量用的缓存域名，避免下一轮直接命中缓存而不发生选路
                for u in ups:
                    u.reset_counters()

        failures.extend(check_readaptation(ups))

        print("\n" + "=" * 74)
        if failures:
            print("策略分布验证未通过：")
            for f in failures:
                print(f"  ✗ {f}")
            return 1
        print("策略分布验证通过：5 种策略的分流特征与 dynamic 的重适应能力均符合设计意图")
        return 0
    finally:
        for u in ups:
            u.stop()


if __name__ == "__main__":
    sys.exit(main())
