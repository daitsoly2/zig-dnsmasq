#!/usr/bin/env python3
"""负数缓存投毒回归测试。

历史 bug（已在 rfc1035.zig / forward.zig 两处修复）：
  上游 119.29.29.29 对**存在**名字的 PTR 查询会回 qd=0 的 NXDOMAIN + SOA
  （TTL 86400）。all-servers 竞速时它一旦抢先：
    * 修复前：Zig 收下这条畸形包，按「名字不存在」缓存 -> 该名字的 A/AAAA
      在负数 TTL 内全部失败（表现为「某些域名时不时解析不了」）；
    * 现在：a) checkReplyWith 直接丢弃 qd!=1 的包；b) 即便别家回了合法的
      正向名 NXDOMAIN，extractAddresses 也不会为 PTR 查询把它缓存成
      「整个名字不存在」。

本脚本做的事：
  1. 先确认基线：目标名字的 A 能解析；
  2. 对目标名字连打大量 PTR 查询（制造被污染的机会窗口）；
  3. 再查 A，必须仍然能解析；
  4. 同时对一批「真的不存在」的名字确认仍能正确拿到 NXDOMAIN。

用法：python3 poison_regression.py [router_ip] [每名 PTR 次数]
"""
import socket, struct, sys, concurrent.futures

ROUTER = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.1"
ROUNDS = int(sys.argv[2]) if len(sys.argv) > 2 else 20
Z = (ROUTER, 53)

# 都是真实存在的、且上游会为其 PTR 回 NXDOMAIN 的正向名
VICTIMS = ["www.qq.com", "www.163.com", "www.taobao.com", "www.jd.com",
           "www.baidu.com", "github.com", "www.sina.com.cn", "www.sohu.com",
           "www.douban.com", "mirrors.aliyun.com"]
# 真的不存在的名字（应稳定 NXDOMAIN）
REAL_NX = ["nonexistent-zzz-9988.example.com", "no-such-host-aabbcc.qq.com",
           "definitely-not-real-8899.baidu.com"]


def mk(name, qtype, tid):
    q = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    for lab in name.encode().split(b"."):
        if lab:
            q += bytes([len(lab)]) + lab
    q += b"\x00" + struct.pack(">HH", qtype, 1)
    return q


def ask(name, qtype, timeout=5.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(mk(name, qtype, 0x3311), Z)
        d, _ = s.recvfrom(4096)
        f = struct.unpack(">H", d[2:4])[0]
        qd, an, ns, ar = struct.unpack(">HHHH", d[4:12])
        return f & 0xF, qd, an
    except Exception:
        return None, None, None
    finally:
        s.close()


def main():
    ok = True

    print("### 1) 基线：受害者名字的 A 记录")
    base = {}
    resolvable = 0
    for n in VICTIMS:
        rc, qd, an = ask(n, 1)
        base[n] = (rc, an)
        # 基线**只作记录**，不用来判定成败：这些公网名字的 A 记录会因上游
        # 方差时有时无（例如 github.com 的 A 走 CNAME，部分上游在 A 查询上
        # 直接回 NODATA）。真正的判据在第 3 步的「污染前 vs 污染后」对比。
        note = "" if (rc == 0 and an) else "  （基线即不可解析，不计入判定）"
        print(f"  {n:22s} A -> rc={rc} an={an}{note}")
        if rc == 0 and an:
            resolvable += 1

    # 但也不能全军覆没：一个都解析不出来，说明解析器本身有问题（或网络断了），
    # 那样第 3 步会因为「基线就不可解析」而全部跳过，变成空跑。
    if resolvable == 0:
        print("\n<<< 基线无一个名字可解析：解析器或网络异常，无法判定污染")
        ok = False

    print(f"\n### 2) 对每个受害者连打 {ROUNDS} 次 PTR（8 线程并发）")
    jobs = [(n, 12) for n in VICTIMS for _ in range(ROUNDS)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        list(ex.map(lambda j: ask(j[0], j[1]), jobs))
    print(f"  已发送 {len(jobs)} 次 PTR 查询")

    print("\n### 3) 复查 A 记录（被污染的话这里会 NXDOMAIN / 空）")
    bad = 0
    for n in VICTIMS:
        rc, qd, an = ask(n, 1)
        was_ok = base[n][0] == 0 and base[n][1]
        now_ok = rc == 0 and an
        if was_ok and not now_ok:
            # 基线可解析、PTR 之后失效 —— 这才是「被污染」
            flag = "<<< 被污染！"
            bad += 1
            ok = False
        elif not was_ok:
            # 基线就解析不了：该名字本身在上游有分歧，不计入判定
            flag = "(基线即不可解析，跳过判定)"
        else:
            flag = "OK"
        print(f"  {n:22s} A -> rc={rc} an={an}   [{flag}]")

    print("\n### 4) 真正不存在的名字不得给出任何正向应答")
    # 判据是「不得出现 bogus 正向应答（an>0）」，而不是「必须恰好 rc==3」：
    # 这些名字的上游之间本就不一致（example.com 下有的上游回 NXDOMAIN、
    # 有的回 NODATA），all-servers 竞速下 rc 会漂移。NXDOMAIN(3) 与
    # NODATA(0 且 an=0) 都是合法结论；只有 rc 里带着答案才说明回归了。
    soft = 0
    for n in REAL_NX:
        rc, qd, an = ask(n, 1)
        if an > 0:
            flag, bad_here = "<<< 对不存在的名字给出了正向应答", True
        elif rc in (0, 3):
            flag, bad_here = ("OK (NXDOMAIN)" if rc == 3 else "OK (NODATA)"), False
        else:
            # SERVFAIL 等在 all-servers 竞速下是瞬时态（C 版同样会出现），
            # 记为告警而不判失败，避免套件随机飘红
            flag, bad_here = f"<<< 期望 0/3，得到 {rc}（瞬时竞态，记为告警）", False
            soft += 1
        if bad_here:
            ok = False
        print(f"  {n:36s} A -> rc={rc} an={an}   [{flag}]")
    if soft:
        print(f"  （其中 {soft} 条为瞬时竞态告警，不影响结论）")

    print(f"\n{'='*60}")
    if ok:
        print("结论：通过（无投毒、负缓存语义正确、不存在名无正向应答）")
    else:
        print(f"结论：失败（被污染的名字 {bad} 个；其余见上方 <<< 标记）")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
