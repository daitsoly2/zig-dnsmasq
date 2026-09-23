#!/usr/bin/env python3
"""`--interface=` / `--except-interface=` 的绑定行为回归测试。

背景（实机 192.168.0.1 上发现的真实问题）：
    ImmortalWrt 生成的配置里是 `interface=br-lan` + `except-interface=pppoe-wan`，
    而本移植当时把 `interface=` 收下之后**从未使用**，于是退化成绑定通配地址。
    日志里白纸黑字写着 "开始监听 0.0.0.0#5354" —— 装到路由器上，递归解析器
    就等于对 WAN 开放了。这类缺陷本地语义套件完全测不到（它只看应答内容，
    不看 socket 绑在哪）。

本脚本自己起守护进程，只验证「绑在哪些地址上」：
    1. `interface=lo`      -> 只绑 127.0.0.1/::1，LAN 地址必须**不**响应
    2. 网卡名不存在          -> 退守回环，同样不得绑通配地址
    3. 不写 interface=      -> 仍是通配地址（保持向后兼容）
"""
import os
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
BIN = os.path.join(ROOT, "zig-out", "bin", "zig-dnsmasq")
PORT = 15357  # 与其它脚本错开，避免互相踩端口


def enc(name: str) -> bytes:
    out = b""
    for part in name.split("."):
        if part:
            out += bytes([len(part)]) + part.encode()
    return out + b"\x00"


def query(host, port=PORT, timeout=1.5):
    """返回 (ok, rcode)。ok=False 表示这个地址上没人应答。"""
    msg = struct.pack("!HHHHHH", 0x9999, 0x0100, 1, 0, 0, 0) + enc("x.test") + struct.pack("!HH", 1, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(msg, (host, port))
        try:
            d, _ = s.recvfrom(4096)
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False, None
        return True, d[3] & 0xF
    finally:
        s.close()


def local_ipv4() -> str:
    """取本机主用非回环 IPv4（不会真的发包）。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # TEST-NET，只借内核选路
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


results = []


def check(desc, ok, detail=""):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {desc}" + (f"   -> {detail}" if detail else ""), flush=True)


def start(cfg_lines, logname):
    conf = os.path.join(HERE, logname + ".conf")
    with open(conf, "w") as f:
        f.write(f"port={PORT}\nno-resolv\nno-poll\n")
        f.write("server=127.0.0.1#1\n")  # 上游不可达也没关系，只看绑定
        f.write("\n".join(cfg_lines) + "\n")
    logf = open(os.path.join(HERE, logname + ".log"), "w")
    proc = subprocess.Popen([BIN, "-C", conf, "-k"], stdout=logf, stderr=subprocess.STDOUT)
    time.sleep(1.0)
    return proc, logf, conf


def stop(proc, logf):
    try:
        proc.kill()
        proc.wait(timeout=3)
    except Exception:
        pass
    try:
        logf.close()
    except Exception:
        pass


def read_log(logname):
    try:
        with open(os.path.join(HERE, logname + ".log")) as f:
            return f.read()
    except OSError:
        return ""


def main():
    if not os.path.exists(BIN):
        print(f"找不到 {BIN}，先 zig build", file=sys.stderr)
        return 1

    lan = local_ipv4()
    print(f"本机非回环 IPv4 = {lan}，监听端口 = {PORT}\n")

    # ---- 1. interface=lo：只绑回环 ----
    proc, logf, _ = start(["interface=lo"], "iface-lo")
    log = read_log("iface-lo")
    ok_lo, _ = query("127.0.0.1")
    ok_lan, _ = query(lan)
    stop(proc, logf)
    check("interface=lo 时回环可应答", ok_lo)
    check("interface=lo 时不会绑到通配地址（LAN 地址无应答）", not ok_lan,
          f"LAN {lan} 应答={'是(错)' if ok_lan else '否'}")
    check("interface=lo 时日志不含 0.0.0.0", "0.0.0.0" not in log,
          next((l.strip() for l in log.splitlines() if "监听" in l), ""))

    # ---- 2. 网卡名不存在：退守回环，绝不退守通配 ----
    proc, logf, _ = start(["interface=这个网卡不存在"], "iface-bogus")
    log = read_log("iface-bogus")
    ok_lo, _ = query("127.0.0.1")
    ok_lan, _ = query(lan)
    stop(proc, logf)
    check("网卡名解析失败时仍能监听回环", ok_lo)
    check("网卡名解析失败时**不**退守通配地址", not ok_lan and "0.0.0.0" not in log)

    # ---- 3. 没有 interface=：保持通配（兼容原行为） ----
    proc, logf, _ = start([], "iface-none")
    log = read_log("iface-none")
    ok_lo, _ = query("127.0.0.1")
    ok_lan, _ = query(lan)
    stop(proc, logf)
    check("未配置 interface= 时监听通配地址（LAN 可达）", ok_lo and ok_lan)

    failed = sum(1 for r in results if not r)
    print(f"\n=== 结果: {len(results) - failed}/{len(results)} 通过 ===", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
