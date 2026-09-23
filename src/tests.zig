// 由 兔子 根据 odhcpd 和 dnsmasq 重写（Derived from odhcpd and dnsmasq）。
// 上游版权与许可证：
//   dnsmasq 2.93 — Copyright (c) 2000-2026 Simon Kelley, GPL-2.0-or-later
//   odhcpd      — Copyright (C) 2012-2013 Steven Barth / OpenWrt, GPL-2.0-only
// 本作品整体以 GPL-2.0-only 发布，详见 LICENSE。

//! tests.zig — 单元测试入口（`zig build test`）
//! 每个模块自己带有对照 C 源码的测试，这里统一引用。

test {
    _ = @import("protocol.zig");
    _ = @import("addr.zig");
    _ = @import("name.zig");
    _ = @import("util.zig");
    _ = @import("cache.zig");
    _ = @import("net.zig");
    _ = @import("log.zig");
    _ = @import("rfc1035.zig");
    _ = @import("hosts.zig");
    _ = @import("resolv.zig");
    _ = @import("domain.zig");
    _ = @import("daemon.zig");
    _ = @import("options.zig");
    _ = @import("forward.zig");
    _ = @import("fwdengine.zig");
    _ = @import("server.zig");
    _ = @import("dhcp.zig");
    _ = @import("dhcpv4.zig");
    _ = @import("ifaddr.zig");
    _ = @import("uci.zig");
    _ = @import("uci_dhcp.zig");
    _ = @import("v6conf.zig");
    _ = @import("v6rt.zig");
    _ = @import("dhcpv6.zig");
    _ = @import("router.zig");
    _ = @import("applet.zig");
    _ = @import("odhcpd_main.zig");
}
