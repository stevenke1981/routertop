# RouterTop 0.7 WAN contract

Extends [0.6](network-v0.6-contract.md). See [plan](plan-v0.7.md) for owners and acceptance gates. Implementation and runtime evidence must be checked separately.

## Configuration

`wan` remains the primary uplink, with `interface`, `mode`, `pppoe` and optional `static_ipv4`. `mode` defaults to `dhcp`; `pppoe` retains the previous account/password/MTU contract. `static` requires canonical `static_ipv4.address` (usable IPv4 host /1 through /30) and `static_ipv4.gateway` (a distinct directly connected IPv4 host); /31, /32 and off-link gateways are outside this version. Non-PPPoE modes cannot retain PPP credentials; non-static modes cannot retain static parameters. Static addresses must not collide with downstream subnets or configured local routes. Overlapping ISP-side networks are isolated through per-uplink probe tables and device binding; they are not downstream LANs. Validation is performed before saving or rendering.

Optional `wan_backup` uses the same structure. It is paired with `failover`:

```toml
[wan]
interface = "eth0"
mode = "static"

[wan.static_ipv4]
address = "198.51.100.2/24"
gateway = "198.51.100.1"

[wan_backup]
interface = "eth2"
mode = "dhcp"

[failover]
primary_target = "203.0.113.9"
backup_target = "203.0.113.9"
interval_seconds = 5
failure_threshold = 3
recovery_threshold = 3
```

The example targets are documentation addresses; configure actual reachable ICMP responders appropriate to each ISP. Probe success describes reachability of the selected target, not all Internet services. Choose a target beyond the ISP gateway to detect upstream failures. Thresholds prevent a single missed/recovered response causing a switch. Two probe timeouts and route/lifecycle work add to the configured interval; this is not a guaranteed real-time switch deadline.

## Runtime and security

Both uplinks acquire their own addresses. The supervisor owns the dual-WAN main default route; neither DHCP nor PPP may independently replace it. PPP names are `ppp0` and `ppp1`. Health probes bind to the logical interface and use dedicated routing tables, so backup success cannot count as primary recovery. Main route selection prefers a healthy primary, otherwise a healthy backup, otherwise neither. A restored primary automatically takes over after its recovery threshold. TCP/VPN sessions may reconnect after source addresses change; no connection migration or load balancing is promised.

Firewall/NAT rules cover both configured uplinks while preserving WAN input denial, downstream isolation and WireGuard full-tunnel leak restrictions. Runtime subnet conflicts must fail closed. Private credential/runtime files remain root-controlled; public status includes neither passwords nor raw PPP output.

IPv6 and DHCPv6-PD belong to the primary uplink. On backup selection, primary delegation, dynamic DNS and forwarding authorization are withdrawn and IPv6 Internet forwarding is blocked. On primary restoration, the existing client lifecycle reacquires usable configuration. The backup provides IPv4 service in this release; it does not obtain an independent delegated prefix. Dual WAN requires automatic primary IPv6 when IPv6 is enabled; static IPv6 remains available with a single WAN and is rejected in dual mode. LAN management remains available over IPv4.

## Web and persistence

Authenticated `/config` exposes blank primary and backup PPP passwords and independent top-level flags `wan_password_set` / `wan_backup_password_set`. Blank save preserves only the existing slot with unchanged account and physical interface. A changed account/interface needs an explicit password. Removing a slot or selecting DHCP/static removes its PPP credential. Configuration uses the existing atomic persistent bundle, revision check and reboot activation. Runtime switching does not rewrite the saved configuration or revision.

`/status.wan` retains legacy primary fields. Dual mode adds `dual_wan`, `active` (`primary`, `backup`, `none`), `ipv6_policy` (`primary-only`), and `primary` / `backup` entries containing `mode`, `interface`, `logical_interface`, `state`, `healthy`, `ipv4_address`, `consecutive_failures`, `consecutive_successes`. Per-link state is `connected`, `probing` or `unavailable`.

Routing behavior is grounded in the [iproute2 routing-rule source manual](https://github.com/iproute2/iproute2/blob/main/man/man8/ip-rule.8.in) and [route source manual](https://github.com/iproute2/iproute2/blob/main/man/man8/ip-route.8.in). The manuals describe device-bound local-socket rules and terminal unreachable routes; actual kernel behavior remains a real-packet acceptance gate.
