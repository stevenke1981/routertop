# RouterTop 0.7 — static and dual WAN

Base: a698bdce2952c99da9e4ff0f7515df138afe7630. User authorizes implementation, isolated lab tests, commit and public push. Target Alpine x86_64; preserve ARM source portability and local light Apple-inspired UI. No new runtime dependency planned.

## Scope and contract

Existing `wan` remains primary. Add optional `wan_backup` and `failover`, present together. Each WAN supports `dhcp`, `pppoe`, `static`; static uses `static_ipv4: {address: IPv4/prefix, gateway: IPv4}`. PPP logical interfaces are ppp0 (primary) and ppp1 (backup). Old single-WAN files remain valid.

`failover` has literal IPv4 `primary_target`, `backup_target`, `interval_seconds` (2..60, default 5), `failure_threshold` and `recovery_threshold` (1..10, default 3). Acquire both uplinks; supervisor exclusively owns the dual-WAN default route. Dedicated per-uplink probe routing must prevent a failed line appearing healthy through its peer. Select healthy primary, otherwise healthy backup, otherwise no WAN route; automatically restore primary after its recovery threshold. Existing connections may need reconnecting after the public source IP changes. This is active/standby, not load balancing or seamless session migration.

IPv6/PD remains primary-only: withdraw delegated addresses, DNS, default availability and authorization while backup is active, reacquire on primary return. The UI must state this limitation. Dual mode rejects static primary IPv6; existing single-WAN static IPv6 remains supported. Dual-provider IPv6 failover is outside this release, while single-WAN IPv6/PPPoE/PD retains its existing behavior.

Web GET never returns either PPP password. Independent `wan_password_set` and `wan_backup_password_set`; blank save preserves only the same slot/account/interface. Disabled/non-PPP slots drop credentials. Existing authentication, revision and reboot activation apply. Root-only credentials and explicit public-status permissions remain mandatory.

Status preserves legacy primary fields and adds `dual_wan`, `active` (primary/backup/none), `ipv6_policy` (primary-only), and primary/backup objects with mode/interface/logical_interface/state/healthy/ipv4_address/consecutive_failures/consecutive_successes. Link state is connected/probing/unavailable.

## Owners

| Owner | Separate worktree | Scope |
|---|---|---|
| wan_core | .worktrees/wan-core | Rust model/compiler/runtime/CLI and non-Web tests; image overlay/build if needed |
| wan_web | .worktrees/wan-web | web/*, web.rs, Web tests, browser-v07-smoke.py, appliance-wan-checks.py |
| wan_test | .worktrees/wan-test | network-v07-smoke.py, lab fixtures, isolated Linux builder and packet evidence |
| root | current checkout | contract, integration, version/CI/docs, artifact and final ISO/browser verification, publishing |
| independent review | separate read scope after a slot frees | one scoped routing/credential/lifecycle review and focused closure |

Authors do not commit/push or overwrite another owner's edits. Integrator copies only handed-off owned paths. Serial/VM ownership is explicit; no host NIC bridge or physical disk provisioning.

## Acceptance gates (initially NOT_RUN)

- AC1: old config compatibility, static gateway/subnet and interface collision validation, two independent write-only credentials, fmt/tests/clippy.
- AC2: actual standalone fixed-IP routing/NAT; dual DHCP/DHCP, DHCP/PPPoE, PPPoE/DHCP and PPPoE/PPPoE packet matrix, plus static uplink participation.
- AC3: carrier loss and upstream blackhole cause backup selection; a healthy backup cannot mask failed primary probes; restoration automatically returns primary; both failed means no fallback route; unsolicited WAN traffic remains denied.
- AC4: primary IPv6/PD withdrawal and return, existing single-WAN IPv6/PD and PPP regressions.
- AC5: actual final ISO Web save/reload/reboot, administrator/TLS/settings and both PPP secrets retained privately; desktop/mobile UI and runtime errors checked.
- AC6: measured image/binary/Web/package growth, independent scoped review, actual remote commit and exact-head CI.

Evidence records actual version, hashes, commands/exit codes and PASS/FAIL/BLOCKED/NOT_RUN. API fixtures, real Linux packets, final ISO lifecycle and hosted CI are separate layers. ARM/hardware/real ISP/load/destructive power-loss remain NOT_RUN.
