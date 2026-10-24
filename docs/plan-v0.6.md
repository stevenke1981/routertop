# RouterTop 0.6 — PPPoE WAN implementation plan

Base: 3991768b388257cef792a5cb1d8fdbaf609d6957. User authorizes implementation, isolated testing, public source commit/push. Runtime target: Alpine x86_64; keep ARM architecture reservation and current light macOS-like UI. No new Rust/frontend dependency planned.

## Scope and frozen interface

- Single WAN: `wan.interface` remains the physical Ethernet/VLAN name; `wan.mode` defaults to `dhcp`, or `pppoe`; `wan.pppoe` is null or `{username,password,mtu}` (MTU default 1492; 1280..1492). PPP logical interface is fixed `ppp0`. Reject collisions and invalid mode/options. Existing v0.5 config stays valid.
- Use packaged pppd plus rp-pppoe userspace transport (Alpine linux-virt 6.18.58 has CONFIG_PPPOE disabled; PPP generic/async modules are supported); PAP/CHAP client credentials persisted only in private state, rendered into root-only runtime files. Password is write-only in Web: GET returns blank and top-level `wan_password_set`; blank on save preserves existing password for the unchanged username, account changes require a password. Disable PPPoE to remove stored credentials. No password in public rendered files, status, errors, screenshots or test reports.
- Logical WAN is used for IPv4 NAT, firewall, routing and WireGuard checks. Physical underlay carries PPPoE, not a simultaneous DHCP client. Automatic reconnect has bounded delay. IPv6CP brings IPv6 over PPP; existing dynamic IPv6/PD client operates on `ppp0` across session changes with stable persisted DUID. Support ISP RA/default route and DHCPv6 IA_NA/IA_PD; PD-only/IPv6CP peer default behavior must be explicit and packet tested.
- Settings use existing authenticated/revision-controlled save and reboot activation. Show WAN dialing/connected/reconnecting plus IPv4/IPv6/PD state in existing light Web layout. Keep IPv4 management/LAN available during failed dialing.

## Owners / write scopes

| Owner | Worktree | Responsibility |
|---|---|---|
| core | .worktrees/pppoe-core | crates/routertop/src and tests; image overlay PPP/client lifecycle; image/packages.txt; scripts/build-image.sh |
| ui | .worktrees/pppoe-web | web/*; scripts/browser-v06-smoke.py; optional scripts/appliance-pppoe-checks.py |
| network_test | .worktrees/pppoe-test | scripts/network-v06-smoke.py and PPPoE lab fixtures; actual isolated Linux test execution |
| root | current checkout | contracts, integration, builder/ISO/actual browser lifecycle, version metadata, CI, evidence and publishing |
| independent reviewer (after author slot frees) | separate scoped read | one credential/lifecycle/firewall integration pass; no broad review chain |

Authors do not revert other edits or commit/push. Integrator copies only assigned files after explicit handoff. Shared lab serial connections have one named owner at a time.

## Acceptance gates

AC1: compatible parsing, mode/credential/MTU validation, safe private rendering and write-only Web secret preservation; fmt/test/clippy.
AC2: actual PPPoE discovery, authenticated PPP session, IPv4 routed HTTP/NAT and negative invalid credentials; no DHCP leak on underlay.
AC3: IPv6CP + real DHCPv6-PD, distinct LAN/VLAN /64 SLAAC and IPv6 HTTP; prefix replacement/expiry and firewall/WireGuard regressions.
AC4: actual session loss and server recovery cause redial and working IPv4/IPv6/PD; retired addresses not authorized.
AC5: real final ISO Web save/reload, password remains blank in GET/UI, admin/settings/TLS/PPP credential/DUID survive reboot and cold boot; desktop/mobile UI and JS errors checked.
AC6: measured ISO/kernel+root/binary/Web/package growth; one independent scoped review; exact remote commit and current hosted CI result.

All gates start NOT_RUN. Keep raw credentials/logs and enrolled data disks ignored. Tests use disposable VMs/namespaces/socket Ethernet; never host-NIC bridges. Hardware/real ISP/ARM/throughput/power-loss/signed production update remain NOT_RUN.
