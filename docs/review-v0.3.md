# RouterTop 0.3 independent scoped review

Date: 2026-10-24 (Asia/Taipei). Task: network-0.3-review. Reviewer actor: `/root/review`; implementation actors: `/root`, `/root/core`, `/root/image`. Next owner: `/root` for isolated Linux/browser/image acceptance and integration.

**PASS for the completed scoped static review and targeted R03-01 fix verification.** No open demonstrated blocker was found in the inspected candidate. Runtime acceptance and the dynamic WAN overlap question below remain separate; this report does not certify production readiness or complete RouterOS compatibility.

Base SHA: `227c672cc9acc08501e6107d2a9af7eb20244bcc` (0.2). HEAD at inspection remains this base; new candidate changes are uncommitted and identified by the SHA256 table below. Input acceptance: `docs/network-v0.3-contract.md`.

Scope: new VLAN/WireGuard/firewall models and rendering in `network.rs` and `lib.rs`; durable WireGuard key migration, authenticated key API, CLI/boot integration; the three Web UI files. Existing unrelated functionality was not broadly re-reviewed. Reviewer did not modify product code, execute repository tests, touch VM serial, alter networking, or publish anything. Only this report was written under explicit ownership.

## Finding and fix verification

**R03-01 — P2 — RESOLVED: a transport endpoint could be captured by a WireGuard connected route.**

Before the fix, endpoint validation rejected exact local router addresses and addresses captured by configured peer routes, but not other addresses inside a WG connected subnet. A concrete accepted example was interface `wg0`, address `10.7.0.1/24`, peer allowed IP `10.7.0.2/32`, endpoint `10.7.0.3:51820`. The generated `ip address add` installs the connected `10.7.0.0/24` route, directing transport for `.3` into WG itself rather than its physical transport. The peer has no matching allowed IP for that transport destination. The same gap existed for another WG interface's connected subnet.

Verified resolution in integrated `crates/routertop/src/network.rs:247`: endpoint validation now rejects containment in every WG connected subnet. The focused regression tests cover `.3`, network and broadcast addresses in the same WG subnet, another WG subnet, and legitimate directly reachable LAN/VLAN endpoints. Integrated source hash matches the worker's repaired candidate. This is source and regression-test inspection, not a reviewer-run handshake reproduction.

## Other inspected behavior

- All new configuration fields pass through `validate_network` via the shared `validate` path before service/shell rendering. Interface names, addresses, endpoints and route strings are constrained before interpolation; firewall enums and bounded comments do not expose raw shell/nft input.
- VLAN IDs, parent/name uniqueness, connected subnet overlap and DHCP bounds are checked. VLAN service rules address the VLAN's own router IP, with internet forwarding/NAT opt-in. No implicit inter-VLAN/LAN forwarding is added.
- Peer routes are canonical, disjoint from configured local/static/peer routes, and cannot capture configured transport endpoints. The own-WG `/32` exception is bounded separately from the connected-subnet endpoint rejection added in R03-01.
- System input reservations precede custom input rules. Custom forward rules follow established/related handling and precede implicit forwarding rules. Enabled rule order is preserved and default input/forward drops remain.
- Durable key material is separate from public Config. Missing/corrupt existing private keys fail rather than silently rotate. Saves reconcile keys by interface and commit configuration plus keys in the same durable bundle. The authenticated key endpoint derives public keys only. Boot WG files use private directory/file permissions and are not part of public render/export/UI output.
- Defaulted 0.2 fields are normalized without replacing administrator credentials or revision. UI edits preserve unrelated config fields, expose ordered rule controls, and maintain save/revision/pending-reboot behavior. New content is constructed using DOM text/value operations rather than interpolated HTML.
- Boot installs nftables before activating new interfaces; advanced setup occurs after base ifup and before enabling forwarding/dnsmasq. Failure continues through the existing forwarding-disable trap.

## Evidence and explicit gaps

**PASS — reviewer source inspection:** scoped `git diff 227c672`, `Get-Content`, `rg`, and `Get-FileHash` commands in `E:\routertop`, with successful reads and final hash command exit 0. No behavioral test pass is inferred from source inspection.

**PASS — Odin-assisted navigation:** explicit project `ws_7eccb743b075c34e255f096273a38d0dd35fc1bd370bd2b8`, returned root `E:\routertop`. `project_analysis` trace `8be56f4d-1331-4b77-aed2-612ccf4fae8c` inspected live structure. Rust LSP symbol overview trace `ab49a031-97be-4c3d-836d-2f6af2ea0727` located the new model/validator/renderer symbols. Incoming-call hierarchy trace `aa90c358-eb0e-45cc-b429-07584627d082` confirmed `lib.rs::validate` calls `network.rs::validate_network`, with current document freshness. These calls executed no repository commands or edits; they do not prove complete call coverage or passing tests.

**PASS — author-reported, not rerun by reviewer:** integrator reported 39 Windows tests and clippy before R03-01. Network worker reported three focused endpoint tests plus clippy after the fix. Final test evidence must identify the tested candidate separately.

**NOT_RUN by reviewer:** Linux VLAN tagged traffic/DHCP/isolation, WireGuard handshake/encrypted traffic/wrong-peer denial, actual firewall ordering, browser CRUD/reload, persistent reboot, BIOS/UEFI image boot, size measurement, and CI. Integrator owns this evidence.

**NOT_RUN / unresolved runtime question, not a confirmed finding:** dynamic WAN addresses are unavailable to the static Config validator. The generated script installs peer routes using `ip route replace` after WAN DHCP. A peer prefix equal to the actual WAN connected prefix (for example QEMU WAN `10.0.2.0/24`) could conflict with that route. Reviewer requested a focused isolated-namespace experiment from the integrator; no runtime outcome was available when this report was written. Do not describe that hypothesis as an observed outage or a passed check. If reproduced, address the specific collision and recheck that delta only.

## Candidate SHA256

| Path | SHA256 |
|---|---|
| `crates/routertop/src/lib.rs` | `773A62A97F33391122DC95E49EDAA34906805BBBCF7065F41570312A42625959` |
| `crates/routertop/src/network.rs` | `E21ED1298B1C193746D32D9A9DD5CD119B0E4F0E7BCEDD30F551F488EF0F8D46` |
| `crates/routertop/src/main.rs` | `EBEDE244FD385891815616A02CEB7BCDDCAA6E5C1290F9D56B5DAE127F68C22E` |
| `crates/routertop/src/web.rs` | `9CF9B5003B54C1E2140321845FE82299E2095E33D32253450D7331722E58E08F` |
| `crates/routertop/tests/network.rs` | `3FB19FD1BF047915E9B65E5491926740D6FCE889364D51CA743B355684DA5006` |
| `crates/routertop/tests/web_network.rs` | `B4A4E870C788FB83C46AFD8872C2FB2206DFDD29D49829D4FB6E6FDA7FE7112A` |
| `web/index.html` | `2D8A28B2AE49F55B94CB9F41F1ED40E2FE668B923493DBD23BF4FAA518B44A2E` |
| `web/app.js` | `D9EAA076026CFE8229EE97D069C33C14968AB34C3D02A133513771C927EAF65F` |
| `web/style.css` | `0B6A094477A54E09B302F9E121EDD6D04511AD1469648CB4FE657D61B55E8C93` |
| `image/overlay/usr/sbin/routertop-boot` | `B28E04529217FD016837A2BD11861AE28A915676E61926548E5540F124F63D38` |

External side effects by reviewer: none. Remaining evidence and the focused WAN collision experiment owner: `/root`.

## Integrator follow-up: observed WAN conflict

The requested isolated Linux experiment reproduced the second issue: `198.18.0.1` resolved through `wan0` before the generated `ip route replace 198.18.0.0/24 dev wg0`, and through `wg0` afterwards. Raw local transcript: `evidence/v03/wan-overlap-reproduction.log` (ignored; no keys). This replaces the earlier NOT_RUN hypothesis with observed evidence; it is not a second broad review.

The integrator added a typed live-WAN subnet validator, `network-check CONFIG`, a pre-activation boot gate, and Alpine udhcpc post-bound/post-renew checks that disable forwarding on a conflict. New pure tests cover equal, covering and more-specific peer routes, connected local networks, static routes, missing WAN leases and malformed prefixes. The packet harness also requires rejected configurations to leave the real WAN gateway route unchanged. Final runtime status is recorded in acceptance-v0.3.md; this addendum does not infer that status from static review.
