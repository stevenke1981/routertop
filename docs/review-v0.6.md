# RouterTop 0.6 scoped independent review

Reviewer: `/root/pppoe_review`, independent of both authors. Task `routertop-v06-review`, revision 1. Base/current committed HEAD: `3991768b388257cef792a5cb1d8fdbaf609d6957`; target: uncommitted candidate identified by the actual-byte hashes below. Review observed 2026-10-24T07:08:28.348356+00:00.

Scope: PPPoE credential parsing/persistence/rendering and write-only Web handling, PPP/IPv6CP/DHCPv6-PD hook lifecycle, stable identity, logical WAN firewall/routing/WireGuard integration, and changed Web settings. One scoped pass, no broad project audit or reviewer chain. Only this report is written; product files and remote state are untouched.

**Result: PASS for this scoped review after both concrete P2 findings were fixed.** Zero open findings from this pass. This is a static review outcome; no packet/VM/image/CI result is inferred. Root owns implementation fixes and runtime acceptance. Pure preferences and speculative issues are not blockers.

## Findings

### PPP-R1 — P2, resolved: custom firewall selectors omitted the PPP logical WAN

Location: `web/app.js:422` (`interfaceChoices`). The helper enumerates `wan.interface`, LAN, VLANs and WireGuard but never `ppp0`. In PPP mode the backend renders WAN NAT/guard/routing against logical `ppp0`, so selecting physical `eth0` does not target routed Internet traffic. The Web Add/Edit rule dialog cannot select `ppp0`; opening an API-created rule targeting `ppp0` also has no matching option and can save it as the blank/any-interface choice.

Executed focused reproduction: evaluated the actual helper expression from the current file using the PPPoE configuration and no VLANs/WireGuard. Node exited 0 and reported available choices `["", "eth0", "eth1"]`, required `ppp0`, result FAIL. This did not mutate files or start a router. Fix: expose logical `ppp0` while PPPoE is selected, keeping valid physical choices as appropriate; verify Add/Edit retains the chosen logical interface.

### PPP-R2 — P2, resolved: CLI apply kept a credential-bearing active config world-readable

Location: `crates/routertop/src/main.rs:152` in `apply()` (`fs::write("/etc/routertop/routertop.toml", source)`). The normal storage boot hook now correctly changes the active TOML to 0600 and the CGI owner, but this supported `apply CONFIG --boot` path writes the same plaintext PPP credential source with no private open mode/permission correction. On an unprovisioned image the builder installed this file as 0644; `fs::write` preserves that mode. If the file is absent, ordinary Unix creation with the default root umask also creates 0644. A local unprivileged process can read the PPP password after this path runs.

Evidence: traced execute -> validated `apply()` -> active-config write; compared the image builder's `install -m 0644` and the changed storage hook's 0600/owner operation. This is direct source/path evidence; the reviewer did not execute appliance provisioning on the Windows host. Fix: write the active config through a private writer, preserving the intended CGI read access and avoiding a world-readable interval; use the same policy for both boot paths.

## Checked boundaries without additional findings

- New model defaults old WAN configs to DHCP; PPP MTU/credential validation is bounded and rejects controls, logical name collisions and static IPv6-on-PPP. TOML parse errors no longer echo source credential lines; Debug redacts the password.
- `render()` exposes interface/policy/client data and excludes PPP credentials. PPP peer credentials are isolated in a 0700 runtime directory with 0600 files; PPP option quoting escapes backslashes/quotes and physical interfaces use the existing validation.
- Authenticated/revision-controlled Web GET clears the password and reports only its saved-presence flag. Blank save preserves only an existing unchanged username; switching to DHCP removes the credential atomically. Durable bundle writes retain their private atomic policy.
- Firewall/IPv6/WireGuard render paths now use the logical WAN getter. Full-tunnel drop guards remain before established/custom rules; DHCPv6 control exceptions stay bounded.
- PPP starts asynchronously after the mandatory firewall and LAN setup. IPv6 client launch follows IPv6CP-up; down requests the client to stop and invokes immediate dynamic authorization/DNS/RA withdrawal. Persistent DUID initialization is retained and malformed identities remain rejected.
- No runtime conformance claim is made for pppd flags, no-RA DHCPv6, re-dial timing, hook execution ordering, negotiated-peer conflicts, or lifecycle failure injection. Those require root/test-agent packet and final image evidence.

## Evidence / handoff

| Check | Result | Environment / exit |
|---|---|---|
| Changed credential/runtime/UI call paths | PASS static inspection, with two findings | Windows `git diff`, targeted source reads, exit 0 |
| PPP custom-rule option reproduction | FAIL behavior reproduced | Node evaluation of actual helper, exit 0 |
| Source snapshot hashes | PASS recorded | Windows SHA256, exit 0 |
| Independent execution of Rust tests, Linux packets, browser/ISO reboot | NOT_RUN by reviewer | Runtime/test owners |
| Hosted CI / remote HEAD | NOT_RUN at this review | Integrator after commit |
| ARM / physical ISP/NIC | NOT_RUN | Outside scoped pass |

The implementation authors/root reported Windows 81 tests and formatter/linter success. These are owner reports at review time, not executions by this reviewer. Both fixes were reviewed in the focused follow-up below. Next owner: root for actual Linux/image/browser acceptance and publishing. No second full review is requested.

## Actual local source snapshot

| File | SHA256 |
|---|---|
| `crates/routertop/src/pppoe.rs` | `2e85f12acdcee44274042e135e7aaf34c1b1b637f0a8f02f2cef5c17b1d4d905` |
| `crates/routertop/src/main.rs` | `b2b263b7b5bc8ed093d5165549024af9801d84076715d288de78673f0bfd54fe` |
| `crates/routertop/src/pd.rs` | `512f6b03c557d4da5bb92b3a8b4c0e43f0a0f1be323fcb6455b2c239bfb96b79` |
| `crates/routertop/src/web.rs` | `fad1fec6cef4df1b2ed84b87376267d89f9c675a3ea2452c60d29929da5156d4` |
| `crates/routertop/src/lib.rs` | `c0bfb37c18e63d8d435e085d2d2c49281214d94d59ef47e53c9cdf6b9c52d3c6` |
| `crates/routertop/src/network.rs` | `45266beb04b2316d9963262ab2c5c4550fe8327460240244e7fab4bc568d6e02` |
| `crates/routertop/src/ipv6.rs` | `c141d4a4fb5ab180410605c85099e6e7a11b668a7315131ed4fa153ad2672157` |
| `web/app.js` | `622f4911c3a1a609fd0abf6b2853372f47f0eec2847bfc499eabcbba7f7fbf88` |
| `image/overlay/usr/sbin/routertop-storage` | `39a124dde45e20e1e68b66b2afe08186451d068b40c9c1be86c24246aa9961c4` |

Raw hashes include local line endings. Later runtime fixes require separate scoped evidence; this report does not automatically cover unseen changes. External publication is authorized by the user but not performed by this reviewer.

## Focused finding-closure follow-up

Observed 2026-10-24T07:14:38.141864+00:00. Only PPP-R1 and PPP-R2 changes were re-read; this is not a repeated full pass or blanket approval of later runtime changes.

- **PPP-R1 closed.** `interfaceChoices` now adds `ppp0` when the current WAN mode is PPPoE, retaining the physical WAN/LAN/VLAN/WireGuard choices. Reviewer re-evaluated the actual helper expression for DHCP and PPPoE: DHCP `["", "eth0", "eth1"]`, PPPoE `["", "ppp0", "eth0", "eth1"]`, both assertions PASS, Node exit 0. The existing Add/Edit dialogs both call this helper, so their selected `ppp0` has a matching option.
- **PPP-R2 closed.** `apply()` now calls `write_active_config(..., Some((1000,1000)))`. The helper creates a new private temporary file using Unix mode 0600, sets the intended CGI UID/GID, writes/syncs it, then renames it over the active path. It therefore corrects a prior 0644 file without exposing new credential content through that file. The new regression checks both fresh creation and replacement of a deliberately 0644 file, with a Unix 0600 assertion. Core/root reports the focused Windows test and Clippy PASS; reviewer inspected the test but did not rerun already-owned tooling. The Unix mode/owner execution remains explicitly owned by the Linux test runner.

Latest actual-byte hashes inspected in this follow-up:

| File | SHA256 |
|---|---|
| `crates/routertop/src/main.rs` | `dc99571af0e182fe8f37f3913622afce3a24e4df375d40c29631673dfe2368f8` |
| `web/app.js` | `29e6ec8f77da20c28b021ece8675bee7ea190a8596603beff832ff682d6a405b` |

Follow-up result **PASS, zero open findings**. Linux permission execution, real PPPoE/PD packets, final ISO/browser lifecycle and current hosted CI remain NOT_RUN by this reviewer; the integrator must attach those owners' evidence. No product file was changed by the reviewer.
