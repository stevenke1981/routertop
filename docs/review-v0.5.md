# v0.5 scoped independent review

- Reviewer: `/root/pd_review`, independent of the implementation authors.
- Base / current committed HEAD: `029a08477fac33030b927e88cd96d41abb168d38`.
- Target: uncommitted v0.5 candidate, identified by the source hashes below.
- Scope: DHCPv6-PD and dynamic WAN model, validation, render, runtime hooks/monitor, persisted client identity, firewall/WireGuard boundaries, and Web configuration/status integration. No broad project review or second reviewer chain.
- Result: **PASS for this scoped static review after one concrete finding was fixed.** Zero open findings from this pass. This is not packet, image, browser, CI, hardware, or release acceptance.

## Finding and closure

**PD-R1 — P2, resolved: repeated degraded IPv6 state restarted shared IPv4 DNS/DHCP every second.**

The original `pd::monitor` error path unconditionally wrote `dnsmasq-restart` on every one-second iteration. A valid but insufficient upstream grant, such as a `/64` when LAN ID 0 and VLAN ID 1 were configured, repeatedly fails `delegated()`. The DNS supervisor would then repeatedly terminate/restart the shared dnsmasq process despite unchanged RA policy, disrupting otherwise usable IPv4 service.

The implementer replaced the duplicated marker handling with `update_ra()`. Both success and error paths now compare the desired RA configuration with the current file and request a restart only when it changes. Reviewer inspected that focused fix and its call sites in `pd.rs`, SHA256 `645b038a3e615d81f82ca3fb0a2f1ec16467955b1106f12aeca616262cf2af05`. The focused test `repeated_degraded_state_requests_only_one_dns_restart` checks one down transition, repeated unchanged degraded updates, and a subsequent up transition. Root reported that focused test PASS, exit 0; this reviewer did not redundantly rerun it. Actual bad-grant/DNS-process stability remains part of the runtime owner's acceptance, not inferred from this review.

## Checked paths and boundaries

- Static configurations default to the existing mode. Automatic mode rejects static WAN fields. PD requires explicit automatic mode and rejects mixed static LAN/VLAN addressing; subnet IDs are unique, bounded by the requested prefix and checked again against the actual grant.
- Rendered interface names are validated through the existing configuration validator. DHCP hook values are parsed as typed IPv6 networks, addresses and integer lifetimes; lease strings are not evaluated as shell commands.
- Delegated and WAN nft sets use finite timeouts, and forwarding guards precede established/custom rules. Full-tunnel WAN guards remain in place; only DHCPv6/router-solicitation control exceptions are added. Automatically learned ISP DNS is not selected in full-tunnel mode.
- Runtime authorization is derived from unexpired leases and matching kernel addresses; changed/expired delegations withdraw previous authorization. Error paths clear dynamic sets/DNS and withdraw advertised default availability.
- A random client identity is created with exclusive creation, private permissions and sync, separately from ephemeral leases. Existing malformed identity is rejected rather than silently regenerated. Boot initialization clears prior runtime status/leases before acquisition.
- Web persistence continues through the existing authenticated/revision-controlled configuration endpoint. Dynamic status is read separately and rendered using text nodes; upstream strings do not become HTML. Saving mode/subnet choices does not persist a runtime lease into the user configuration.
- Boot orders mandatory firewall setup before WAN/forwarding. Dynamic setup requires the provisioned data volume. New executable hooks and the packaged dhcpcd account are handled by the image builder.

## Evidence boundary

Read-only inspection commands (`git diff`, `git rev-parse HEAD`, targeted source reads and `Get-FileHash`) completed successfully on Windows in `E:/routertop`. No host networking, production files, commits or remote state were changed by the reviewer. Only this report was written.

| Check | Reviewer result |
|---|---|
| Changed call paths, validation and error handling | PASS, static inspection |
| PD-R1 focused fix and regression test inspection | PASS |
| Independent execution of Rust / Linux packet / VM / browser tests | NOT_RUN by this reviewer; owned by integrator and test agent |
| Hosted CI / public remote HEAD | NOT_RUN at review time |
| ARM / physical NIC / arbitrary ISP interoperability | NOT_RUN |

## Source snapshot

Hashes are the actual local file bytes, including local line endings. Later runtime fixes are separately evidenced by their authors and acceptance records; this report does not imply a second full review of later changes.

| File | SHA256 |
|---|---|
| `crates/routertop/src/pd.rs` (finding fix) | `645b038a3e615d81f82ca3fb0a2f1ec16467955b1106f12aeca616262cf2af05` |
| `crates/routertop/src/ipv6.rs` | `4a20d9c56ca47ae2d5ca3bc8162fa20f62d2eda0119bf48bdf5f14092ade67cf` |
| `crates/routertop/src/lib.rs` | `a093fe06042507dc6e39505606085b7984707eb17ba9348887e1f9917cdbb008` |
| `crates/routertop/src/main.rs` | `31b12b3d126b3309bbdde86d87cb830547a2ba4d51ce691620698d5a867f2ee6` |
| `crates/routertop/src/network.rs` | `df9bffe01f8f7507f02162fb00ad23433b7e439fd352017effbdfe7bff22984c` |
| `crates/routertop/src/web.rs` | `09e9f844188ac437d9b056cf078597c73149d2150e12c44e196c7b08375234d7` |
| `web/app.js` | `2996e3548abab1b0d8f5c85e9b7d945739570c3274b6f22cf6465d2d4c38b857` |
| `image/overlay/usr/sbin/routertop-boot` | `c44e10ba4e7b703e9d0777a6d38a1bec72ff89c69947f2e8b70361c14af2e8ec` |
| `image/overlay/usr/sbin/routertop-ipv6-start` | `3ad00d07fc6853bcc095486dc28189936b566b658917647506cebfe1a7952f16` |
| `image/overlay/usr/sbin/routertop-ipv6-hook` | `569a6bbc18eae74ab3dc1f387f6db9a9d5a6badeadffbf776087adedf2318eba` |
| `image/overlay/usr/sbin/routertop-dns-supervisor` | `19354fc7aa9039fd96503c32144395a1bcce2a0d1ea27a5dff21e50e059403c5` |

Next owner: root integrates actual packet/browser/image evidence and verifies the exact pushed commit and hosted CI. No open item from this scoped review calls for another broad review.

## Focused runtime-fix follow-up (r4)

Requested by root after real Linux/image acceptance discovered two integration mismatches. This follow-up inspected only those two fixes and their corresponding tests; it did not repeat the full review. **PASS: no new finding in these two changes.**

1. **dhcpcd hook field name.** `lease_from_env()` now reads the prefix address from the bare indexed field `new_dhcp6_ia_pd1_prefixN`; `_length`, `_pltime`, and `_vltime` remain separate suffixed fields. It continues through canonical IPv6 parsing and the existing lifetime checks. The updated test now asserts that the real field shape produces one parsed `/56` and two delegated `/64` entries, in addition to rejecting injection and invalid lifetimes. This closes the previous empty-prefix result instead of merely accepting a renamed synthetic fixture. Inspected `pd.rs` SHA256: `13e4ee4b79712f597f30b1713dc19944f322908c3849785c8171c88693f87e2c`.
2. **Explicit IPv4 client selection.** The generated WAN `inet dhcp` stanza now contains `dhcp-program udhcpc`. This keeps IPv4 acquisition with its existing client after the dhcpcd package is installed, while the dedicated IPv6 startup remains IPv6-only. The literal is fixed, introduces no user-controlled command, and the existing default-render test asserts its placement in the WAN stanza. Root reported inspection of the actual installed ifupdown-ng executor's `IF_DHCP_PROGRAM` support. Inspected `lib.rs` SHA256: `49ad437517ee78f019572e47f7c5655aadc3d1c749cde97386ac91ce53dbd72f`.

Evidence inspected: [r4 Windows checks](../evidence/v05/windows-checks.json) records 75 tests plus format/lint/syntax PASS, exit 0, and both matching source hashes. [r3 PD packet result](../evidence/v05/network-v05-results-r3.jsonl) records 16 real packet cases PASS; [its artifact record](../evidence/v05/r3-packet-artifact.json) explicitly identifies it as preceding the IPv4 client-selection fix. Therefore r3 packet evidence is not presented as final r4 ISO proof. Final r4 image boot/browser/cold-boot and hosted CI were still pending at this focused follow-up; the integrator owns those later results.
