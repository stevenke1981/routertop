# RouterTop 0.6 acceptance

Scope: PPPoE WAN, IPv6/PD on PPP, Web and private credential persistence, real dialing/reconnect/reboot. Base 3991768b388257cef792a5cb1d8fdbaf609d6957. [Plan/owners](plan-v0.6.md).

| Gate | State | Evidence |
|---|---|---|
| Compatible Rust configuration and private Web credential handling | PASS on Windows r2 | 84 final r4 tests, fmt/clippy/JS syntax; Linux permission assertions recorded separately |
| Real PPPoE discovery/authentication, routed IPv4 and wrong-password denial | PASS | [Final release r4 17 cases](../evidence/v06/network-v06-release-report.json), including both WAN families, 120 KiB LAN/VLAN traffic, wire MSS and checksum assertions |
| IPv6CP, actual DHCPv6-PD, LAN/VLAN SLAAC and routed IPv6 | PASS | Standard 17 cases plus [6 PD-only cases](../evidence/v06/pd-only-release-report.json): IA_NA NoAddrsAvail, no WAN GUA, actual IA_PD and default route |
| Session loss/reconnect, old-prefix withdrawal and new delegation | PASS on release r4 | Standard and PD-only real ISP interruptions, renamed prefixes, retired source denial, lease expiry and stable DUID; final ISO lifecycle recorded separately |
| Final ISO Web, credential/settings/admin/TLS/DUID retention after reboot and cold boot | PASS on r4 | [Actual Chrome report](../evidence/v06/browser/browser-v06-report.json): 10 groups, 6 real-ISO lifecycle groups, 5 visual audits; BIOS and UEFI, same 256 MiB lab disk |
| Size/package/source/artifact verification | PASS | [Artifact verification](../evidence/v06/artifact-verification.json): final ISO 63.62 MiB, +376 KiB; runtime 65 packages, no new Rust/frontend dependency |
| Independent scoped review | PASS | [One pass and focused two-fix closure](review-v0.6.md); no open findings |
| Public push / exact remote head / current CI | Recorded after commit | Corresponding commit checks in [GitHub Actions](https://github.com/stevenke1981/routertop/actions) and final delivery; local PASS does not imply hosted CI success |

All lab networking is isolated using disposable Linux namespaces and socket Ethernet between VMs. Host NICs and physical disks are not reconfigured. Raw PPP passwords, client identities, private keys, cookies, terminal captures and enrolled disks are excluded from public evidence. ARM, physical NICs/ISPs, load/throughput, destructive power-loss and production signing/update remain NOT_RUN.

## Findings resolved during implementation and lab setup

- Exact Alpine kernel configuration confirmed no native PPPoE module; use ppp-daemon/rp-pppoe over the supported PPP generic/async modules, avoiding a larger kernel change or unused PPP meta-package plugins.
- Independent review found the missing logical `ppp0` firewall selector and a CLI `apply` path retaining legacy 0644 active-config permissions. The selector now includes PPP WAN; atomic private creation/replacement uses 0600 with the management-service owner. Focused tests and independent follow-up close both findings.
- PPP daemon hooks inherit restrictive umask: public WAN status now explicitly sets 0644, while the credential peer stays 0600. This avoids a successful PPP session appearing perpetually dialing to CGI.
- Initial test-server discovery worked but pppd execution required an explicit absolute path through rp-pppoe server's `-q` argument. This changes the lab fixture only.
- Actual pppd source/trace showed lifecycle scripts under the lab's `/tmp` workspace are intentionally rejected because an ancestor is world-writable. The packet lab now uses a private root-owned directory under `/var/lib`; pppd's security check remains enabled. Product hooks are already under `/usr/sbin`.
- TCG unit and optimized builds are slow; the first 600-second foreground command expired while release compilation was still active. The build was preserved and observed, not treated as a packet failure or blindly restarted. r1 Linux unit checks passed 82 tests; final candidate checks are version-scoped separately.

- Real exec tracing found pppd clears sbin directories from hook PATH. All four production PPP lifecycle hooks now export the fixed Alpine system PATH before invoking routertop and DHCP/network tools. Test wrappers mirror that actual line; no permission or daemon security check is disabled.

- Real ISP-side capture proved rp-pppoe userspace MSS adjustment corrupts a VLAN SYN checksum by eight while LAN SYN succeeds. Removing only that adjustment restores both flows; final product moves MSS clamping into nftables and requires fresh release/image acceptance. r3 Web/reboot success is not final r4 packet acceptance.
- The first actual browser run passed save/reboot but attempted to click the hidden IPv6 refresh button after returning to WAN settings. The harness now selects the IPv6 page before that action; this is a test navigation fix.

- Two parallel Windows Web tests collided because their temporary directory name used only PID and the clock timestamp. A per-process atomic sequence now makes each directory unique; the full final 84-test Windows run and Clippy pass. This is a test helper change, not an appliance behavior change.

## Final r4 artifact and acceptance scope

ISO: **66,705,408 bytes / 63.62 MiB**, **376 KiB** above v0.5. Kernel + initramfs: **53,583,437 bytes / 51.10 MiB**, below the 64 MiB compressed boot budget. Rust binary: **1,262,208 bytes / 1.20 MiB**; Web assets: **98,544 bytes / 96.23 KiB**. Runtime packages: **65**, four above v0.5 (`ppp-daemon`, `rp-pppoe`, `libpcap`, `ifupdown-ng-ppp`). The data image stays 33 MiB. Python, packet fixtures and development tools are lab-only. No new Cargo or frontend dependency.

ISO SHA256: `284b81fa9ae3f9b1bb77012aa002e19d8e52dec0a83e3ebd1fc9158979b0ceb7`.
Release binary SHA256: `9b088b194e417c1c8bcda0607321932e7f5a9f7d270a3eaa2e5b8cf9c11103b2`.

Final release r4: 17 real network cases PASS, including PAP rejection, IPv4/IPv6 LAN/VLAN HTTP, four 120 KiB transfers, actual MSS/checksum observations, unsolicited WAN denial, no DHCP underlay fallback, renumbering, old-source denial, reconnect, expiry and DUID preservation. The targeted PD-only extension adds 6 PASS groups with actual IA_NA NoAddrsAvail and usable IA_PD without a WAN GUA. The standard report identifies its tested harness hash before the additive PD-only CLI extension; default behavior is unchanged. Both actual exit codes are zero, with binary identity recorded.

Final r4 ISO: 10 browser groups and 6 upstream lifecycle groups PASS. Same-volume Web reboot and authenticated poweroff/UEFI cold boot preserve user config, revision, admin login, TLS identity, PPP private peer material (0600) and DUID. Old Web sessions fail after reboot; final authenticated poweroff closes HTTPS/serial and root separately verifies the QEMU process exited. Source/build/artifact hashes and the launched ISO path are independently verified; no claim is made of a retained live-binary digest in browser output. Private digests are compared in memory and excluded from public reports.

The BIOS idle sample reports MemTotal 220,724 KiB and MemAvailable 114,844 KiB. This is one sample, not a minimum-RAM, throughput or load guarantee. [Desktop after UEFI cold boot](../evidence/v06/browser/pppoe-after-uefi-cold-boot.png), [IPv6/PD](../evidence/v06/browser/pppoe-ipv6-pd-desktop.png), [mobile](../evidence/v06/browser/pppoe-mobile.png). The light interface uses local assets without a frontend framework.

Version boundaries: r1 Linux unit checks passed 82; two affected Unix permission checks ran under umask 077 on r2. Windows final r4 passes 84, including the added kernel-MSS regression and the unique-directory helper fix. R3 Web/reboot and experimental private-peer tests are diagnostic history only; all final packet and full image lifecycle results above use r4. The original build manifest keeps its build-time `boot_test: NOT_RUN`; later actual boot evidence is recorded here. Existing VLAN/WireGuard/static IPv6/console packet regressions and a full fresh Linux test run are run by the final hosted workflow; exact result belongs to that commit's checks and delivery record.

Limitations: a single PPPoE WAN/session, MTU 1280–1492, IPv4 IPCP plus optional IPv6CP, the existing one-PD-association /48–/64 and up-to-16 delegated VLAN contract, globally scoped/ULA automatic IPv6 DNS, and reboot activation. IPv4 DNS uses the explicit DNS settings. Service-name selection, arbitrary underlay VLAN provisioning, jumbo/multilink/IPv6-only PPP, physical ISP interoperability, ARM, hardware throughput/load, destructive power-loss, signing and production deployment are **NOT_RUN/outside this release**. This remains a development image. See [the configuration/runtime contract](network-v0.6-contract.md).
