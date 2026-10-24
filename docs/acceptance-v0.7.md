# RouterTop 0.7 acceptance

Base: a698bdce2952c99da9e4ff0f7515df138afe7630. Final candidate: **r4-final**. Local implementation, actual packets, actual ISO and hosted CI are separate evidence layers.

| Gate | Result | Evidence |
|---|---|---|
| Compatible model, fixed IP validation, dual secrets, compiler | PASS | [Windows](../evidence/v07/windows-checks.json): 96 tests, fmt and Clippy on final sources |
| Actual fixed-IP and dual DHCP/PPPoE packet matrix | PASS | [Final network report](../evidence/v07/network-v07-r4-final-report.json): 62 groups, all eight scenarios, exit 0 |
| Carrier loss, upstream blackhole, automatic restoration, both-down isolation | PASS | Same 62 groups; real LAN NAT HTTP, both WAN deny with live-listener positive control, per-interface probe isolation and unchanged settings |
| Initially unavailable PPP primary, late recovery and primary-only IPv6/PD | PASS | [13 focused groups](../evidence/v07/network-v07-focused-r4.jsonl), repeated in final matrix; actual PD/SLAAC/IPv6 HTTP, prefix change/withdrawal and stable DUID |
| Existing single PPPoE / PD-only regression | PASS | [17 standard](../evidence/v07/network-v06-regression-r4.jsonl) and [6 PD-only](../evidence/v07/network-v06-pd-only-regression-r4.jsonl), exit 0 |
| Linux unprivileged credential-export restriction | PASS | [Public JSON summary](../evidence/v07/linux-cli-checks.json): ordinary public config allowed; PPP backup credential export denied. Original CLI log remains private |
| Real Chrome fixture | PASS, fixture scope only | [UI handoff](../evidence/v07/ui-handoff.json): 8 groups and 4 visual audits; distinct from actual appliance proof |
| Actual final ISO Web, reboot and UEFI cold-boot persistence | PASS | [Actual Chrome](../evidence/v07/browser/browser-v07-report.json): 13 groups, 5 upstream lifecycle groups, 6 visual audits; 256 MiB VM |
| Runtime/build-source and artifact binding, measured size | PASS | [Artifact verification](../evidence/v07/artifact-verification.json), [image acceptance binding](../evidence/v07/image-acceptance-manifest.json) |
| Independent scoped review | PASS | [One pass and focused corrections](review-v0.7.md); no open confirmed findings |
| Public commit/push / exact-head hosted CI | Tracked after commit | [GitHub Actions](https://github.com/stevenke1981/routertop/actions) and the final delivery record identify the actual commit and conclusions; local PASS does not imply hosted success |

The final network harness SHA256 is `c5886069eee6133f6d2eed4e007447f4064089f13729f62bc88240fabb579de1`. The fixed initial-backup case first keeps the PPP server disabled, requires working DHCP backup and no unintended DHCPv6 master, then enables PPP and requires real IPv6/PD without reboot. All final runs use the compiled production fix: no test-side reverse-path-filter or DHCPv6-stop bypass. The 13 focused groups repeat within the 62-group matrix; do not add them as unique coverage.

The eight scenarios are standalone fixed IP, fixed-IP/DHCP, DHCP/fixed-IP, DHCP/DHCP, DHCP/PPPoE, PPPoE/DHCP, PPPoE/PPPoE, and PPPoE/DHCP with primary IPv6/PD. All protocol pairs have model/compiler tests; packet evidence is limited to this explicit matrix. Source-byte hashes and actual exit codes appear in the reports and role handoffs. Namespace inventory was empty after cleanup.

## Final r4 image

- ISO: **66,746,368 bytes / 63.65 MiB**, **40 KiB** above v0.6.
- Kernel + initramfs: **53,625,306 bytes / 51.14 MiB**, below the 64 MiB compressed boot budget.
- Rust binary: **1,352,320 bytes / 1.29 MiB**. Web assets: **109,365 bytes / 106.80 KiB** normalized LF.
- Runtime packages: **65**, unchanged. No new Rust or frontend dependency. Factory blank data disk: **33 MiB**, separate from the enrolled disposable test disk.

ISO SHA256: `b670017e38fd6158396c26d1f7eefd867b901010b2e88d462cf950f303260be2`.
Release binary SHA256: `2333d78fdbd34724295c80a2be410fd0a19c39dafa369f51dd896a2fa5c1c104`.
Runtime/build input archive SHA256: `e4c5a618a7a09085ab2f185e8e4bd95b1b2d2edad01ebd60625c253450dbe56e`.

Actual BIOS/reboot/UEFI cold boot used the same final ISO and data volume. Web saved fixed IP/DHCP/backup modes and then both PPP credentials plus IPv6/PD. Settings/revision, administrator, TLS identity, both 0600 PPP peers and DUID survived. Stale sessions failed after reboot. Initial backup-only startup explicitly proved there was no DHCPv6 master, stale delegated address or authorization; enabling the primary recovered real PPP/PD without reboot. Blackhole and PPP session loss then selected backup IPv4 and withdrew primary IPv6; restoration returned primary IPv4/IPv6/PD. Root independently verified the final authenticated poweroff ended the appliance process, and shut down the disposable ISP VM.

The build manifest retains its build-time `boot_test: NOT_RUN`; later actual boot proof is recorded separately. No retained live-binary digest is claimed: source/build/artifact hashes, launched ISO path and browser observations bind the acceptance. A boot on 256 MiB is not a minimum-memory, load or throughput guarantee. [UEFI screenshot](../evidence/v07/browser/dual-wan-after-uefi-cold-boot.png), [mobile](../evidence/v07/browser/dual-wan-mobile.png).

## Resolved findings and evidence boundaries

1. Independent review reproduced custom primary-only firewall rules being copied onto backup. The generator now preserves exact user interface scope; focused rerender and regressions close the finding.
2. Real DHCP/DHCP acquisition succeeded but bound probes were dropped by Linux reverse-path checks before a main default existed. A controlled same-binary test changed only those settings and restored probes and LAN HTTP. The dual-only production profile now covers all/default and existing physical interfaces; future PPP interfaces inherit the appropriate default. Single WAN remains unchanged.
3. The last mixed PPP/DHCP IPv6 case exposed Alpine dhcpcd 10.5.2 starting a default-config daemon when `dhcpcd -6 -x` was called with no daemon. This occurred when backup was selected before the PPP primary. The final fix stops only a verified live master in the same network namespace, bounds termination/startup, serializes lifecycle operations and rechecks the selected role after locking. Both initial-backup packet and actual-ISO regressions pass. Superseded r3 positive BIOS/UEFI tests did not exercise that startup order and are not final acceptance.
4. A repeated standalone test inherited `/run/ifstate` from an earlier namespace, so ifup skipped its new interface. Giving that test a fresh private `/run`, while preserving the old global file, restored actual static routing. This is a test-isolation fix; final production/ISO bytes did not change.
5. A fixture-only manual DHCP probe had changed the disposable builder resolver. Restoring the QEMU resolver allowed the same image inputs to build. Failed attempts and diagnostic overrides are retained in ignored lab history, not counted as final PASS.
6. The new WAN startup hook is committed executable (100755), matching its tested source-archive and ISO mode; Linux checkouts must preserve it. No source-script permission grant is inferred from Windows filesystem attributes.

## Scope and untested areas

This is IPv4 active/standby, not load balancing or seamless connection migration. Configured ICMP responders define health; existing TCP/VPN sessions may need reconnecting when the source IP changes. IPv6/PD is **primary-only**: backup supplies IPv4 while primary delegation/DNS/authorization are withdrawn, and primary return reacquires the prefix. Dual WAN with IPv6 requires automatic primary IPv6; existing single-WAN static IPv6 remains available.

Lab networking uses disposable namespaces and socket Ethernet; no host NIC bridging or physical-disk provisioning. Passwords, tokens, cookies, raw PPP logs, private client identities and enrolled disks are excluded from public evidence. ARM, physical NICs/real ISPs, throughput/load, destructive power-loss, installer/upgrade signing and production deployment are **NOT_RUN**. This remains a development image. See [the contract](network-v0.7-contract.md), [plan](plan-v0.7.md) and [team handoff](../evidence/v07/team-handoff.json).
