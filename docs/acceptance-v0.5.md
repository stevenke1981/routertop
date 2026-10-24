# RouterTop 0.5 acceptance

Scope: dynamic IPv6 WAN, DHCPv6-PD, Web configuration and persistence, disconnect/reconnect, prefix updates, and reboot retention. Baseline: `029a08477fac33030b927e88cd96d41abb168d38` (0.4).

Implementation plan and ownership: [plan-v0.5.md](plan-v0.5.md). This report is updated only from actual executed checks. Until recorded below, a gate is NOT_RUN.

| Gate | State | Evidence |
|---|---|---|
| Rust validation / rendering / persistence tests | PASS | Windows r4: 75; Linux r3: 76; final r4 IPv4-client selection focused Linux check 1/1 PASS |
| Linux real DHCPv6 IA_NA / IA_PD / RA / SLAAC | PASS on final r4 release | [16 packet assertions](../evidence/v05/network-v05-results-r4.jsonl), including actual learned IPv6 DNS and WireGuard full-tunnel leak prevention |
| Disconnect / reconnect / renewal / changed prefix / expiry | PASS | Final r4 packets plus 6 real-ISO lifecycle assertions: actual link loss/recovery, renewed prefix, retired kernel/firewall addresses, expiry, and unchanged saved config |
| IPv4 / static IPv6 / WireGuard regression | PASS on r3 | network03 15/15 and network04 17/17; r4 changes only IPv4 DHCP program selection |
| Actual Web desktop / mobile settings and status | PASS | [Final Chrome report](../evidence/v05/browser/browser-v05-report.json): 9 groups and 5 visual audits; fixture-specific conflict/status checks separately [5 groups](../evidence/v05/browser-fixture/report.json) |
| Final image reboot and cold boot / saved modes and identity | PASS | QEMU TCG BIOS and UEFI at 256 MiB; saved config/revision/admin/TLS retained, old sessions denied, DUID unchanged, prefix reacquired after cold boot; authenticated final poweroff and process exit |
| Image size and hashes | PASS | [Artifact and normalized source verification](../evidence/v05/artifact-verification.json); final ISO 63.25 MiB, +220 KiB |
| Independent scoped review | PASS | [review-v0.5.md](review-v0.5.md), including focused follow-up for the two runtime fixes |
| Public push / exact remote head / hosted CI | Recorded after commit | See the corresponding commit in [GitHub Actions](https://github.com/stevenke1981/routertop/actions) and the delivery response; local tests do not imply hosted CI success |

Lab: disposable Alpine x86_64 builder with network namespaces; separate isolated upstream ISP VM connected to the appliance by QEMU socket Ethernet. No host-NIC bridge or physical disk changes. The test DHCPv6 server is a bounded fixture exchanging actual UDP packets; it is not included in the runtime image. Public evidence excludes credentials, DUID values, populated disks, raw console logs and private keys.

Size baseline: ISO 66,095,104 bytes; kernel plus initramfs 52,974,428 bytes; Rust binary 1,110,656 bytes; Web assets 85,610 bytes. Final measured growth is recorded below.

Implementation reference: [dhcpcd 10.5.2 configuration manual](https://github.com/NetworkConfiguration/dhcpcd/blob/v10.5.2/src/dhcpcd.conf.5.in). Runtime behavior is verified independently of manual claims.

## Findings resolved during validation

- Independent review identified repeated DNS/DHCP restarts for an insufficient actual delegation. The monitor now requests a restart only when RA policy changes; the repeated-degraded-state regression passes.
- Actual DHCPv6 exchange exposed a hook-field mismatch: dhcpcd 10.5.2 supplies the prefix at `new_dhcp6_ia_pd1_prefix1`, without a trailing `_prefix`. The parser and regression fixture were corrected using the observed field names. No identity values were copied into public evidence.
- The local lab archive initially used zero source timestamps, allowing Cargo to reuse an old binary after extraction. The transfer helper now stamps current source times, and the Linux test runner forces fresh source timestamps before rebuilding. Only results from the recompiled binary count toward acceptance.
- Actual ISO boot showed that installing dhcpcd changes ifupdown-ng's default DHCP-program selection, including the IPv4 WAN. The generated IPv4 stanza now explicitly selects `udhcpc`, preserving the existing bound/renew checks and separating it from the dedicated IPv6 client. Final image acceptance uses the rebuilt candidate.
- The Windows cold-boot test launcher inherited captured output pipes into the new QEMU process, leaving the harness waiting before it could connect to the serial listener. Redirecting launcher output to DEVNULL fixes this harness issue; the same final ISO is rerun from a fresh disposable data disk.

## Final artifacts and scope

Final ISO: **66,320,384 bytes / 63.25 MiB**, exactly **220 KiB larger** than v0.4. Kernel plus initramfs: **53,199,411 bytes / 50.73 MiB**. Rust binary: **1,217,152 bytes / 1.16 MiB**. Embedded Web assets: **93,531 bytes / 91.34 KiB**. Runtime packages: **61**; the sole added package is `dhcpcd-10.5.2-r1`, with no new Cargo dependency or frontend framework. The provisioned blank data image remains 33 MiB. Python and the test DHCPv6 server are lab-only.

Final ISO SHA256: `35a509558a50e4640ae904d0ba1db256c749626cbe9a785e8965ddd1741979b6`.
Final release binary SHA256: `d9d554fb2e41ec020a10bea96dc8ace77a0f7466b2c07ae18f6869c4faad6686`.
Local artifacts: `dist/v0.5/`. Public source does not contain binary images or enrolled data disks. The final browser launcher booted this verified ISO path; its generic secret redactor also removes 64-character binary digests from the console observation, so the browser report is not a retained runtime-digest comparison. Source/build/artifact hashes are recorded independently in artifact-verification.json.

The final BIOS sample reported MemTotal 220,724 KiB and MemAvailable 117,404 KiB. This is one idle sample, not a minimum-RAM or throughput guarantee. Actual UI: [after reboot](../evidence/v05/browser/ipv6-pd-after-reboot.png), [after UEFI cold boot](../evidence/v05/browser/ipv6-pd-after-uefi-cold-boot.png), [mobile](../evidence/v05/browser/ipv6-pd-mobile.png). The cold-boot image reacquired the changed `2001:db8:200::/56` fixture prefix while keeping LAN/VLAN subnet IDs and persistent client identity.

Version boundaries: full Linux 76-test and 15/17 packet regressions used r3; final r4 only adds explicit IPv4 `dhcp-program udhcpc` selection and its assertion. Windows 75 tests, the affected Linux unit, final PD 16 packets, and full image/browser lifecycle/cold boot were checked on r4. The original build manifest retains its build-time `boot_test: NOT_RUN`; later acceptance is recorded here rather than mutating the build manifest.

Remaining limitations: one dynamic WAN and one delegated association, /48–/64 request/grant range, at most 16 delegated VLANs, and globally scoped/ULA learned DNS (link-local learned DNS is not supported). Static LAN/VLAN IPv6 and delegated addressing are mutually exclusive. Settings changes activate after reboot. This is a development image, not a RouterOS-parity or production-readiness claim. **NOT_RUN:** ARM/physical NIC boards, arbitrary real ISP interoperability, throughput/load, destructive power-loss injection, signed package release and production deployment. See [the configuration/runtime contract](network-v0.5-contract.md).

## Hosted CI portability follow-up

The first two hosted runs (`40068963198`, `40069477831`) passed Windows and Alpine image builds, plus the existing 15/17 packet regressions, but the Ubuntu PD lab timed out before DHCP exchange. Added bounded startup diagnostics showed a live client with all mount/exec stages complete and no hook events. The exact Ubuntu dhcpcd package contains a udev plugin; its network-namespace detection depends on `/var/run/netns`, hidden by this lab's private `/run`. This leaves pre-created veth interfaces waiting for udev initialization. The harness now uses documented `--nodev` to skip device-management plugins in this isolated namespace; real DHCPv6/RA/netlink, privilege separation and all packet assertions remain enabled. No appliance/runtime input changed, so the final r4 ISO and browser evidence remain applicable. The outcome of the corrected exact-head hosted run is linked in the delivery response.
