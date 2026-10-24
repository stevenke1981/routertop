# RouterTop 0.8 acceptance

Candidate: `rc2`, based on `fcc8c02b742ffeac4531423f78be82cd098c4966`. Local acceptance is **PARTIAL**: the final optimized packet/permission suite passes, but the complete actual-ISO lifecycle remains open. This development-source delivery does not declare that remaining gate passed. Hosted CI is checked against the pushed commit and reported separately.

## Implemented scope

Opt-in `ipv6.provider_policy = "active-standby"` follows the existing IPv4 WAN health/hysteresis selection across DHCP and PPPoE. Both providers support automatic IPv6 and DHCPv6-PD, shared LAN/VLAN subnet allocation and DNS settings. Selection withdraws old authorization, prefixes, addresses, routes and DNS before starting the replacement client. Immutable provider epochs and supervised PPP process identity reject delayed old callbacks, including A → B → A transitions. Each slot retains its own private persistent DUID.

Web settings preserve the existing light Apple-inspired interface and legacy clients' saved policy. The default remains `primary-only`. Settings take effect on reboot through the existing atomic persistent bundle and revision flow. IPv6-only upstream failure does not independently switch providers while the IPv4 health checks still consider the active WAN healthy.

## Current evidence

| Layer | Result | Evidence / boundary |
|---|---|---|
| Windows Rust | PASS | 103 tests; fmt and Clippy with warnings denied; [checks](../evidence/v08/windows-checks.json) |
| Browser fixtures | PASS | 9 groups and 5 desktop/mobile visual audits; [report](../evidence/v08/browser-fixture/browser-v08-report.json); real browser with local API fixtures |
| Scoped independent review | PASS | [One pass and focused closure](review-v0.8.md); one monitor cleanup race fixed; static scope only |
| Odin | PASS | [Project-scoped real Rust LSP navigation](../evidence/v08/odin.json); no compiler/runtime claim |
| Adaptive Router | PASS | [Native child settings](../evidence/v08/adaptive-reasoning.json): same child session medium → high, successful architecture job; active parent remained medium |
| Actual CGI permissions | PASS | RC1 root/UID-1000 contrast reproduced the failure; RC2 passes 10 authenticated CGI checks, with private epoch still denied; [regression evidence](../evidence/v08/actual-iso-regression.json) |
| Final optimized Linux packets / CGI | PASS | 89 checks, seven commands exit 0; four DHCP/PPPoE combinations, LAN/VLAN prefix switching, stale hooks, DNS, primary-only and real working/unavailable WireGuard regressions; [report](../evidence/v08/network-release.json) |
| Actual ISO Web / warm reboot | PASS for completed checks | Fresh setup, five visual audits, both credentials/settings/TLS persistence, expired old session and backup IPv6/PD readiness; complete lifecycle is not yet passed |
| Actual ISO routed IPv6 HTTP | PASS for initial backup | Classified same-config reboot probe reached the backup HTTP marker; subsequent DNS command failed and is being checked separately |
| Actual ISO full lifecycle / UEFI cold boot | OPEN / NOT_RUN | Full live prefix renewal, same-boot failover/recovery, final cold-boot identity persistence and authenticated cleanup remain required |
| Final size/source binding | PASS | [81 immutable inputs, binary/image hashes and explicit test-only additions/overrides](../evidence/v08/artifact-verification.json) |
| Public exact-commit CI | Checked after push | Repository Actions and delivery record identify the actual pushed head; local evidence does not substitute for hosted results |

RC1 passed 79 optimized packet checks but failed actual ISO backup-readiness after seven preceding browser checks. Its private provider epoch was unreadable to CGI UID 1000, so Web recomputation incorrectly cleared readiness despite real DHCPv6 renewals. R3 publishes only a nonsecret generation and correlates fresh public snapshots; private epoch/token/incarnation permissions remain unchanged. RC2 replaces the binary and image, and requires its own packet and full ISO lifecycle results. The separate review records this focused closure.

Local QEMU 11.1 with CPU `max` panicked during IO-APIC timer setup with both RC1 and the unchanged 0.7 control ISO. An initial single-thread `icount` workaround reached boot but did not close the lifecycle gate. The latest RC2 test uses q35, CPU `qemu64`, normal multi-thread TCG, no icount, 256 MiB and two virtual CPUs; BIOS boot and the completed checks above passed. The distributed basic launcher does not force CPU `max`. These are VM configuration changes, not ISO/kernel-argument changes; physical hardware is not certified. See [environment observations](../evidence/v08/boot-environment.json). QEMU documents icount and its single-thread restriction in its [primary documentation](https://www.qemu.org/docs/master/devel/tcg-icount.html).

Two read-only console diagnostic attempts were rejected before execution by automatic approval review with the sole reason `blocked by policy`. They were not retried through another route. Classification continued through the already authorized functional HTTP/DNS checks and API reboot; no blocked log/process/route-read payload was executed.

## Measured size

| Artifact | RC2 bytes | Comparison with 0.7 |
|---|---:|---:|
| ISO | 66,775,040 | +28 KiB |
| Compressed kernel + root | 53,653,979 | 51.17 MiB; below the 64 MiB boot-payload target |
| Optimized Rust executable | 1,417,856 | +64 KiB |
| Web assets | 111,097 | +1,732 bytes; no frontend framework or CDN |
| Runtime packages | 65 | unchanged |
| Factory-blank settings disk | 34,603,008 | 33 MiB logical file; separate from the OS payload |

## Size priority and limits

[The size roadmap](image-size-roadmap.md) puts SquashFS zstd/xz plus overlay or an independent settings partition first, followed by kernel trimming, Alpine cleanup, qcow2/sparse compression and advanced initramfs reduction. This version documents that order; those storage-format changes are **NOT_RUN**.

Physical ISP/NIC/hardware trials, ARM builds/boot, throughput/load, power-loss durability and production signing are **NOT_RUN**. All live networking uses isolated VM/network-namespace providers rather than host NIC bridging. Lab credentials, raw serial logs and enrolled settings disks remain private ignored files; the distributable settings disk is factory blank.
