# RouterTop 0.8 — dual-WAN IPv6 and prefix delegation

Base: fcc8c02b742ffeac4531423f78be82cd098c4966. User authorizes implementation, isolated lab verification, commit and public push. Runtime target is Alpine x86_64; retain ARM source reservation, local light Apple-inspired UI and compact dependencies.

## Scope / initial gates

Extend 0.7 primary-only IPv6/PD to active/standby provider switching across DHCP and PPPoE. Preserve existing configuration compatibility and administrator/TLS/PPP identities. Withdraw retired provider addresses, DNS, routes and firewall authorization before activating the replacement; asynchronous old-provider hooks must not resurrect them. Recover the preferred provider and reacquire changed prefixes without changing saved configuration/revision. The bounded architecture spike selected high effort and completed. The frozen schema/process/identity contract is [network-v0.8-contract.md](network-v0.8-contract.md).

The image-size documentation must prioritize SquashFS (zstd/xz) plus overlay or a separate configuration partition. Subsequent priorities are kernel trimming, Alpine package cleanup, qcow2/sparse storage reduction, then advanced initramfs reduction. Measure boot payload, ISO, data disk, RAM and host storage separately; document roadmap work without inventing an implemented storage-format migration.

Adaptive Reasoning Router is explicitly invoked. Inspect actual selected model/effort, use its external CLI launcher for the bounded architecture job, retain sanitized setting evidence, and distinguish any child-job effort change from the active parent turn. Do not change global model/provider/configuration or claim a prompt changed native effort.

| Owner | Worktree / scope |
|---|---|
| Adaptive CLI architect | Read-only existing root; textual schema/lifecycle advisory only |
| core, after contract freeze | .worktrees/v08-core; Rust model/compiler/runtime/CLI, non-Web tests and image overlay |
| web | .worktrees/v08-web; Web assets, web.rs/Web tests and actual browser harness |
| network test | .worktrees/v08-test; network-v08 harness, ISP fixtures, isolated Linux packet lab |
| root | Integration, plan/spec/docs, version/CI, source/artifact binding, actual ISO lifecycle, commit/push |
| independent reviewer | One scoped routing/provider-generation/lifecycle pass and focused closure |

One author per worktree; no other owner's changes reverted. Authors do not commit/push. Serial/VM ownership is explicit; no host NIC bridging or physical-disk provisioning.

AC1: old/new config and credential compatibility, validation, deterministic render, fmt/test/Clippy.

AC2: real dual-provider DHCP/DHCP, DHCP/PPPoE, PPPoE/DHCP and PPPoE/PPPoE IPv6/PD packets; active-provider LAN/VLAN SLAAC and routed IPv6 HTTP.

AC3: carrier loss/upstream blackhole, initial backup-only boot, prefix replacement, old-source/standby authorization denial, both-down isolation, preferred-provider restoration and stale-hook race rejection.

AC4: actual final ISO Web save/reload, reboot and cold boot preserve settings/admin/TLS/PPP credentials/provider identities; per-provider prefixes return and old sessions expire; desktop/mobile UI checked.

Actual-ISO refinement: RC1 failed the initial backup-ready predicate despite successful DHCPv6 renewals. A real authenticated CGI comparison reproduced root-ready versus UID-1000-unready because the latter could not read private `provider.json`. R3 fixes public snapshot correlation without widening private permissions. RC2 must pass root/UID-1000 equality, stale/degraded/mismatched snapshot rejection and a fresh actual-ISO lifecycle run; RC1 packet success does not close those replacement gates.

AC5: measured image/binary/Web/package growth and ordered SquashFS-first size roadmap, with actual implemented and NOT_RUN work distinguished.

AC6: scoped independent review; actual public remote head and exact-commit hosted CI; explicit Adaptive Router outcome with actual native setting evidence.

All new gates start NOT_RUN. Lab-only tools and raw logs/secrets/enrolled disks remain ignored. Physical NICs/real ISPs, ARM, throughput/load, power-loss and production signing remain separately NOT_RUN.
