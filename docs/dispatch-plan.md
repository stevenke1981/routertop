# RouterTop implementation contract

Current v0.5 scope, owners and acceptance gates are in [plan-v0.5.md](plan-v0.5.md). The original initial-image contract below is retained as historical context; the user has authorized v0.5 commit and public push.

Requested: compact Linux / Alpine / apk router OS, Rust control plane, x86_64 first, ARM reserved, agent team and Odin assistance.

Initial tree: empty. No existing product or acceptance evidence.

Deliverable: bootable x86_64 development image, bounded Rust configuration validation/rendering, router CLI, isolated VM smoke evidence, package architecture, honest feature matrix. Full RouterOS parity remains a multi-release objective, never inferred from Linux package availability.

Owners: core worker owns crates/routertop/src/lib.rs and configs/routertop.toml; image worker owns image/, packaging/, scripts/build-image.sh and scripts/boot-qemu.ps1; integrator owns CLI, root manifests, tests, documentation and validation. Independent reviewer checks resulting candidate once. Authors use separate worktrees; integrator transfers scoped files.

Frozen library API: pub fn parse_config(&str) -> Result<Config,String>; pub fn render(&Config) -> Result<Rendered,String>. Rendered has public String fields interfaces, nftables, dnsmasq, sysctl. Config serde serialize/deserialize. Interfaces eth0 WAN DHCP, eth1 LAN static by default. LAN 192.168.88.1/24; pool .100-.199. Strict validation; no user shell interpolation. nftables table inet routertop, drop unsolicited WAN input/forward, LAN forwarding and masquerade. IPv6 forwarding disabled until supported. CLI check/render/apply/status/export; apply root Linux only and never on host during development.

Acceptance: Rust unit and CLI tests; Linux build and tool syntax checks; actual QEMU boot and DHCP/DNS/NAT where environment permits; compressed artifact size target <=64 MiB (aspirational, report actual). ARM target manifests only until tested. No changes to host networking, physical disks or external publication.
