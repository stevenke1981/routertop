# RouterTop 0.8 development image

The x86_64 image uses an Alpine Linux RAM root plus an optional writable ext4 data volume. It is not an installer and never formats an attached disk at boot. A provisioned data volume enables persistent settings, administrator enrollment and LAN-only HTTPS management. Local serial/VGA consoles require the same persistent administrator password as Web. Missing or corrupt state never grants an unauthenticated shell.

Actual 0.8 artifact sizes and test outcomes belong in [acceptance-v0.8.md](../docs/acceptance-v0.8.md). Keep [0.1 acceptance](../docs/acceptance.md) and its artifacts separate; old results do not certify the updated management image.

## Build in a disposable Alpine x86_64 VM

```sh
apk add cargo cpio gzip findutils coreutils kmod grub grub-bios grub-efi xorriso mtools
cargo build --locked --release
OUT=/tmp/routertop-build-007 \
ROUTERTOP_BINARY="$PWD/target/release/routertop" \
ROUTERTOP_BINARY_TARGET="$(rustc -vV | sed -n 's/^host: //p')" \
sh scripts/build-image.sh
```

Root is needed to assemble the filesystem. The builder verifies apk signatures using the installed Alpine keys, requires HTTPS repositories, and refuses a nonempty output directory. The default branch is Alpine v3.24. `MAKE_ISO=0` skips GRUB/xorriso and produces the kernel/initramfs pair only. Compilers remain in the builder.

Without `ROUTERTOP_BINARY`, the builder detects the installed compiler's native musl triple. Alpine may use `x86_64-alpine-linux-musl`, not rustup's `x86_64-unknown-linux-musl`. Profiles describe intended ABI; they do not install a missing Rust standard library.

Static and Alpine-musl dynamically linked binaries are supported. The builder executes the supplied binary inside the assembled root, so missing runtime libraries fail the build. A caller-supplied `ROUTERTOP_BINARY_TARGET` is recorded metadata, not independently proven compiler provenance.

Outputs include `vmlinuz`, `initramfs.gz`, optional `routertop-x86_64.iso`, `packages.txt`, `repositories.txt`, `build-manifest.json` and `SHA256SUMS`. The 64 MiB target measures compressed kernel plus initramfs; ISO overhead, the data disk and runtime RAM are separate. Normalized timestamps and deterministic gzip do not make moving Alpine repositories or GRUB bit-for-bit reproducible. Exact rebuilds need package snapshots, toolchain/lockfile and binary hashes.

## Create a new persistent data disk

In Linux, install the helper's tools (`mkfs.ext4`, `sfdisk`, `truncate`, `dd`, `mktemp`) and run:

```sh
sh scripts/make-data-disk.sh /tmp/routertop-data.img
```

The helper creates a **new 33 MiB regular file**, with an MBR partition starting at sector 2048 and a 32 MiB ext4 filesystem labelled `ROUTERTOP_DATA`. It refuses existing paths and block devices; it does not provision physical disks. Copy this file to the Windows host and reuse the same file across VM restarts. Do not share one writable image concurrently between VMs.

At boot, `routertop.datadev=/dev/vda1` selects an explicit partition. Without that parameter, exactly one `ROUTERTOP_DATA` label is accepted. Duplicate labels require an explicit choice. The filesystem mounts at `/data` with `rw,nosuid,nodev,noexec`. The OS boot path never runs a formatter.

- `/data/routertop`: durable canonical settings, revision, administrator Argon2id hash, enrollment state and per-interface WireGuard private keys; owned by unprivileged UID 1000.
- `/data/tls`: persisted TLS key/certificate, root-only.
- `/data/routertop-dhcpcd/duid`: persistent DHCPv6 client identity, root-only; dynamic IPv6 requires a data volume. DHCP leases and generated client configuration remain in RAM.
- `/run/routertop/web`: volatile sessions, throttle and fixed reboot request; cleared by reboot.

Without a data volume, basic routing can boot but HTTPS management stays disabled. A corrupt existing state is an error, not permission to reset an administrator. Persistent data loading failure stops provisioning with forwarding disabled. RAM-root package installations and arbitrary console edits are not made persistent by this volume.

## Boot on Windows and enroll

```powershell
./scripts/boot-qemu.ps1 -ImageDirectory ./dist/v0.8 -DataDisk ./routertop-data.img -Qemu 'C:/path/to/qemu-system-x86_64.exe'
./scripts/boot-qemu.ps1 -ImageDirectory ./dist/v0.8 -DataDisk ./routertop-data.img -Qemu 'C:/path/to/qemu-system-x86_64.exe' -Iso
```

The launcher defaults to 512 MiB RAM, QEMU user-mode WAN and a restricted virtual LAN. It forwards only `127.0.0.1:19443` to the guest LAN `192.168.88.1:443`; `-ManagementPort` changes the host-side port. This is not a physical LAN bridge. `-DataDisk` attaches an existing raw image, and the label selects its partition. Omitting it runs without writable management persistence.

At first boot, the console offers `Setup choice [create/token]`. Choose `create` to create and confirm the administrator password locally, then log in. Inside the authenticated shell, inspect the persisted HTTPS certificate fingerprint:

```sh
openssl x509 -in /data/tls/server.pem -noout -sha256 -fingerprint
```

Open `https://127.0.0.1:19443`, verify the certificate identity, then log in as `admin` with the same password. Alternatively choose `token` at the initial console prompt to obtain the one-time Web enrollment token. Passwords contain 12–128 bytes and exclude ASCII control characters. Web asks for at least 12 characters. An old password containing control characters still works through Web; change it there before using console login.

Direct LAN clients use `https://192.168.88.1`. The self-signed certificate persists with the disk; localhost forwarding differs from its LAN IP subject alternative name. The enrollment token is unavailable after successful setup and is never returned by the public API. `exit` logs out of the console; every new shell requires authentication.

HTTPS binds the configured LAN IP only and is permitted by the LAN firewall rule. There is no HTTP listener or enabled SSH daemon. Saved settings apply on the next boot; the UI distinguishes saved/pending from active and asks before rebooting. Changing the LAN IP/HTTPS port requires a new URL and corresponding adjustments to the launcher's fixed guest forwarding destination. Logout, password change and reboot invalidate sessions. Web password changes also change subsequent console logins; existing authenticated shells are not terminated. Without a valid data volume, consoles remain locked.

`ROUTERTOP_READY` proves the boot path reached its ready marker, not end-to-end routing. The launcher itself does not place a DHCP client behind the router. Use a separate client VM or `scripts/netns-smoke.sh` for DHCP/DNS/NAT evidence. Runtime, browser, persistence and negative-access results must be recorded independently.

## Legacy read-only configuration input

The 0.1 `routertop.configdev=/dev/vdb1` option remains an explicit secondary ext4 input mounted `ro,noload,nosuid,nodev,noexec`. Its `/routertop.toml` supplies initial settings, but it is not a writable management store. When a durable 0.8 bundle already exists, that bundle supplies saved configuration. Prefer the dedicated writable data disk for the 0.8 management flow.

## apk packaging and platform limits

`sh packaging/make-source.sh` prepares `packaging/alpine/routertop-0.8.0.tar.gz` from the exact local source and Cargo lockfile. Run `abuild checksum` and `abuild -r` as an Alpine abuild user with signing configured. Crates are fetched during prepare; build/tests use `--frozen`.

The **0.8 apk contains the CLI, default config and license only**. It does not install the full OS boot stack, Web files, lighttpd configuration or data-volume management. Trust the signing key before installing; never substitute `--allow-untrusted` for a signing workflow. Package build/signing needs its own evidence.

The `linux-virt` kernel targets QEMU/VMs. Physical NIC firmware, board drivers, installation/upgrades and secure boot remain separate work. `profiles/aarch64.env` and APKBUILD's aarch64 declaration reserve portability; the image builder rejects unimplemented ARM boot paths.

## Primary references

- [Alpine package management](https://wiki.alpinelinux.org/wiki/Alpine_Package_Keeper)
- [Official rootfs builder](https://github.com/alpinelinux/alpine-make-rootfs)
- [Alpine image scripts](https://gitlab.alpinelinux.org/alpine/aports/-/tree/master/scripts)
- [APKBUILD reference](https://wiki.alpinelinux.org/wiki/APKBUILD_Reference)

PPPoE uses `ppp-daemon` and `rp-pppoe`, with `ppp_generic`/`ppp_async` loaded at runtime. Credentials are configured through authenticated Web settings and persisted privately; the factory image contains no ISP credentials. Actual dialing/reconnect/reboot acceptance is recorded in [0.8 acceptance](../docs/acceptance-v0.8.md).

Dual WAN supports fixed IPv4, DHCP and PPPoE with primary restoration after interface-bound probe recovery. Use three Ethernet interfaces (primary, LAN, backup) for appliance acceptance; the simple launcher above has only one WAN and is not dual-WAN proof. Both PPP peer files are private, and dual-WAN default routing is owned by the Rust supervisor. The dual-WAN sysctl profile disables IPv4 reverse-path filtering on both uplinks and future PPP interfaces because bootstrap/standby probes use dedicated tables before a main default exists; scoped nftables policy remains mandatory. IPv6/PD defaults to primary-only; opt-in active-standby uses the selected provider and shared PD layout with isolated slot identities. See [0.8 WAN contract](../docs/network-v0.8-contract.md).

The first future size priority is SquashFS (zstd/xz) with overlay or a separate configuration partition; kernel trimming, Alpine cleanup, qcow2/sparse reduction and advanced initramfs reduction follow in that order. See [the measured-gate roadmap](../docs/image-size-roadmap.md). This documentation is not a claim that a SquashFS migration was implemented or boot-tested in 0.8.
