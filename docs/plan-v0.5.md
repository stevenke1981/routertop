# RouterTop v0.5 implementation and acceptance plan

Base: 029a08477fac33030b927e88cd96d41abb168d38. Requested: dynamic IPv6 WAN and DHCPv6 prefix delegation, persistent Web settings, unchanged light Settings-style UI, compact x86_64 image, actual reconnect/renumber/reboot acceptance, commit and public push.

Architecture: retain Rust typed validation/rendering and Alpine data plane. Prefer packaged dhcpcd for DHCPv6/RA/PD lifecycle instead of a new DHCP implementation. Keep IPv4 client isolated. Static v0.4 configurations must remain compatible. Delegate explicit, unique /64 subnet IDs to LAN/VLAN; reject impossible sizes and conflicting static settings. Keep ephemeral leases separate from saved user configuration and preserve client identity on the data volume. Dynamic addresses, routes, DNS and firewall must follow lease updates and expiry without accepting unsolicited WAN traffic or bypassing WireGuard guards.

Owners (separate author worktrees, scoped integration by root):
- core: Rust model/render/runtime integration and image boot/client lifecycle; contract and unit tests.
- image: Web form/settings/status, browser acceptance harness; no backend edits.
- network_test: isolated real DHCPv6/RA/PD server/client packet harness, reconnect/renumber/expiry evidence; no production source edits.
- root: integration, build/image/version/CI documentation, real appliance/browser/reboot acceptance and publication; independent reviewer once candidate stabilizes.

Gates: existing tests and format/lint; dynamic model invalid input and backward compatibility; actual IA_NA/SLAAC and IA_PD acquisition; separate LAN/VLAN /64 routes and SLAAC; WAN link loss/reconnect; real lease renewal with changed prefix and removal/deprecation of old prefix; failed/expired lease handling; IPv4/WG firewall regression; Web save/reload and actual cold reboot retaining modes/subnet IDs and client identity then reacquiring lease; desktop/mobile UI smoke; image/binary/web sizes and hashes; scoped independent review; exact remote SHA and CI result. Test only disposable VM/namespaces, never host NICs.

No RouterOS feature-parity claim; ARM remains reserved but not hardware-tested. Evidence labels distinguish PASS/FAIL/BLOCKED/NOT_RUN. No credentials, populated data disk, lease identity or raw private logs in public evidence. Runtime package growth must be measured against v0.4 ISO 66,095,104 bytes and kernel+initramfs 52,974,428 bytes.
