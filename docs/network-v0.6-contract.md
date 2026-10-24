# RouterTop 0.6 PPPoE WAN contract

Extends [0.5 dynamic IPv6/PD](network-v0.5-contract.md). Actual acceptance belongs in [acceptance-v0.6.md](acceptance-v0.6.md). Defaults preserve existing DHCP WAN configurations.

## Saved WAN and public API

`wan.interface` is the physical underlay. `wan.mode` is `dhcp` (default) or `pppoe`. `wan.pppoe` is null in DHCP mode or `{username,password,mtu}` in PPPoE mode. Username/password each accept 1–128 printable ASCII bytes; MTU defaults to 1492 and accepts 1280–1492. PPPoE uses fixed logical `ppp0`; this name is reserved from LAN, VLAN and WireGuard interface collisions. VLAN/WireGuard connected subnet and firewall validation still apply. PPPoE IPv6 requires automatic WAN mode; static IPv6 WAN values are not combined with PPP-negotiated addressing.

The authenticated/revision-controlled `/config` GET returns `config.wan.pppoe.password` as an empty string and top-level `wan_password_set`. POST accepts a replacement password; blank/missing preserves it only for the same previously configured username. New or changed accounts need an explicit password. Switching to DHCP removes the PPP credential object. Existing pending-reboot semantics apply. `/status` includes public `wan` connection information plus `ipv6_dynamic`; it never contains a password, PPP log or DUID. Only root/management private state retains the reversible ISP credential needed for dialing. No password is present in general render output. The private runtime peer file is mode 0600 in a 0700 directory; active configuration is 0600 and readable by the existing management service. Passwords are escaped as pppd option values, never interpolated into shell code. TOML parse errors do not echo credential-bearing source lines.

## Runtime

- Packaged `ppp-daemon` plus `rp-pppoe` are used, without a new Cargo or frontend dependency. Alpine linux-virt 6.18.58 has `CONFIG_PPPOE` disabled; supported `ppp_generic`/`ppp_async` modules carry the small userspace PPPoE transport. pppd maintains PPP/IPCP/IPv6CP and PAP/CHAP client authentication. The runtime image does not contain the Python ISP fixture.
- The underlay is brought up without an IPv4 DHCP client. Routing, IPv4 masquerade, input/forward rules, WireGuard WAN checks, IPv6 dynamic sets and PD bind to `ppp0`. Management remains on the LAN during failed dialing. PPP liveness and a five-second reconnect delay allow recovery after peer loss; dialing does not block system boot.
- IPv6CP negotiates link-local identifiers and a PPP IPv6 default route. The dedicated DHCPv6 client starts after IPv6CP, without waiting for an Ethernet RA, and handles IA_NA/IA_PD. PPP needs no Ethernet SLAAC WAN advertisement. LAN/VLAN delegation still uses the existing /48–/64, unique subnet-ID and finite-lifetime contract. The stable DUID stays on the provisioned data volume. PD-only ISPs may return IA_NA NoAddrsAvail while delegating IA_PD: a global WAN IPv6 address is not required for LAN/VLAN routed IPv6, and this path has a separate real-packet/reconnect acceptance case.
- IPv6-down stops the session client and withdraws dynamic authorization, addresses, learned DNS and LAN default availability. A restored session reacquires a valid prefix. Runtime leases/status are RAM-only; saved user settings and identities persist. Private lifecycle locks prevent concurrent hook changes; public connection status permissions are explicit even with pppd's restrictive umask.

## Validation boundaries

Use real isolated PPPoE discovery/session frames and authenticated pppd peers, actual IPCP/IPv6CP, UDP DHCPv6 and routed client traffic. Test wrong-password denial before positive controls, lost peer/redial, prefix change/expiry, old-address rejection, and same-volume reboot/cold boot. Do not infer live acceptance from rendered files or the installation of a package. Production ISP interoperability, service-name selection, arbitrary WAN VLAN provisioning, PPP multilink/multiple sessions, jumbo PPPoE, IPv6-only PPP, modem-specific extensions and real hardware are outside this release's acceptance.

References: [pppd official manual](https://ppp.samba.org/pppd.html), [Alpine PPP packaging guidance](https://wiki.alpinelinux.org/wiki/PPP). Installed versions, paths, kernel configuration and actual traffic are checked in the lab rather than inferred from these documents.

MSS is clamped by two scoped nftables PPP forward rules for original SYN and SYN+ACK, using kernel `rt mtu`; the rp-pppoe userspace MSS option is deliberately omitted after a real VLAN checksum failure was reproduced. The kernel preserves an already-smaller MSS and updates the checksum. [Netfilter documentation](https://wiki.nftables.org/wiki-nftables/index.php/Mangling_packet_headers) and actual wire captures support this behavior.
