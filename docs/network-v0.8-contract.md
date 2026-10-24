# RouterTop 0.8 dual-provider IPv6 contract

Base: fcc8c02b742ffeac4531423f78be82cd098c4966. Extends [0.7](network-v0.7-contract.md); actual acceptance is separate from this specification.

## Saved configuration and compatibility

Add `ipv6.provider_policy`: `primary-only` by default, or explicit `active-standby`. Old files retain their previous behavior. Active/standby requires two WANs, automatic IPv6 and DHCPv6-PD. Both DHCP and PPPoE WAN transports are supported. The existing PD hint, LAN/VLAN subnet IDs and DNS policy are shared; validate each actual provider grant against that layout. Do not duplicate complete IPv6 profiles.

Provider selection follows the existing IPv4 `wan.active` health checks and recovery hysteresis. Independent IPv6-only health arbitration is outside this contract. A selected provider is distinct from a ready provider. Configuration/revision changes still require authenticated atomic save and reboot activation; runtime switching does not rewrite saved settings or revision. Both PPP credentials remain independently write-only.

## Lifecycle and isolation

Run one DHCPv6 client and one monitor. Negotiate IPv6CP on both PPP links when opted in, without letting standby pppd install a usable IPv6 default. The selected coordinator controls PPP defaults; Ethernet RA/default/DNS ownership belongs only to the active client. Standby RA/RDNSS/DHCPv6 must not authorize routing or DNS.

Each activation is identified by boot epoch, monotonic generation, provider slot, logical interface and session incarnation. Tokens are captured at event origin, not obtained later from the current marker. Events and reconciliation must reject stale generations under the PD state lock, including primary-to-backup-to-primary and same-provider reconnects. Old PPP-down events cannot stop or revoke a newer active session.

On transition, invalidate old ownership and close IPv6 forwarding first, stop and verify the old client exits, then withdraw its PD, owned WAN addresses/defaults, learned DNS and downstream advertisements. Preserve management and WireGuard routes. Do not erase the cleanup inventory before withdrawal. Only then activate the new generation and authorize validated current prefixes/egress. Never hold the PD lock while waiting for client startup/exit hooks. Preserve the verified-PID, same-network-namespace, bounded lifecycle and prohibition on bare `dhcpcd -x`.

Retain the primary identity at `/data/routertop-dhcpcd/duid`; backup uses private sibling `backup-duid`. Slot identities survive switches/reboot and remain dormant when disabled. Corrupt identities fail closed instead of silently regenerating. Runtime lease/generation/readiness starts closed after reboot and must be reacquired.

## Runtime and Web

Retain current `ipv6_dynamic` fields and add `provider` (`primary`, `backup`, null), `generation`, `logical_interface` and `phase` (`inactive`, `acquiring`, `bound`, `degraded`). `wan.ipv6_policy` reports the actual configured policy; `wan.ipv6_active` is a currently valid provider or null. Readiness requires usable current routing and installed, valid, DAD-complete delegation, not merely a live client or configured IPv6 block.

The privileged WAN coordinator publishes nonsecret `wan.ipv6_generation` (number or null). CGI correlates this public selected-provider generation with fresh public PD status and the selected connected physical/logical interface. CGI must not read or expose the private provider epoch, boot token or PPP incarnation; their private permissions remain unchanged. Missing, stale, acquiring, degraded or mismatched public snapshots report IPv6 unavailable.

The light Web UI exposes the opt-in policy alongside the shared automatic IPv6/PD controls, and distinguishes selected/acquiring/currently bound ownership. Save/reload/reboot tests cover the policy and both credentials. The manager must preserve full-tunnel VPN leak restrictions and deny retired-source traffic, including router-originated packets.

## Acceptance

Real DHCP/DHCP, DHCP/PPPoE, PPPoE/DHCP and PPPoE/PPPoE tests require distinct provider prefixes/DNS, actual downstream SLAAC/HTTP, initial backup boot, carrier and upstream failures, failback with prefix replacement, both-down isolation, stale callbacks and no standby default/DNS. The final ISO must pass Web persistence, reboot and cold boot with stable slot identities. Package/image growth and the [SquashFS-first roadmap](image-size-roadmap.md) are measured/documented separately.
