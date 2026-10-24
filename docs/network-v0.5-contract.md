# RouterTop v0.5 IPv6 WAN / DHCPv6-PD contract

Status: implementation contract. Runtime packet, ISO, reconnect, renumber and reboot results belong in `acceptance-v0.5.md`; this document does not assert those gates passed. Existing v0.4 static IPv6 and WireGuard behavior remains supported.

## Saved configuration

`Config.ipv6` remains nullable. Every new object rejects unknown fields. Existing IPv4 WAN DHCP remains managed by BusyBox udhcpc; dhcpcd manages IPv6 only.

| IPv6 field | Type / default | Meaning |
| --- | --- | --- |
| `wan_mode` | `"static"` / `"auto"`; default `"static"` | Preserve old static behavior or enable dhcpcd RA/SLAAC and DHCPv6 IA_NA |
| `wan_address`, `wan_gateway` | nullable strings | Static WAN pair; both must be null in auto mode. Legacy omission in static mode still requires a dual-stack full tunnel |
| `lan_address` | string; default `""` | Static LAN host `/64`; must be empty when PD is enabled |
| `vlans` | array of `{interface,address}` | Existing static VLAN IPv6 host `/64` configuration; must be empty with PD |
| `dns_upstream` | array of canonical IPv6 literals | Existing explicit global/ULA upstreams; at most eight, may be empty |
| `dns_auto` | boolean; default `true` | In auto mode, additionally learn supported WAN DNS servers. Ignored in static mode; disabled at runtime when a full tunnel is configured |
| `pd` | null or object; default null | Request and assign a delegated prefix |

The PD object contains required `prefix_length` (integer 48–64), `lan_subnet_id` (unsigned integer) and `vlans` (array of `{interface,subnet_id}`). IDs must be unique across LAN and VLANs and fall in `0 .. 2^(64-prefix_length)-1`. A `/64` request therefore permits only LAN ID 0 and no VLAN targets. A `/48` request permits IDs through 65535. At most 16 VLAN targets are accepted; each must uniquely reference an existing IPv4 VLAN interface. This release does not mix static LAN/VLAN IPv6 addresses with PD assignments.

PD always requires `wan_mode:"auto"`. Every delegated target uses a `/64` and router suffix `::1`. The request length is a hint, not a promised ISP allocation: runtime validation checks the **actual** prefix length and ID capacity. A grant that cannot fit the configured IDs is rejected for forwarding rather than aliasing different networks. Runtime grants must be canonical global/ULA `/48` through `/64`, disjoint from WireGuard connected networks and nondefault peer routes and from the observed connected WAN. Existing IPv6 literal, family, port, interface and injection validation still applies.

The following examples are the `ipv6` portion of a complete RouterTop configuration. VLAN `guest` must already exist in `Config.vlans` where referenced.

### Static WAN and LAN

```json
{
  "wan_mode": "static",
  "wan_address": "2001:db8:1::2/64",
  "wan_gateway": "fe80::1",
  "lan_address": "2001:db8:88::1/64",
  "vlans": [],
  "dns_upstream": ["2001:4860:4860::8888"],
  "dns_auto": true,
  "pd": null
}
```

The link-local static gateway is scoped to the configured WAN interface. Old JSON/TOML omitting the three new fields loads with static mode, `dns_auto:true`, and no PD.

### Automatic WAN with static LAN

```json
{
  "wan_mode": "auto",
  "wan_address": null,
  "wan_gateway": null,
  "lan_address": "2001:db8:88::1/64",
  "vlans": [],
  "dns_upstream": [],
  "dns_auto": true,
  "pd": null
}
```

The LAN prefix remains the administrator's responsibility: automatic WAN addressing does not make an arbitrary static LAN prefix routable upstream. WAN addresses/default routes may come from RA/SLAAC and DHCPv6; no delegated LAN prefix is requested in this example.

### Automatic WAN and delegated LAN/VLAN

```json
{
  "wan_mode": "auto",
  "wan_address": null,
  "wan_gateway": null,
  "lan_address": "",
  "vlans": [],
  "dns_upstream": [],
  "dns_auto": true,
  "pd": {
    "prefix_length": 56,
    "lan_subnet_id": 0,
    "vlans": [{"interface": "guest", "subnet_id": 1}]
  }
}
```

With an actual `2001:db8:100::/56` grant, LAN becomes `2001:db8:100::1/64` and guest becomes `2001:db8:100:1::1/64`. `Config.vlans[].internet` still controls guest Internet forwarding; an isolated VLAN receives SLAAC but advertises no Internet default. Saving changes remains revision-checked and requires reboot for activation. Runtime leases never rewrite the saved configuration or revision.

## Client and runtime files

`Rendered` adds `dhcpcd: String`. The CLI `render CONFIG --output DIRECTORY` writes `dhcpcd.conf` alongside the existing interfaces, nftables, dnsmasq, sysctl and network setup files. The file is empty in legacy/static mode.

The dynamic client configuration uses `ipv6only`, global `noipv6rs`, explicit `allowinterfaces` for WAN plus delegated targets, WAN `ipv6rs`, IA_NA ID 1 and optional IA_PD ID 2. For the PD example the association is `ia_pd 2/::/56 LAN/0/64/1 guest/1/64/1`. Delegated targets disable their own RS and DHCPv6 requests. dhcpcd owns kernel address lifetimes, connected/default routes, renewals and lease expiry. RouterTop does not implement a DHCPv6 protocol client.

| Path | Owner / lifetime | Purpose |
| --- | --- | --- |
| `/data/routertop-dhcpcd/duid` | root, 0600; parent 0700; persistent | Random DUID-UUID bytes rendered as an explicit client `duid` directive. Existing invalid identity fails initialization without resetting it |
| `/var/lib/dhcpcd`, `/run/dhcpcd` | appliance RAM | Packaged dhcpcd database/leases and runtime state; not copied to persistent storage |
| `/run/routertop/dhcpcd.conf` | generated boot file | Indicates whether dynamic IPv6 is enabled |
| `/run/routertop/pd/dhcpcd.conf` | generated runtime file | Client configuration with the persistent identity injected |
| `/run/routertop/pd/lease.json` | RAM | Validated IA_PD prefix/lifetime and DHCPv6 DNS event data |
| `/run/routertop/pd/ra-dns.json` | RAM | Validated finite-lifetime RA DNS data |
| `/run/routertop/pd/ra.conf` | RAM | dnsmasq RA default-lifetime parameters |
| `/run/routertop/pd/resolv.conf` | RAM | Valid learned DNS upstreams for dnsmasq; does not replace the host resolver file |
| `/run/routertop/pd/status.json` | RAM; readable by Web CGI | Observed operational state, excluding identity and credentials |
| `/run/routertop/pd/lock` | RAM | Shared event/monitor file lock |
| `/run/routertop/pd/dnsmasq-restart` | RAM | Fixed supervisor marker, emitted only when RA configuration changes |

Identity creation uses OS randomness and synchronizes the identity file and parent directory. Boot initialization clears leases, learned DNS and status before acquisition. Dynamic mode requires the explicit persistent data volume; static/diskless behavior is unchanged. A backup intended to preserve DHCPv6 identity must include the separate `routertop-dhcpcd` directory, not only the management bundle.

Root-only Linux CLI operations:

```text
routertop ipv6-init CONFIG RUNTIME_DIRECTORY IDENTITY_FILE
routertop ipv6-event CONFIG RUNTIME_DIRECTORY
routertop ipv6-monitor CONFIG RUNTIME_DIRECTORY
```

`ipv6-event` parses dhcpcd's environment without evaluating shell data. It ignores events for interfaces other than the configured WAN. Lease events include BOUND6/RENEW6/REBIND6/REBOOT6; loss/expiry events clear authorization; ROUTERADVERT updates finite-lifetime DNS information. Current supported prefix fields follow `new_dhcp6_ia_pd1_prefixN` for the address and `new_dhcp6_ia_pd1_prefixN_{length,pltime,vltime}` for its metadata, up to 16 prefix records under the single requested PD association. Multiple independent PD associations are outside scope.

The packaged hook is `/usr/sbin/routertop-ipv6-hook`. Its default configuration and runtime paths are `/etc/routertop/routertop.toml` and `/run/routertop/pd`; the trusted test harness may override `ROUTERTOP_CONFIG` and `ROUTERTOP_PD_RUNTIME` through dhcpcd's environment. All three CLI commands accept explicit paths for isolated tests. The production launch/supervisor scripts intentionally use appliance paths.

## Boot and reconciliation order

1. Mount the explicit data volume, load the active saved configuration, validate and render services.
2. For dynamic mode, initialize identity and empty runtime files before checking dnsmasq configuration.
3. Validate and install the owned nftables table before bringing up interfaces or forwarding.
4. Bring up IPv4, perform the existing live WAN IPv4 collision check, create VLAN/WireGuard links, apply network setup and forwarding sysctls.
5. Start dnsmasq with initial RA default lifetime zero for dynamic Internet targets.
6. Start packaged dhcpcd, the Rust IPv6 monitor, and the fixed dnsmasq supervisor; management startup follows.

The monitor reconciles about once per second using bounded `ip`/`nft` subprocesses. It intersects unexpired dhcpcd delegation records with actual non-tentative kernel addresses, caps advertised status lifetimes to the kernel's remaining lifetimes, and updates only RouterTop's dynamic nft sets in one transaction. Authorization elements expire within at most five seconds without refresh; they are not extended to a stale lease's original lifetime. Carrier plus a current WAN IPv6 default route is required for dynamic readiness, including PD with a full tunnel configured.

dnsmasq constructor contexts follow interface preferred/valid lifetimes. RouterTop advertises an Internet default only while dynamic connectivity and, when required, an assigned delegation exist. Default RA lifetime is 30 seconds while ready and zero otherwise, with configured interval 5 seconds. Loss or removal of a previously accepted assignment causes its kernel address to be deprecated and given at most two more seconds of validity. Clients may retain old addresses according to their own IPv6 lifetime rules; forwarding authorization for removed prefixes is withdrawn independently.

Because SIGHUP does not reload general dnsmasq `ra-param` configuration, the dedicated supervisor restarts its owned dnsmasq process when RA default availability changes. This also briefly restarts the shared IPv4 DNS/DHCP service. Repeated identical degraded states do **not** repeatedly request restarts. Prefix changes and ordinary renewals use constructor lifetimes rather than restarting dnsmasq on every event.

## DNS and firewall boundaries

Learned DNS support is limited to global/ULA IPv6 literals. Loopback, link-local DNS (including scoped `fe80::` resolvers), multicast and non-address data are ignored. RA RDNSS and DHCPv6 DNS are bounded to eight distinct servers after merging, obey their recorded remaining lifetimes, and are removed on uplink loss. Learned addresses equal to a local router address are excluded. Explicit IPv4/IPv6 DNS upstream configuration remains available. WAN information is trusted only from the configured WAN interface; this release does not authenticate an ISP's DHCPv6 or RA server.

Only configured WAN input accepts DHCPv6 UDP 547→546 and router advertisements from link-local sources with hop limit 255. Existing ND, ICMPv6 error/PMTU handling and default-drop policy remain. This is a DHCPv6 **client**, not a stateful DHCPv6 server on LAN. LAN/VLAN use RA/SLAAC and router DNS advertisements. A VLAN without an IPv4 DHCP pool still has no generated IPv4 pool or UDP67 input allowance.

`auto_wan` is an expiring interface-name set gating dynamic IPv6 WAN forwarding. `pd_netN` and `pd_addrN` are expiring IPv6 prefix/address sets for each delegated target. Source/destination membership guards precede established-state and user-forward rules so removed prefixes cannot survive solely through conntrack or a user accept rule. Updates preserve unrelated nftables tables.

WireGuard full tunnel remains one full interface / one default peer, IPv4 outer endpoint, mandatory `0.0.0.0/0`, optional `::/0`, optional explicit NAT66. Dynamic WAN only adds narrowly scoped DHCPv6 and RS control-traffic exceptions to the existing direct-WAN output gate. Learned WAN DNS is disabled with any full tunnel. The direct-WAN kill switch remains before established-state acceptance. An IPv4-only full tunnel continues to block IPv6 forwarding and advertise no IPv6 Internet default. PD with dual-stack full tunnel and no NAT66 requires appropriate return routing at the VPN peer.

## Failure handling and remaining scope

- Invalid saved configuration fails before rendering/applying network changes.
- Unknown carrier/default route, no usable delegation, expired leases or kernel address removal clear dynamic forwarding authorization and withdraw the dynamic Internet default.
- Too-small actual grants, actual WAN/WireGuard overlaps or malformed lease fields produce degraded status and no authorized delegated forwarding. Identity corruption fails without silently replacing the stored identity.
- Monitor failure leaves only bounded nft authorization lifetimes; stale status older than ten seconds is returned as null. A supervisor/service crash is not represented as a successful acquisition.
- Renumbering permits an explicitly deprecated prefix only through its remaining valid lifetime. An explicit zero-validity prefix is not authorized or used to extend learned DNS lifetime.
- The runtime package requires dhcpcd's packaged privilege-separation account/directories even when the image is assembled with APK scripts disabled; image assembly owns those entries.
- No DHCPv6-PD server, multi-WAN failover, multiple delegated associations, arbitrary prefix lengths, prefix-to-subnet automatic placement, link-local learned DNS, or immediate settings activation is promised in v0.5. ARM is structurally reserved, not hardware-qualified.

GET `/cgi-bin/routertop.cgi/status` adds `ipv6_dynamic`, either null or:

```json
{
  "wan_mode": "auto",
  "state": "bound",
  "wan_addresses": ["2001:db8:1::2/128"],
  "delegated": [{
    "interface": "eth1",
    "address": "2001:db8:100::1/64",
    "prefix": "2001:db8:100::/64",
    "preferred_seconds": 30,
    "valid_seconds": 60
  }],
  "dns_servers": ["2001:db8:1::53"],
  "updated_uptime_seconds": 123,
  "error": null
}
```

States are `waiting`, `bound`, or `degraded`; example values are illustrative, not test evidence. `updated_uptime_seconds` is a monotonic appliance-uptime timestamp, not Unix time. Identity, server DUIDs and secrets are excluded.

Primary implementation references: [dhcpcd 10.5.2 configuration manual](https://raw.githubusercontent.com/NetworkConfiguration/dhcpcd/v10.5.2/src/dhcpcd.conf.5.in), [dhcpcd DHCPv6 environment option definitions](https://raw.githubusercontent.com/NetworkConfiguration/dhcpcd/v10.5.2/src/dhcpcd-definitions.conf), and [dnsmasq manual](https://thekelleys.org.uk/dnsmasq/docs/dnsmasq-man.html).
