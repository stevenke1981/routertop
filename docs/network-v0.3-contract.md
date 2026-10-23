# RouterTop 0.3 implementation contract

Request: implement VLAN, WireGuard VPN, firewall rule management in persistent Web UI; keep image compact; real tests; commit/push public repository. Base 227c672 (0.2). No physical host networking changes. Existing 0.1/0.2 artifacts remain intact. IPv4 first; no claim of full RouterOS compatibility.

Owners: network worker `.worktrees/network-v03` owns src/lib.rs, NEW src/network.rs and tests/network.rs only. Web worker `.worktrees/web-v03` owns web/index.html, app.js, style.css and NEW scripts/browser-network-smoke.py only. Root owns Cargo manifests, src/main.rs, src/web.rs, new tests/web_network.rs, image/runtime, integration network harness, docs and publication. Independent reviewer checks concrete candidate once. Do not revert another owner's changes.

Public config additions, serde defaults for 0.2 compatibility:

```text
Config.vlans: Vec<Vlan> = []
Vlan { interface:String, parent:String, id:u16, address:String, dhcp:Option<Dhcp>, internet:bool }
Config.wireguard: Vec<WireGuard> = []
WireGuard { interface:String, address:String, listen_port:u16, mtu:u16, internet:bool, peers:Vec<Peer> }
Peer { public_key:String, allowed_ips:Vec<String>, endpoint:Option<String>, persistent_keepalive:u16 }
Firewall.rules: Vec<FirewallRule> = []
FirewallRule { id:String, enabled:bool, chain:"input"|"forward", action:"accept"|"drop"|"reject", protocol:"any"|"tcp"|"udp"|"icmp", in_interface:Option<String>, out_interface:Option<String>, source:Option<String>, destination:Option<String>, destination_port:Option<u16>, comment:String }
```

All fields in new entries explicit; max16 VLANs, max4 WireGuard interfaces /32 peers each, max64 firewall rules. VLAN parent must be physical configured WAN or LAN; no nested VLAN. ID1..4094, unique parent+tag, interface names unique including WAN/LAN, safe Linux names. Address IPv4 usable host /8../30, all local subnets disjoint. VLAN optional DHCP uses existing bounds rules; extra subnets default isolated, internet=true enables WAN forwarding+masquerade only. No implicit VLAN-to-LAN/VLAN forwarding.

WireGuard is split-tunnel IPv4. Public keys canonical base64 32 nonzero bytes. Ports nonzero unique and not UDP DNS/DHCP. MTU576..9000. Endpoints optional literal unicast IPv4:port (no DNS dependency). Allowed IPs nonempty canonical IPv4 networks, /1../32; disallow default routes, multicast, local LAN/VLAN overlap, local router addresses, endpoint capture and overlapping peer routes (including across WG interfaces). Peer /32 inside own WG subnet allowed. Remote site subnets supported. Keepalive0..65535. Root generates private keys automatically on first config save with a new WG interface; preserves them while interface exists; deletion removes secret. No private keys in Config, export, Web responses, screenshots or evidence. WireGuard public keys are returned by authenticated GET /wireguard/keys as {public_keys:{interface:base64}}. Key rotation is not in this scope.

Firewall rule IDs unique safe ASCII, comments max80 safe printable ASCII; validate all names against existing interfaces, source/destination canonical IPv4 CIDR, out_interface forbidden for input, destination_port only TCP/UDP and nonzero. Typed model only; no raw nft/script input. Preserve rule order, support create/edit/delete/enable/disable/reorder. System input rules (loopback, state, DHCP/DNS, LAN management, WG listener) precede custom input rules; custom forward rules after established/related and before implicit LAN-to-WAN/static route allows. Default drops remain. Inter-VLAN/VPN access requires explicit forward rule. Config saving still applies on reboot, not live transaction/rollback.

Rendering: extend Rendered with network_setup:String. Network worker emits deterministic shell text using only strictly validated tokens; no user comments in shell. Script creates VLAN/WG interfaces and addresses, sets mtu, runs `wg setconf IF /run/routertop/wireguard/IF.conf`, sets links up and installs allowed-IP routes. Root writes network-setup.sh and invokes AFTER base ifup, BEFORE forwarding/dnsmasq. nft applies before any link activation. Root `wg-configs DATA OUT` (root-only on Linux) writes secret [Interface]/[Peer] configs with keys from durable bundle; output directory0700 files0600. Network worker does not write secret renderer. Root adds wireguard-tools-wg package and kernel module loading. No wg-quick/bash runtime dependency.

Persistence: same atomic state.json bundle contains new defaulted wireguard_keys map, protected0700/0600. 0.2 canonical config normalization must migrate without resetting accounts/revisions. Save transaction validates config then generates missing keys and commits config+keys atomically. Active config stays secret-free0644; root-generated runtime WG files0700/0600. Existing session/Origin/CSRF/revision checks remain.

UI: separate VLAN, WireGuard and firewall navigation panels with real add/edit/delete controls, validation, empty states. Shared config/revision; preserve all unrelated fields. Save displays pending reboot. WG public key shown after save with copy function; peer keys never mistaken for private key. All advanced saves use existing POST /config, key view GET /wireguard/keys. LAN management reservations and rule ordering explained briefly. No new frontend framework/CDN.

Acceptance: Windows/Linux focused tests incl malformed config/injection/overlap, old-state migration, secret non-disclosure, persisted keys; real Linux VLAN tagged traffic/isolation and DHCP, actual WireGuard handshake/encrypted peer traffic and wrong-peer denial, actual ordered firewall allow/drop/reorder; real Chrome CRUD/save/reload/reboot survival; BIOS/UEFI image boot, size/hash measurement; one independent review. Public GitHub stevenke1981/routertop after local validation and secret audit; local Git email stevenke1981@gmail.com. Source publish authorized; no complete OS binary release or production deployment implied.

Primary references: https://www.wireguard.com/quickstart/ ; https://www.wireguard.com/netns/ ; https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains .

Runtime WAN gate: after DHCP and before advanced setup, `network-check CONFIG` reads actual WAN IPv4 addresses and rejects overlap with local/peer/static-route networks. A configured VPN requires a known WAN lease. Alpine udhcpc post-bound/post-renew hooks check later address changes; conflicts disable forwarding and require correction plus reboot. This was added after an isolated Linux reproduction confirmed that a peer route could replace a dynamic WAN connected route.
