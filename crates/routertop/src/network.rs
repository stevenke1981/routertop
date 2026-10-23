//! Typed advanced networking. Keys here are public; private key provisioning is
//! owned by the persistent store, never by the exported router configuration.
use crate::{cidr, interface, ipv4, unicast, Cidr, Config, Dhcp};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt::Write, net::Ipv4Addr};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Vlan {
    pub interface: String,
    pub parent: String,
    pub id: u16,
    pub address: String,
    pub dhcp: Option<Dhcp>,
    pub internet: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireGuard {
    pub interface: String,
    pub address: String,
    pub listen_port: u16,
    pub mtu: u16,
    pub internet: bool,
    pub peers: Vec<Peer>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub persistent_keepalive: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallChain {
    Input,
    Forward,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallAction {
    Accept,
    Drop,
    Reject,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FirewallProtocol {
    Any,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallRule {
    pub id: String,
    pub enabled: bool,
    pub chain: FirewallChain,
    pub action: FirewallAction,
    pub protocol: FirewallProtocol,
    pub in_interface: Option<String>,
    pub out_interface: Option<String>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub destination_port: Option<u16>,
    pub comment: String,
}

/// Decode only canonical 32-byte, nonzero public keys.
pub fn decode_public_key(value: &str) -> Result<[u8; 32], String> {
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| "WireGuard public_key must be canonical base64".to_string())?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "WireGuard public_key must decode to 32 bytes".to_string())?;
    if bytes.iter().all(|b| *b == 0) || STANDARD.encode(bytes) != value {
        return Err("WireGuard public_key must be nonzero canonical base64".into());
    }
    Ok(bytes)
}

/// Endpoints are numeric IPv4 only; startup never depends on DNS resolution.
pub fn validate_endpoint(value: &str) -> Result<(Ipv4Addr, u16), String> {
    let (host, port) = value
        .split_once(':')
        .ok_or_else(|| "WireGuard endpoint must be IPv4:port".to_string())?;
    let ip = ipv4(host, "WireGuard endpoint")?;
    if !unicast(ip) || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err("WireGuard endpoint must be unicast IPv4:port".into());
    }
    let port: u16 = port
        .parse()
        .map_err(|_| "WireGuard endpoint port invalid".to_string())?;
    if port == 0 || format!("{}:{port}", Ipv4Addr::from(ip)) != value {
        return Err("WireGuard endpoint must be canonical IPv4 with nonzero port".into());
    }
    Ok((Ipv4Addr::from(ip), port))
}

/// Check runtime DHCP addresses before activating configured networks or
/// installing routes. Unlike configured local LANs, live WAN prefixes may be
/// /0 through /32; each host/prefix is normalized to its connected network.
pub fn validate_wan_subnets(config: &Config, addresses: &[String]) -> Result<(), String> {
    crate::validate(config)?;
    if addresses.is_empty() {
        return if config.wireguard.is_empty() {
            Ok(())
        } else {
            Err("WireGuard requires a known WAN IPv4 lease before network setup".into())
        };
    }
    let mut configured = vec![cidr(&config.lan.address, "LAN address")?];
    for vlan in &config.vlans {
        configured.push(cidr(&vlan.address, "VLAN address")?);
    }
    for wg in &config.wireguard {
        configured.push(cidr(&wg.address, "WireGuard address")?);
        for peer in &wg.peers {
            for allowed in &peer.allowed_ips {
                configured.push(cidr(allowed, "WireGuard allowed IP")?);
            }
        }
    }
    for route in &config.routes {
        configured.push(cidr(&route.destination, "static route")?);
    }
    for address in addresses {
        let wan = cidr(address, "live WAN address")?;
        if let Some(conflict) = configured.iter().find(|network| overlaps(wan, **network)) {
            return Err(format!(
                "configured network {} overlaps live WAN connected network {}; refusing unsafe route setup",
                conflict.network_text(), wan.network_text()
            ));
        }
    }
    Ok(())
}

fn overlaps(a: Cidr, b: Cidr) -> bool {
    a.network() <= b.broadcast() && b.network() <= a.broadcast()
}
fn contains(network: Cidr, ip: u32) -> bool {
    ip >= network.network() && ip <= network.broadcast()
}
fn local_address(value: &str) -> Result<Cidr, String> {
    let network = cidr(value, "interface address")?;
    if !(8..=30).contains(&network.prefix)
        || !unicast(network.ip)
        || !network.contains_host(network.ip)
        || value != format!("{}/{}", Ipv4Addr::from(network.ip), network.prefix)
    {
        return Err(
            "VLAN/WireGuard address must be a usable canonical IPv4 host /8 through /30".into(),
        );
    }
    Ok(network)
}
fn canonical_network(value: &str, allow_default: bool) -> Result<Cidr, String> {
    let network = cidr(value, "IPv4 network")?;
    if (!allow_default && network.prefix == 0) || value != network.network_text() {
        return Err(
            "expected a canonical IPv4 network; peer default routes are not supported".into(),
        );
    }
    Ok(network)
}
fn dhcp(pool: &Dhcp, subnet: Cidr) -> Result<(), String> {
    let start = ipv4(&pool.start, "VLAN DHCP start")?;
    let end = ipv4(&pool.end, "VLAN DHCP end")?;
    if !subnet.contains_host(start)
        || !subnet.contains_host(end)
        || start > end
        || (start <= subnet.ip && subnet.ip <= end)
        || !(1..=8760).contains(&pool.lease_hours)
    {
        return Err("VLAN DHCP must be an ordered usable pool excluding the router, with lease 1..8760 hours".into());
    }
    Ok(())
}

pub(crate) fn validate_network(config: &Config) -> Result<(), String> {
    if config.vlans.len() > 16 || config.wireguard.len() > 4 || config.firewall.rules.len() > 64 {
        return Err(
            "at most 16 VLANs, 4 WireGuard interfaces and 64 firewall rules are supported".into(),
        );
    }
    let lan = cidr(&config.lan.address, "lan.address")?;
    // Tuple contains interface name, connected subnet and whether this is WG.
    let mut local = vec![(config.lan.interface.as_str(), lan, false)];
    let mut names = HashSet::from([config.wan.interface.as_str(), config.lan.interface.as_str()]);
    let mut tags = HashSet::new();
    let mut ports = HashSet::new();
    for vlan in &config.vlans {
        interface(&vlan.interface)?;
        if !names.insert(&vlan.interface) {
            return Err("network interface names must be unique".into());
        }
        if vlan.parent != config.wan.interface && vlan.parent != config.lan.interface {
            return Err(
                "VLAN parent must be the configured physical WAN or LAN; nesting is not supported"
                    .into(),
            );
        }
        if !(1..=4094).contains(&vlan.id) || !tags.insert((vlan.parent.as_str(), vlan.id)) {
            return Err("VLAN tags must be 1..4094 and unique on each parent".into());
        }
        let subnet = local_address(&vlan.address)?;
        if let Some(pool) = &vlan.dhcp {
            dhcp(pool, subnet)?;
        }
        local.push((&vlan.interface, subnet, false));
    }
    for wg in &config.wireguard {
        interface(&wg.interface)?;
        if !names.insert(&wg.interface) {
            return Err("network interface names must be unique".into());
        }
        if matches!(wg.listen_port, 0 | 53 | 67 | 68) || !ports.insert(wg.listen_port) {
            return Err(
                "WireGuard listen ports must be unique, nonzero and not DNS/DHCP ports".into(),
            );
        }
        if !(576..=9000).contains(&wg.mtu) || wg.peers.len() > 32 {
            return Err("WireGuard MTU must be 576..9000, with at most 32 peers".into());
        }
        local.push((&wg.interface, local_address(&wg.address)?, true));
    }
    for (index, (_, subnet, _)) in local.iter().enumerate() {
        if local
            .iter()
            .take(index)
            .any(|(_, other, _)| overlaps(*subnet, *other))
        {
            return Err("LAN, VLAN and WireGuard connected subnets must not overlap".into());
        }
        if index > 0 {
            for route in &config.routes {
                if overlaps(*subnet, cidr(&route.destination, "static route")?) {
                    return Err(
                        "VLAN/WireGuard subnet conflicts with an existing static route".into(),
                    );
                }
            }
        }
    }
    for server in &config.dns.upstream {
        let ip = ipv4(server, "dns.upstream")?;
        if local.iter().any(|(_, subnet, _)| {
            ip == subnet.ip || ip == subnet.network() || ip == subnet.broadcast()
        }) {
            return Err(
                "DNS upstream must not reference any local router, network or broadcast address"
                    .into(),
            );
        }
    }
    let mut endpoints = Vec::new();
    let mut peer_routes = Vec::new();
    for wg in &config.wireguard {
        let mut keys = HashSet::new();
        for peer in &wg.peers {
            let key = decode_public_key(&peer.public_key)?;
            if !keys.insert(key) {
                return Err("WireGuard peer public keys must be unique on an interface".into());
            }
            if peer.allowed_ips.is_empty() {
                return Err("WireGuard peer requires at least one allowed IPv4 network".into());
            }
            if let Some(endpoint) = &peer.endpoint {
                let (ip, _) = validate_endpoint(endpoint)?;
                let ip = u32::from(ip);
                if local.iter().any(|(_, subnet, _)| ip == subnet.ip) {
                    return Err("WireGuard endpoint cannot be a local router address".into());
                }
                // Adding a WG address installs its entire connected route, not
                // only its peers' allowed-IP routes. Transport endpoints must
                // stay outside every WG subnet to avoid recursive tunnelling.
                if local
                    .iter()
                    .any(|(_, subnet, is_wg)| *is_wg && contains(*subnet, ip))
                {
                    return Err(
                        "WireGuard endpoint is captured by a WireGuard connected subnet".into(),
                    );
                }
                endpoints.push(ip);
            }
            for allowed in &peer.allowed_ips {
                let network = canonical_network(allowed, false)?;
                if !unicast(network.network()) || !unicast(network.broadcast()) {
                    return Err(
                        "WireGuard allowed IPs must contain only usable unicast IPv4 ranges".into(),
                    );
                }
                for (name, subnet, is_wg) in &local {
                    if contains(network, subnet.ip) {
                        return Err(
                            "WireGuard allowed IPs cannot capture any router address".into()
                        );
                    }
                    if overlaps(network, *subnet)
                        && !(*is_wg && *name == wg.interface && network.prefix == 32)
                    {
                        return Err("WireGuard allowed IPs overlap a local subnet; only /32 hosts inside this WG subnet are allowed".into());
                    }
                }
                for route in &config.routes {
                    if overlaps(network, cidr(&route.destination, "static route")?) {
                        return Err(
                            "WireGuard allowed IPs conflict with an existing static route".into(),
                        );
                    }
                }
                if peer_routes.iter().any(|other| overlaps(network, *other)) {
                    return Err(
                        "WireGuard allowed IP routes must not overlap, including across interfaces"
                            .into(),
                    );
                }
                peer_routes.push(network);
            }
        }
    }
    if endpoints
        .iter()
        .any(|ip| peer_routes.iter().any(|network| contains(*network, *ip)))
    {
        return Err("WireGuard allowed IP route captures a peer endpoint".into());
    }
    let mut ids = HashSet::new();
    for rule in &config.firewall.rules {
        if rule.id.is_empty()
            || rule.id.len() > 32
            || !rule
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || !ids.insert(&rule.id)
        {
            return Err(
                "firewall rule IDs must be unique 1..32 ASCII letters, digits, _ or -".into(),
            );
        }
        if rule.comment.len() > 80
            || !rule
                .comment
                .bytes()
                .all(|b| (b' '..=b'~').contains(&b) && b != b'"' && b != b'\\')
        {
            return Err("firewall comment must be at most 80 printable ASCII characters without double quote or backslash".into());
        }
        for name in [&rule.in_interface, &rule.out_interface]
            .into_iter()
            .flatten()
        {
            if !names.contains(name.as_str()) {
                return Err("firewall rule references an unknown interface".into());
            }
        }
        if rule.chain == FirewallChain::Input && rule.out_interface.is_some() {
            return Err("input firewall rules cannot specify an output interface".into());
        }
        for network in [&rule.source, &rule.destination].into_iter().flatten() {
            canonical_network(network, true)?;
        }
        if let Some(port) = rule.destination_port {
            if port == 0 || !matches!(rule.protocol, FirewallProtocol::Tcp | FirewallProtocol::Udp)
            {
                return Err(
                    "firewall destination port must be nonzero and requires TCP or UDP".into(),
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn render_rules(config: &Config, chain: FirewallChain) -> String {
    let mut output = String::new();
    for rule in config
        .firewall
        .rules
        .iter()
        .filter(|rule| rule.enabled && rule.chain == chain)
    {
        output.push_str("        meta nfproto ipv4");
        if let Some(name) = &rule.in_interface {
            write!(output, " iifname \"{name}\"").expect("String write");
        }
        if let Some(name) = &rule.out_interface {
            write!(output, " oifname \"{name}\"").expect("String write");
        }
        if let Some(source) = &rule.source {
            write!(output, " ip saddr {source}").expect("String write");
        }
        if let Some(destination) = &rule.destination {
            write!(output, " ip daddr {destination}").expect("String write");
        }
        let protocol = match rule.protocol {
            FirewallProtocol::Any => None,
            FirewallProtocol::Tcp => Some("tcp"),
            FirewallProtocol::Udp => Some("udp"),
            FirewallProtocol::Icmp => Some("icmp"),
        };
        if let Some(protocol) = protocol {
            write!(output, " ip protocol {protocol}").expect("String write");
            if let Some(port) = rule.destination_port {
                write!(output, " {protocol} dport {port}").expect("String write");
            }
        }
        let action = match rule.action {
            FirewallAction::Accept => "accept",
            FirewallAction::Drop => "drop",
            FirewallAction::Reject => "reject",
        };
        writeln!(
            output,
            " counter {action} comment \"{}: {}\"",
            rule.id, rule.comment
        )
        .expect("String write");
    }
    output
}

/// Pieces inserted only after validate_network has succeeded.
pub(crate) struct NetworkRendered {
    pub setup: String,
    pub input: String,
    pub forward: String,
    pub nat: String,
    pub dnsmasq: String,
}

pub(crate) fn render_network(config: &Config) -> Result<NetworkRendered, String> {
    let mut rendered = NetworkRendered {
        setup: "#!/bin/sh\n# Generated by RouterTop; boot-time setup only.\nset -eu\n".into(),
        input: String::new(),
        forward: String::new(),
        nat: String::new(),
        dnsmasq: String::new(),
    };
    for vlan in &config.vlans {
        let name = &vlan.interface;
        let subnet = local_address(&vlan.address)?;
        let network = subnet.network_text();
        let ip = Ipv4Addr::from(subnet.ip);
        writeln!(
            rendered.setup,
            "ip link add link '{}' name '{name}' type vlan id {}",
            vlan.parent, vlan.id
        )
        .expect("String write");
        writeln!(
            rendered.setup,
            "ip address add '{}' dev '{name}'",
            vlan.address
        )
        .expect("String write");
        writeln!(rendered.setup, "ip link set dev '{name}' up").expect("String write");
        writeln!(rendered.dnsmasq, "interface={name}").expect("String write");
        writeln!(
            rendered.input,
            "        iifname \"{name}\" ip saddr {network} ip daddr {ip} udp dport 53 accept"
        )
        .expect("String write");
        writeln!(
            rendered.input,
            "        iifname \"{name}\" ip saddr {network} ip daddr {ip} tcp dport 53 accept"
        )
        .expect("String write");
        writeln!(
            rendered.input,
            "        iifname \"{name}\" ip saddr {network} ip daddr {ip} ip protocol icmp accept"
        )
        .expect("String write");
        if let Some(pool) = &vlan.dhcp {
            writeln!(rendered.input,"        iifname \"{name}\" ip saddr {{ 0.0.0.0, {network} }} udp sport 68 udp dport 67 accept").expect("String write");
            writeln!(
                rendered.dnsmasq,
                "dhcp-range=set:rt-{name},{},{},{},{}h",
                pool.start,
                pool.end,
                Ipv4Addr::from(subnet.mask),
                pool.lease_hours
            )
            .expect("String write");
            writeln!(rendered.dnsmasq,"dhcp-option=tag:rt-{name},option:router,{ip}\ndhcp-option=tag:rt-{name},option:dns-server,{ip}").expect("String write");
        } else {
            writeln!(rendered.dnsmasq, "no-dhcp-interface={name}").expect("String write");
        }
        if vlan.internet {
            internet_rules(&mut rendered, name, &network, &config.wan.interface);
        }
    }
    for wg in &config.wireguard {
        let name = &wg.interface;
        writeln!(rendered.setup, "ip link add dev '{name}' type wireguard").expect("String write");
        writeln!(
            rendered.setup,
            "ip address add '{}' dev '{name}'",
            wg.address
        )
        .expect("String write");
        writeln!(rendered.setup, "ip link set dev '{name}' mtu {}", wg.mtu).expect("String write");
        writeln!(
            rendered.setup,
            "wg setconf '{name}' '/run/routertop/wireguard/{name}.conf'"
        )
        .expect("String write");
        writeln!(rendered.setup, "ip link set dev '{name}' up").expect("String write");
        writeln!(
            rendered.input,
            "        meta nfproto ipv4 iifname {{ \"{}\", \"{}\" }} udp dport {} accept",
            config.wan.interface, config.lan.interface, wg.listen_port
        )
        .expect("String write");
        for peer in &wg.peers {
            for network in &peer.allowed_ips {
                writeln!(rendered.setup, "ip route replace '{network}' dev '{name}'")
                    .expect("String write");
                if wg.internet {
                    internet_rules(&mut rendered, name, network, &config.wan.interface);
                }
            }
        }
    }
    Ok(rendered)
}

fn internet_rules(rendered: &mut NetworkRendered, name: &str, network: &str, wan: &str) {
    writeln!(
        rendered.forward,
        "        iifname \"{name}\" oifname \"{wan}\" ip saddr {network} accept"
    )
    .expect("String write");
    writeln!(
        rendered.nat,
        "        oifname \"{wan}\" ip saddr {network} masquerade"
    )
    .expect("String write");
}
