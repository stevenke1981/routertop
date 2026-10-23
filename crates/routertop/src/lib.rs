//! Validated IPv4 configuration and deterministic Linux service rendering.
//!
//! No command is executed by this library. Rendered firewall files are intended
//! for a single `nft -f` transaction and own only `table inet routertop`.
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt::Write;
use std::net::Ipv4Addr;

pub mod network;
pub mod web;
pub use network::{
    FirewallAction, FirewallChain, FirewallProtocol, FirewallRule, Peer, Vlan, WireGuard,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub hostname: String,
    pub wan: Wan,
    pub lan: Lan,
    pub dhcp: Dhcp,
    pub dns: Dns,
    pub firewall: Firewall,
    #[serde(default)]
    pub routes: Vec<Route>,
    #[serde(default)]
    pub vlans: Vec<Vlan>,
    #[serde(default)]
    pub wireguard: Vec<WireGuard>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Wan {
    pub interface: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Lan {
    pub interface: String,
    pub address: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Dhcp {
    pub start: String,
    pub end: String,
    pub lease_hours: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Dns {
    pub upstream: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Firewall {
    pub ssh_port: Option<u16>,
    pub https_port: Option<u16>,
    #[serde(default)]
    pub rules: Vec<FirewallRule>,
}

/// A network reached through a directly connected LAN-side gateway.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub destination: String,
    pub gateway: String,
}

#[derive(Clone, Debug)]
pub struct Rendered {
    pub interfaces: String,
    pub nftables: String,
    pub dnsmasq: String,
    pub sysctl: String,
    pub network_setup: String,
}

#[derive(Clone, Copy)]
struct Cidr {
    ip: u32,
    prefix: u32,
    mask: u32,
}

impl Cidr {
    fn network(self) -> u32 {
        self.ip & self.mask
    }
    fn broadcast(self) -> u32 {
        self.network() | !self.mask
    }
    fn contains_host(self, ip: u32) -> bool {
        ip > self.network() && ip < self.broadcast()
    }
    fn network_text(self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.network()), self.prefix)
    }
}

fn ipv4(value: &str, field: &str) -> Result<u32, String> {
    value
        .parse::<Ipv4Addr>()
        .map(u32::from)
        .map_err(|_| format!("{field}: expected a literal IPv4 address"))
}

fn unicast(ip: u32) -> bool {
    let first = ip >> 24;
    first != 0 && first != 127 && first < 224
}

fn cidr(value: &str, field: &str) -> Result<Cidr, String> {
    let (address, prefix) = value
        .split_once('/')
        .ok_or_else(|| format!("{field}: expected IPv4/prefix"))?;
    if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return Err(format!("{field}: invalid IPv4 prefix"));
    }
    let prefix: u32 = prefix
        .parse()
        .map_err(|_| format!("{field}: invalid IPv4 prefix"))?;
    if prefix > 32 {
        return Err(format!("{field}: IPv4 prefix exceeds 32"));
    }
    Ok(Cidr {
        ip: ipv4(address, field)?,
        prefix,
        mask: if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        },
    })
}

fn interface(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 15
        || value == "lo"
        || !value.as_bytes()[0].is_ascii_alphabetic()
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err("interface: use 1-15 ASCII letters, digits, _, - or .; start with a letter; lo is reserved".into());
    }
    Ok(())
}

/// Parse strict TOML and validate cross-field invariants.
pub fn parse_config(source: &str) -> Result<Config, String> {
    if source.len() > 128 * 1024 {
        return Err("configuration exceeds 128 KiB".into());
    }
    let config: Config = toml::from_str(source).map_err(|e| e.to_string())?;
    validate(&config)?;
    Ok(config)
}

/// Also used by render so direct struct construction cannot bypass validation.
pub fn validate(config: &Config) -> Result<(), String> {
    let host = &config.hostname;
    if host.is_empty()
        || host.len() > 63
        || !host.as_bytes()[0].is_ascii_alphanumeric()
        || !host.as_bytes()[host.len() - 1].is_ascii_alphanumeric()
        || !host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("hostname: expected a single ASCII DNS label (1-63 characters)".into());
    }
    interface(&config.wan.interface)?;
    interface(&config.lan.interface)?;
    if config.wan.interface == config.lan.interface {
        return Err("WAN and LAN interfaces must differ".into());
    }
    let lan = cidr(&config.lan.address, "lan.address")?;
    if !(8..=30).contains(&lan.prefix) || !unicast(lan.ip) || !lan.contains_host(lan.ip) {
        return Err(
            "lan.address: expected a usable unicast host address with prefix /8 through /30".into(),
        );
    }
    let start = ipv4(&config.dhcp.start, "dhcp.start")?;
    let end = ipv4(&config.dhcp.end, "dhcp.end")?;
    if !lan.contains_host(start) || !lan.contains_host(end) || start > end {
        return Err(
            "DHCP pool must be ordered and entirely within usable LAN host addresses".into(),
        );
    }
    if start <= lan.ip && lan.ip <= end {
        return Err("DHCP pool must not include the router address".into());
    }
    if !(1..=8760).contains(&config.dhcp.lease_hours) {
        return Err("dhcp.lease_hours: expected 1 through 8760".into());
    }
    if config.dns.upstream.is_empty() || config.dns.upstream.len() > 8 {
        return Err("dns.upstream: expected 1 through 8 IPv4 servers".into());
    }
    let mut servers = HashSet::new();
    for server in &config.dns.upstream {
        let ip = ipv4(server, "dns.upstream")?;
        if !unicast(ip)
            || ip == lan.ip
            || ip == lan.network()
            || ip == lan.broadcast()
            || !servers.insert(ip)
        {
            return Err(
                "dns.upstream: server must be unique usable unicast, and not the router itself"
                    .into(),
            );
        }
    }
    if let Some(port) = config.firewall.ssh_port {
        if port == 0 || port == 53 {
            return Err(
                "firewall.ssh_port: must be nonzero and cannot conflict with DNS port 53".into(),
            );
        }
    }
    if let Some(port) = config.firewall.https_port {
        if port == 0 || port == 53 || Some(port) == config.firewall.ssh_port {
            return Err(
                "firewall.https_port: nonzero, distinct from DNS and SSH ports required".into(),
            );
        }
    }
    if config.routes.len() > 128 {
        return Err("routes: at most 128 static routes are supported".into());
    }
    let mut destinations = HashSet::new();
    for route in &config.routes {
        let destination = cidr(&route.destination, "routes.destination")?;
        if destination.prefix == 0
            || destination.ip != destination.network()
            || !unicast(destination.ip)
            || !unicast(destination.broadcast())
            || (destination.network() <= lan.broadcast()
                && lan.network() <= destination.broadcast())
        {
            return Err("routes.destination: expected a canonical unicast network not overlapping LAN; default routes belong to WAN DHCP".into());
        }
        if !destinations.insert((destination.network(), destination.prefix)) {
            return Err("routes: duplicate destination".into());
        }
        let gateway = ipv4(&route.gateway, "routes.gateway")?;
        if !lan.contains_host(gateway) || gateway == lan.ip {
            return Err("routes.gateway: must be another usable host on the LAN".into());
        }
        if start <= gateway && gateway <= end {
            return Err("routes.gateway: must be outside the dynamic DHCP pool".into());
        }
    }
    network::validate_network(config)
}

/// Render services without running commands or touching host network state.
pub fn render(config: &Config) -> Result<Rendered, String> {
    validate(config)?;
    let advanced = network::render_network(config)?;
    let custom_input = network::render_rules(config, FirewallChain::Input);
    let custom_forward = network::render_rules(config, FirewallChain::Forward);
    let advanced_input = &advanced.input;
    let advanced_forward = &advanced.forward;
    let advanced_nat = &advanced.nat;
    let lan = cidr(&config.lan.address, "lan.address")?;
    let network = lan.network_text();
    let address = Ipv4Addr::from(lan.ip);
    let mask = Ipv4Addr::from(lan.mask);
    let wan_if = &config.wan.interface;
    let lan_if = &config.lan.interface;
    let mut interfaces = format!(
        "# Generated by RouterTop\nauto lo\niface lo inet loopback\n\nauto {wan_if}\niface {wan_if} inet dhcp\n\nauto {lan_if}\niface {lan_if} inet static\n    address {address}\n    netmask {mask}\n"
    );
    for route in &config.routes {
        writeln!(
            interfaces,
            "    post-up ip route replace {} via {} dev {lan_if}",
            route.destination, route.gateway
        )
        .map_err(|e| e.to_string())?;
        writeln!(
            interfaces,
            "    pre-down ip route del {} via {} dev {lan_if} || true",
            route.destination, route.gateway
        )
        .map_err(|e| e.to_string())?;
    }
    let mut input_ssh = String::new();
    if let Some(port) = config.firewall.ssh_port {
        input_ssh = format!("        iifname \"{lan_if}\" ip saddr {network} tcp dport {port} ct state new accept\n");
    }
    if let Some(port) = config.firewall.https_port {
        writeln!(
            input_ssh,
            "        iifname \"{lan_if}\" ip saddr {network} tcp dport {port} ct state new accept"
        )
        .map_err(|e| e.to_string())?;
    }
    let mut static_forward = String::new();
    for route in &config.routes {
        writeln!(static_forward, "        iifname \"{lan_if}\" oifname \"{lan_if}\" ip saddr {network} ip daddr {} accept", route.destination).map_err(|e| e.to_string())?;
    }
    let nftables = format!(
        "# Generated by RouterTop; load as one nft -f transaction.\n\
table inet routertop\n\
flush table inet routertop\n\
table inet routertop {{\n\
    chain input {{\n\
        type filter hook input priority 0; policy drop;\n\
        iifname \"lo\" accept\n\
        ct state invalid drop\n\
        meta nfproto ipv4 ct state established,related accept\n\
        iifname \"{wan_if}\" udp sport 67 udp dport 68 accept\n\
        iifname \"{lan_if}\" ip saddr {{ 0.0.0.0, {network} }} udp sport 68 udp dport 67 accept\n\
        iifname \"{lan_if}\" ip saddr {network} udp dport 53 accept\n\
        iifname \"{lan_if}\" ip saddr {network} tcp dport 53 accept\n\
        iifname \"{lan_if}\" ip saddr {network} ip protocol icmp accept\n\
{input_ssh}\
{advanced_input}\
{custom_input}\
    }}\n\
    chain forward {{\n\
        type filter hook forward priority 0; policy drop;\n\
        ct state invalid drop\n\
        meta nfproto ipv4 ct state established,related accept\n\
{custom_forward}\
        iifname \"{lan_if}\" oifname \"{wan_if}\" ip saddr {network} accept\n\
{static_forward}\
{advanced_forward}\
    }}\n\
    chain postrouting {{\n\
        type nat hook postrouting priority 100; policy accept;\n\
        oifname \"{wan_if}\" ip saddr {network} masquerade\n\
{advanced_nat}\
    }}\n\
}}\n"
    );
    let mut dnsmasq = format!(
        "# Generated by RouterTop\ninterface={lan_if}\nexcept-interface={wan_if}\nbind-interfaces\nno-resolv\ndomain-needed\nbogus-priv\ndhcp-authoritative\ndhcp-range={},{},{mask},{}h\ndhcp-option=option:router,{address}\ndhcp-option=option:dns-server,{address}\ndhcp-leasefile=/var/lib/misc/dnsmasq.leases\n",
        config.dhcp.start, config.dhcp.end, config.dhcp.lease_hours
    );
    for upstream in &config.dns.upstream {
        writeln!(dnsmasq, "server={upstream}").map_err(|e| e.to_string())?;
    }
    dnsmasq.push_str(&advanced.dnsmasq);
    let sysctl = "# Generated by RouterTop\nnet.ipv4.ip_forward=1\nnet.ipv4.conf.all.send_redirects=0\nnet.ipv4.conf.default.send_redirects=0\nnet.ipv4.conf.all.accept_redirects=0\nnet.ipv4.conf.default.accept_redirects=0\nnet.ipv6.conf.all.forwarding=0\nnet.ipv6.conf.default.forwarding=0\n".to_string();
    Ok(Rendered {
        interfaces,
        nftables,
        dnsmasq,
        sysctl,
        network_setup: advanced.setup,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const SAMPLE: &str = include_str!("../../../configs/routertop.toml");
    fn sample() -> Config {
        parse_config(SAMPLE).unwrap()
    }

    #[test]
    fn default_policy_is_scoped_and_fail_closed() {
        let generated = render(&sample()).unwrap();
        assert!(generated.nftables.starts_with("# Generated by RouterTop; load as one nft -f transaction.\ntable inet routertop\nflush table inet routertop\n"));
        assert!(!generated.nftables.contains("flush ruleset"));
        assert_eq!(generated.nftables.matches("policy drop;").count(), 2);
        assert!(!generated.nftables.contains("tcp dport 22"));
        assert!(generated
            .nftables
            .contains("oifname \"eth0\" ip saddr 192.168.88.0/24 masquerade"));
        assert!(generated
            .nftables
            .contains("udp sport 67 udp dport 68 accept"));
        assert!(generated
            .dnsmasq
            .contains("dhcp-range=192.168.88.100,192.168.88.199,255.255.255.0,12h"));
        assert!(generated.sysctl.contains("net.ipv6.conf.all.forwarding=0"));
    }

    #[test]
    fn rejects_unknown_fields_at_each_level() {
        for value in [
            format!("typo = true\n{SAMPLE}"),
            SAMPLE.replace("[wan]", "[wan]\nmode = 'static'"),
            SAMPLE.replace("[lan]", "[lan]\nextra = 1"),
            SAMPLE.replace("[dhcp]", "[dhcp]\nextra = 1"),
            SAMPLE.replace("[dns]", "[dns]\nextra = 1"),
            SAMPLE.replace("[firewall]", "[firewall]\nextra = 1"),
            format!(
                "{SAMPLE}\n[[routes]]\ndestination='10.0.0.0/8'\ngateway='192.168.88.2'\nextra=1"
            ),
        ] {
            assert!(parse_config(&value).is_err(), "{value}");
        }
    }

    #[test]
    fn rejects_injection_even_for_direct_struct_callers() {
        for bad in [
            "eth0;reboot",
            "eth0\npost-up reboot",
            "$(reboot)",
            "eth\"0",
            "../eth0",
            "eth 0",
            "eth0:1",
            "éth0",
            "lo",
            "123",
            "abcdefghijklmnop",
            "",
        ] {
            let mut config = sample();
            config.wan.interface = bad.into();
            assert!(render(&config).is_err(), "{bad}");
        }
        let mut config = sample();
        config.hostname = "router\nreboot".into();
        assert!(render(&config).is_err());
        let mut config = sample();
        config.dns.upstream = vec!["1.1.1.1\nconf-file=/evil".into()];
        assert!(render(&config).is_err());
    }

    #[test]
    fn address_and_pool_boundaries() {
        for bad in [
            "192.168.88.0/24",
            "192.168.88.255/24",
            "192.168.88.1/31",
            "192.168.88.1/32",
            "192.168.88.1/33",
            "192.168.88.1/-1",
            "192.168.88.1/+24",
            "192.168.88.1/0",
            "192.168.88.1",
            "127.0.0.1/24",
            "224.1.1.1/24",
            "0.1.1.1/24",
            "::1/64",
        ] {
            let mut config = sample();
            config.lan.address = bad.into();
            assert!(render(&config).is_err(), "{bad}");
        }
        for (start, end) in [
            ("192.168.88.0", "192.168.88.199"),
            ("192.168.88.100", "192.168.88.255"),
            ("192.168.88.100", "192.168.89.1"),
            ("192.168.88.199", "192.168.88.100"),
            ("192.168.88.1", "192.168.88.199"),
        ] {
            let mut config = sample();
            config.dhcp.start = start.into();
            config.dhcp.end = end.into();
            assert!(render(&config).is_err());
        }
        let mut config = sample();
        config.lan.address = "192.168.88.1/30".into();
        config.dhcp.start = "192.168.88.2".into();
        config.dhcp.end = config.dhcp.start.clone();
        assert!(render(&config).is_ok());
    }

    #[test]
    fn service_validation_and_ssh_scope() {
        let mut config = sample();
        let rules = render(&config).unwrap().nftables;
        assert!(rules.contains(
            "iifname \"eth1\" ip saddr 192.168.88.0/24 tcp dport 443 ct state new accept"
        ));
        assert!(!rules.contains("iifname \"eth0\" tcp dport 443"));
        for port in [0, 53, 22] {
            config.firewall.ssh_port = Some(22);
            config.firewall.https_port = Some(port);
            assert!(render(&config).is_err());
        }
        let mut config = sample();
        config.wan.interface = config.lan.interface.clone();
        assert!(render(&config).is_err());
        for lease in [0, 8761, u32::MAX] {
            let mut config = sample();
            config.dhcp.lease_hours = lease;
            assert!(render(&config).is_err());
        }
        for port in [0, 53] {
            let mut config = sample();
            config.firewall.ssh_port = Some(port);
            assert!(render(&config).is_err());
        }
        let mut config = sample();
        config.firewall.ssh_port = Some(65535);
        assert!(render(&config).unwrap().nftables.contains(
            "iifname \"eth1\" ip saddr 192.168.88.0/24 tcp dport 65535 ct state new accept"
        ));
        for dns in [
            vec![],
            vec!["192.168.88.1"],
            vec!["127.0.0.1"],
            vec!["255.255.255.255"],
            vec!["1.1.1.1", "1.1.1.1"],
        ] {
            let mut config = sample();
            config.dns.upstream = dns.into_iter().map(String::from).collect();
            assert!(render(&config).is_err());
        }
    }

    #[test]
    fn static_routes_require_canonical_nonoverlapping_destination_and_lan_gateway() {
        let mut config = sample();
        config.routes.push(Route {
            destination: "10.20.0.0/16".into(),
            gateway: "192.168.88.2".into(),
        });
        let generated = render(&config).unwrap();
        assert!(generated
            .interfaces
            .contains("post-up ip route replace 10.20.0.0/16 via 192.168.88.2 dev eth1"));
        assert!(generated.nftables.contains("ip daddr 10.20.0.0/16 accept"));
        for bad in [
            "10.20.0.1/16",
            "192.168.88.0/24",
            "192.168.0.0/16",
            "0.0.0.0/0",
            "224.0.0.0/4",
            "10.20.0.0/16;reboot",
        ] {
            config.routes[0].destination = bad.into();
            assert!(render(&config).is_err(), "{bad}");
        }
        config.routes[0].destination = "10.20.0.0/16".into();
        for bad in [
            "192.168.88.0",
            "192.168.88.255",
            "192.168.88.1",
            "192.168.89.2",
            "192.168.88.100",
            "192.168.88.2;reboot",
        ] {
            config.routes[0].gateway = bad.into();
            assert!(render(&config).is_err(), "{bad}");
        }
        config.routes[0].gateway = "192.168.88.2".into();
        config.routes.push(config.routes[0].clone());
        assert!(render(&config).is_err());
    }

    #[test]
    fn serialization_roundtrip_and_size_limit() {
        let config = sample();
        let encoded = toml::to_string_pretty(&config).unwrap();
        assert_eq!(
            render(&config).unwrap().nftables,
            render(&parse_config(&encoded).unwrap()).unwrap().nftables
        );
        assert!(parse_config(&" ".repeat(128 * 1024 + 1)).is_err());
    }
}
