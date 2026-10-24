//! Static IPv6/SLAAC and leak-resistant WireGuard policy routing.
use crate::{Config, FirewallFamily, WireGuard};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt::Write, net::Ipv6Addr};

pub const FULL_TUNNEL_MARK: u32 = 0x5254;
pub const FULL_TUNNEL_TABLE: u32 = 51820;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ipv6Config {
    #[serde(default)]
    pub provider_policy: ProviderPolicy,
    #[serde(default)]
    pub wan_mode: WanMode,
    #[serde(default = "yes")]
    pub dns_auto: bool,
    #[serde(default)]
    pub pd: Option<PrefixDelegation>,
    pub wan_address: Option<String>,
    pub wan_gateway: Option<String>,
    #[serde(default)]
    pub lan_address: String,
    pub vlans: Vec<Ipv6Vlan>,
    pub dns_upstream: Vec<String>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderPolicy {
    #[default]
    PrimaryOnly,
    ActiveStandby,
}
fn yes() -> bool {
    true
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WanMode {
    #[default]
    Static,
    Auto,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixDelegation {
    pub prefix_length: u8,
    pub lan_subnet_id: u32,
    pub vlans: Vec<DelegatedVlan>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegatedVlan {
    pub interface: String,
    pub subnet_id: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ipv6Vlan {
    pub interface: String,
    pub address: String,
}

#[derive(Clone, Copy)]
pub(crate) struct Net6 {
    pub ip: u128,
    pub prefix: u32,
}
impl Net6 {
    fn mask(self) -> u128 {
        if self.prefix == 0 {
            0
        } else {
            u128::MAX << (128 - self.prefix)
        }
    }
    pub(crate) fn first(self) -> u128 {
        self.ip & self.mask()
    }
    fn last(self) -> u128 {
        self.first() | !self.mask()
    }
    pub(crate) fn contains(self, ip: u128) -> bool {
        ip >= self.first() && ip <= self.last()
    }
    pub(crate) fn overlaps(self, other: Self) -> bool {
        self.first() <= other.last() && other.first() <= self.last()
    }
    pub(crate) fn text(self) -> String {
        format!("{}/{}", Ipv6Addr::from(self.first()), self.prefix)
    }
}
fn address(value: &str) -> Result<Ipv6Addr, String> {
    let ip = value
        .parse::<Ipv6Addr>()
        .map_err(|_| "expected a literal canonical IPv6 address".to_string())?;
    if ip.to_string() != value {
        return Err("IPv6 addresses must use canonical lowercase compressed notation".into());
    }
    Ok(ip)
}
fn cidr6(value: &str) -> Result<Net6, String> {
    let (host, prefix) = value
        .split_once('/')
        .ok_or_else(|| "expected IPv6/prefix".to_string())?;
    if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid IPv6 prefix".into());
    }
    let bits = prefix
        .parse::<u32>()
        .map_err(|_| "invalid IPv6 prefix".to_string())?;
    if bits > 128 || bits.to_string() != prefix {
        return Err("IPv6 prefix must be canonical 0..128".into());
    }
    Ok(Net6 {
        ip: u128::from(address(host)?),
        prefix: bits,
    })
}
pub(crate) fn network(value: &str) -> Result<Net6, String> {
    let net = cidr6(value)?;
    if net.ip != net.first() {
        return Err("IPv6 network has nonzero host bits".into());
    }
    Ok(net)
}
pub(crate) fn global_or_ula(ip: u128) -> bool {
    let first = (ip >> 112) as u16;
    first & 0xe000 == 0x2000 || first & 0xfe00 == 0xfc00
}
fn link_local(ip: u128) -> bool {
    (ip >> 118) == 0x3fa
}
pub(crate) fn host(value: &str, min: u32, max: u32) -> Result<Net6, String> {
    let net = cidr6(value)?;
    if !(min..=max).contains(&net.prefix)
        || !global_or_ula(net.ip)
        || !global_or_ula(net.first())
        || !global_or_ula(net.last())
        || (net.prefix < 128 && net.ip == net.first())
    {
        return Err(format!(
            "IPv6 interface requires a global/ULA usable host /{min} through /{max}"
        ));
    }
    Ok(net)
}
pub(crate) fn full_tunnel(config: &Config) -> Option<&WireGuard> {
    config.wireguard.iter().find(|wg| wg.full_tunnel)
}
pub(crate) fn full_v6(wg: &WireGuard) -> bool {
    wg.peers
        .iter()
        .any(|peer| peer.allowed_ips.iter().any(|ip| ip == "::/0"))
}
fn enabled(config: &Config) -> bool {
    config.ipv6.is_some() || config.wireguard.iter().any(|wg| wg.address_v6.is_some())
}

pub(crate) fn validate(config: &Config) -> Result<(), String> {
    let full = full_tunnel(config);
    if config.wireguard.iter().filter(|wg| wg.full_tunnel).count() > 1 {
        return Err("only one full-tunnel interface is supported".into());
    }
    for wg in &config.wireguard {
        if wg.full_tunnel {
            if wg.internet || wg.peers.len() != 1 {
                return Err("full tunnel requires exactly one peer and internet=false".into());
            }
            let peer = &wg.peers[0];
            let allowed = &peer.allowed_ips;
            if peer.endpoint.is_none()
                || !allowed.iter().any(|ip| ip == "0.0.0.0/0")
                || allowed.len() > 2
                || allowed.iter().any(|ip| ip != "0.0.0.0/0" && ip != "::/0")
                || allowed.iter().collect::<HashSet<_>>().len() != allowed.len()
            {
                return Err("full tunnel requires an IPv4 endpoint and 0.0.0.0/0, optionally ::/0, with no other routes".into());
            }
        }
        if wg.nat66 && (!wg.full_tunnel || !full_v6(wg) || wg.address_v6.is_none()) {
            return Err(
                "NAT66 requires a dual-stack full tunnel with an IPv6 tunnel address".into(),
            );
        }
        if full_v6(wg) && (!wg.full_tunnel || wg.address_v6.is_none()) {
            return Err("::/0 requires an explicit full tunnel and IPv6 tunnel address".into());
        }
        if wg.address_v6.is_some() && wg.mtu < 1280 {
            return Err("WireGuard IPv6 requires MTU >=1280".into());
        }
    }
    // All statically connected IPv6 subnets are disjoint, including WAN.
    let mut local: Vec<(&str, Net6, bool)> = Vec::new();
    if let Some(v6) = &config.ipv6 {
        crate::pd::validate(config, v6)?;
        if v6.vlans.len() > 16 || v6.dns_upstream.len() > 8 {
            return Err("IPv6 allows at most 16 VLAN prefixes and 8 DNS upstreams".into());
        }
        match (&v6.wan_address,&v6.wan_gateway) {
            (Some(value),Some(gateway))=>{
                let wan=host(value,1,128)?;
                let gateway=u128::from(address(gateway)?);
                if gateway==wan.ip||(!link_local(gateway)&&(!global_or_ula(gateway)||!wan.contains(gateway))) {return Err("IPv6 WAN gateway must be on-link global/ULA or link-local and not the router".into());}
                local.push((config.wan.device(),wan,false));
            }
            (None,None) if full.is_some_and(full_v6)||v6.wan_mode==WanMode::Auto=>{}
            _=>return Err("IPv6 WAN address/gateway must be a pair; omission requires a dual-stack full tunnel".into()),
        }
        if v6.pd.is_none() {
            local.push((&config.lan.interface, host(&v6.lan_address, 64, 64)?, false));
        }
        let mut names = HashSet::new();
        for vlan in &v6.vlans {
            if !config
                .vlans
                .iter()
                .any(|entry| entry.interface == vlan.interface)
                || !names.insert(vlan.interface.as_str())
            {
                return Err("IPv6 VLAN must uniquely reference a configured VLAN".into());
            }
            local.push((&vlan.interface, host(&vlan.address, 64, 64)?, false));
        }
    }
    for wg in &config.wireguard {
        if let Some(value) = &wg.address_v6 {
            local.push((&wg.interface, host(value, 64, 128)?, true));
        }
    }
    for (index, (_, subnet, _)) in local.iter().enumerate() {
        if local
            .iter()
            .take(index)
            .any(|(_, other, _)| subnet.overlaps(*other))
        {
            return Err("connected IPv6 WAN/LAN/VLAN/WireGuard subnets overlap".into());
        }
    }
    if let Some(v6) = &config.ipv6 {
        let mut unique = HashSet::new();
        for server in &v6.dns_upstream {
            let ip = u128::from(address(server)?);
            if !global_or_ula(ip)
                || !unique.insert(ip)
                || local
                    .iter()
                    .any(|(_, net, _)| net.ip == ip || net.first() == ip)
            {
                return Err("IPv6 DNS must be unique global/ULA addresses, excluding local router/subnet addresses".into());
            }
        }
    }
    let mut routes: Vec<Net6> = Vec::new();
    for wg in &config.wireguard {
        for peer in &wg.peers {
            for allowed in peer.allowed_ips.iter().filter(|ip| ip.contains(':')) {
                let net = network(allowed)?;
                if wg.address_v6.is_none() {
                    return Err(
                        "IPv6 peer routes require an IPv6 WireGuard interface address".into(),
                    );
                }
                if net.prefix == 0 {
                    continue;
                } // Full default validated above; separate policy table.
                if !global_or_ula(net.first()) || !global_or_ula(net.last()) {
                    return Err("IPv6 allowed IPs must be global/ULA unicast networks".into());
                }
                for (name, subnet, is_wg) in &local {
                    if net.contains(subnet.ip)
                        || (net.overlaps(*subnet)
                            && !(*is_wg && *name == wg.interface && net.prefix == 128))
                    {
                        return Err("IPv6 peer route captures a router/local subnet; only own WG /128 hosts are exempt".into());
                    }
                }
                if routes.iter().any(|other| net.overlaps(*other)) {
                    return Err("IPv6 peer routes overlap across peers/interfaces".into());
                }
                routes.push(net);
            }
        }
    }
    if !enabled(config)
        && config
            .firewall
            .rules
            .iter()
            .any(|rule| rule.family == FirewallFamily::Ipv6)
    {
        return Err("IPv6 firewall rules require IPv6 networking to be configured".into());
    }
    Ok(())
}

pub(crate) struct Extra {
    pub sets: String,
    pub setup: String,
    pub input: String,
    pub forward: String,
    pub nat: String,
    pub dnsmasq: String,
    pub guard: String,
    pub output: String,
    pub established: String,
    pub sysctl: String,
}
pub(crate) fn render(config: &Config) -> Result<Extra, String> {
    let mut out = Extra {
        sets: String::new(),
        setup: String::new(),
        input: String::new(),
        forward: String::new(),
        nat: String::new(),
        dnsmasq: String::new(),
        guard: String::new(),
        output: String::new(),
        established: String::new(),
        sysctl: String::new(),
    };
    let full = full_tunnel(config);
    let ipv6_enabled = enabled(config);
    let v6_egress_allowed = full.is_none_or(full_v6);
    let wan = config.wan.device();
    let destination = full.map_or(wan, |wg| wg.interface.as_str());
    if ipv6_enabled {
        out.established = "        meta nfproto ipv6 ct state established,related accept\n".into();
        out.input.push_str("        meta nfproto ipv6 meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem } accept\n        meta nfproto ipv6 ip6 hoplimit 255 meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept\n");
    }
    if let Some(v6) = &config.ipv6 {
        if v6.wan_mode == WanMode::Auto {
            out.sets
                .push_str("    set auto_wan { type ifname; flags timeout; timeout 5s; }\n");
            writeln!(out.guard,"        meta nfproto ipv6 oifname \"{wan}\" oifname != @auto_wan drop\n        meta nfproto ipv6 iifname \"{wan}\" iifname != @auto_wan drop").expect("String write");
            writeln!(out.input,"        iifname \"{wan}\" ip6 saddr fe80::/10 ip6 hoplimit 255 meta l4proto ipv6-icmp icmpv6 type nd-router-advert accept\n        iifname \"{wan}\" meta nfproto ipv6 udp sport 547 udp dport 546 accept").expect("String write");
        }
        if let (Some(address), Some(gateway)) = (&v6.wan_address, &v6.wan_gateway) {
            writeln!(out.setup,"ip -6 address add '{address}' dev '{wan}'\nip -6 route replace default via '{gateway}' dev '{wan}'").expect("String write");
        }
        out.dnsmasq.push_str("enable-ra\n");
        if v6.pd.is_none() {
            render_lan(
                &mut out,
                &config.lan.interface,
                &v6.lan_address,
                true,
                destination,
                full,
                v6_egress_allowed,
            )?;
        } else {
            crate::pd::render_lans(config, &mut out, destination, v6_egress_allowed)?;
        }
        for subnet in &v6.vlans {
            let internet = config
                .vlans
                .iter()
                .find(|vlan| vlan.interface == subnet.interface)
                .is_some_and(|vlan| vlan.internet);
            render_lan(
                &mut out,
                &subnet.interface,
                &subnet.address,
                internet,
                destination,
                full,
                v6_egress_allowed,
            )?;
        }
        for server in &v6.dns_upstream {
            writeln!(out.dnsmasq, "server={server}").expect("String write");
        }
    }
    if v6_egress_allowed {
        for wg in config.wireguard.iter().filter(|wg| wg.internet) {
            for allowed in wg
                .peers
                .iter()
                .flat_map(|peer| &peer.allowed_ips)
                .filter(|ip| ip.contains(':'))
            {
                writeln!(
                    out.forward,
                    "        iifname \"{}\" oifname \"{destination}\" ip6 saddr {allowed} accept",
                    wg.interface
                )
                .expect("String write");
                if full.is_some_and(|full| full.nat66) {
                    writeln!(
                        out.nat,
                        "        oifname \"{destination}\" ip6 saddr {allowed} masquerade"
                    )
                    .expect("String write");
                }
            }
        }
    }
    if let Some(wg) = full {
        let name = &wg.interface;
        // Explicit priority preserves connected routes for management and WG's
        // marked transport; defaults live only in the isolated tunnel table.
        writeln!(out.setup,"ip -4 route replace default dev '{name}' table {FULL_TUNNEL_TABLE}\nip -4 rule add priority 100 table main suppress_prefixlength 0\nip -4 rule add priority 110 not fwmark {FULL_TUNNEL_MARK} table {FULL_TUNNEL_TABLE}").expect("String write");
        if full_v6(wg) {
            writeln!(out.setup,"ip -6 route replace default dev '{name}' table {FULL_TUNNEL_TABLE}\nip -6 rule add priority 100 table main suppress_prefixlength 0\nip -6 rule add priority 110 not fwmark {FULL_TUNNEL_MARK} table {FULL_TUNNEL_TABLE}").expect("String write");
        }
        // This gate is inserted before established/custom accepts. It remains
        // installed even when the WG interface or its policy route disappears.
        writeln!(
            out.guard,
            "        oifname \"{wan}\" counter drop comment \"full-tunnel direct WAN blocked\""
        )
        .expect("String write");
        if !full_v6(wg) {
            out.guard.push_str("        meta nfproto ipv6 counter drop comment \"IPv4-only full tunnel blocks IPv6 forwarding\"\n");
        }
        let ports = config
            .wireguard
            .iter()
            .map(|wg| wg.listen_port.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        out.output=format!("    chain output {{\n        type filter hook output priority 0; policy accept;\n        oifname \"{wan}\" meta nfproto ipv4 meta mark {FULL_TUNNEL_MARK} udp sport {{ {ports} }} accept\n        oifname \"{wan}\" meta nfproto ipv4 udp sport 68 udp dport 67 accept\n        oifname \"{wan}\" meta nfproto ipv6 ip6 hoplimit 255 meta l4proto ipv6-icmp icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert }} accept\n        oifname \"{wan}\" counter drop comment \"full-tunnel router WAN blocked\"\n    }}\n");
        if config
            .ipv6
            .as_ref()
            .is_some_and(|v6| v6.wan_mode == WanMode::Auto)
        {
            let exception=format!("        oifname \"{wan}\" meta nfproto ipv6 udp sport 546 udp dport 547 accept\n        oifname \"{wan}\" ip6 daddr ff02::2 ip6 hoplimit 255 meta l4proto ipv6-icmp icmpv6 type nd-router-solicit accept\n");
            out.output = out.output.replace(
                &format!("        oifname \"{wan}\" counter drop"),
                &format!("{exception}        oifname \"{wan}\" counter drop"),
            );
        }
        let lan = crate::cidr(&config.lan.address, "lan.address")?.network_text();
        writeln!(
            out.forward,
            "        iifname \"{}\" oifname \"{name}\" ip saddr {lan} accept",
            config.lan.interface
        )
        .expect("String write");
        writeln!(
            out.nat,
            "        oifname \"{name}\" ip saddr {lan} masquerade"
        )
        .expect("String write");
    }
    let forwarding = if ipv6_enabled { 1 } else { 0 };
    out.sysctl=format!("net.ipv6.conf.all.forwarding={forwarding}\nnet.ipv6.conf.default.forwarding={forwarding}\nnet.ipv6.conf.all.accept_ra=0\nnet.ipv6.conf.default.accept_ra=0\nnet.ipv6.conf.all.accept_redirects=0\nnet.ipv6.conf.default.accept_redirects=0\n");
    if full.is_some() {
        out.sysctl.push_str("net.ipv4.conf.all.src_valid_mark=1\n");
    }
    if crate::provider::enabled(config) {
        let backup = crate::wan::device(config.wan_backup.as_ref().unwrap(), 1);
        // Generated policy expands to both links. User rules are rendered later
        // and never rewritten by this expansion.
        for field in [
            &mut out.input,
            &mut out.forward,
            &mut out.nat,
            &mut out.guard,
            &mut out.output,
        ] {
            let mut expanded = String::new();
            for line in field.lines() {
                expanded.push_str(line);
                expanded.push('\n');
                if line.contains(&format!("\"{wan}\"")) {
                    expanded
                        .push_str(&line.replace(&format!("\"{wan}\""), &format!("\"{backup}\"")));
                    expanded.push('\n');
                }
            }
            *field = expanded;
        }
        out.sets.push_str(
            "    set auto_sources { type ipv6_addr; flags interval,timeout; timeout 5s; }\n",
        );
        let gate=format!("        oifname {{ \"{wan}\", \"{backup}\" }} meta nfproto ipv6 ip6 saddr fe80::/10 udp sport 546 udp dport 547 accept\n        oifname {{ \"{wan}\", \"{backup}\" }} meta nfproto ipv6 ip6 hoplimit 255 meta l4proto ipv6-icmp icmpv6 type {{ nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit }} accept\n        oifname {{ \"{wan}\", \"{backup}\" }} meta nfproto ipv6 oifname != @auto_wan drop\n        oifname {{ \"{wan}\", \"{backup}\" }} meta nfproto ipv6 ip6 saddr != @auto_sources drop\n");
        if out.output.is_empty() {
            out.output=format!("    chain output {{\n        type filter hook output priority 0; policy accept;\n{gate}    }}\n");
        } else {
            out.output = out.output.replacen(
                "type filter hook output priority 0; policy accept;\n",
                &format!("type filter hook output priority 0; policy accept;\n{gate}"),
                1,
            );
        }
        out.sysctl
            .push_str("net.ipv6.conf.all.autoconf=0\nnet.ipv6.conf.default.autoconf=0\n");
        for uplink in crate::wan::uplinks(config) {
            writeln!(
                out.sysctl,
                "net.ipv6.conf.{}.accept_ra=0\nnet.ipv6.conf.{}.autoconf=0",
                uplink.interface, uplink.interface
            )
            .unwrap();
        }
    }
    Ok(out)
}
fn render_lan(
    out: &mut Extra,
    name: &str,
    value: &str,
    internet: bool,
    destination: &str,
    full: Option<&WireGuard>,
    v6_egress_allowed: bool,
) -> Result<(), String> {
    let subnet = host(value, 64, 64)?;
    let ip = Ipv6Addr::from(subnet.ip);
    let network = subnet.text();
    writeln!(out.setup, "ip -6 address add '{value}' dev '{name}'").expect("String write");
    writeln!(out.dnsmasq,"dhcp-range=set:rt6-{name},::,constructor:{name},ra-only,64,12h\ndhcp-option=tag:rt6-{name},option6:dns-server,[{ip}]").expect("String write");
    // Do not advertise an Internet default when this subnet is intentionally
    // isolated or the full tunnel has no IPv6 transport route.
    if !internet || !v6_egress_allowed {
        writeln!(out.dnsmasq, "ra-param={name},0,0").expect("String write");
    }
    writeln!(out.input,"        iifname \"{name}\" ip6 hoplimit 255 ip6 saddr {{ ::, fe80::/10 }} meta l4proto ipv6-icmp icmpv6 type nd-router-solicit accept").expect("String write");
    writeln!(out.input,"        iifname \"{name}\" ip6 saddr {network} ip6 daddr {ip} udp dport 53 accept\n        iifname \"{name}\" ip6 saddr {network} ip6 daddr {ip} tcp dport 53 accept\n        iifname \"{name}\" ip6 saddr {network} ip6 daddr {ip} meta l4proto ipv6-icmp icmpv6 type echo-request accept").expect("String write");
    if internet && v6_egress_allowed {
        writeln!(
            out.forward,
            "        iifname \"{name}\" oifname \"{destination}\" ip6 saddr {network} accept"
        )
        .expect("String write");
        if full.is_some_and(|wg| wg.nat66) {
            writeln!(
                out.nat,
                "        oifname \"{destination}\" ip6 saddr {network} masquerade"
            )
            .expect("String write");
        }
    }
    Ok(())
}
