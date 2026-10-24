use base64::{engine::general_purpose::STANDARD, Engine};
use routertop::{
    parse_config, render, validate, Config, FirewallAction, FirewallChain, FirewallFamily,
    FirewallProtocol, FirewallRule, Ipv6Config, Ipv6Vlan, Peer, Vlan, WireGuard,
};
use serde_json::json;

const SAMPLE: &str = include_str!("../../../configs/routertop.toml");
fn base() -> Config {
    parse_config(SAMPLE).unwrap()
}
fn v6() -> Ipv6Config {
    Ipv6Config {
        wan_address: Some("2001:db8:1::2/64".into()),
        wan_gateway: Some("2001:db8:1::1".into()),
        lan_address: "2001:db8:88::1/64".into(),
        vlans: vec![],
        dns_upstream: vec!["2001:4860:4860::8888".into()],
    }
}
fn tunnel() -> WireGuard {
    WireGuard {
        interface: "wg0".into(),
        address: "10.44.0.1/24".into(),
        listen_port: 51820,
        mtu: 1420,
        internet: false,
        peers: vec![Peer {
            public_key: STANDARD.encode([1u8; 32]),
            allowed_ips: vec!["0.0.0.0/0".into(), "::/0".into()],
            endpoint: Some("198.18.0.3:51820".into()),
            persistent_keepalive: 25,
        }],
        address_v6: Some("fd44::1/64".into()),
        full_tunnel: true,
        nat66: true,
    }
}
fn full() -> Config {
    let mut cfg = base();
    cfg.ipv6 = Some(v6());
    cfg.wireguard.push(tunnel());
    cfg
}
fn rule(id: &str) -> FirewallRule {
    FirewallRule {
        family: FirewallFamily::Ipv6,
        id: id.into(),
        enabled: true,
        chain: FirewallChain::Forward,
        action: FirewallAction::Drop,
        protocol: FirewallProtocol::Tcp,
        in_interface: Some("eth1".into()),
        out_interface: Some("eth0".into()),
        source: Some("2001:db8:88::/64".into()),
        destination: None,
        destination_port: Some(80),
        comment: "IPv6 web policy".into(),
    }
}

#[test]
fn old_config_defaults_disable_ipv6_and_full_tunnel() {
    let cfg = base();
    assert!(cfg.ipv6.is_none());
    let mut encoded = serde_json::to_value(tunnel()).unwrap();
    for key in ["address_v6", "full_tunnel", "nat66"] {
        encoded.as_object_mut().unwrap().remove(key);
    }
    let decoded: WireGuard = serde_json::from_value(encoded).unwrap();
    assert!(decoded.address_v6.is_none() && !decoded.full_tunnel && !decoded.nat66);
    let mut encoded = serde_json::to_value(rule("a")).unwrap();
    encoded.as_object_mut().unwrap().remove("family");
    let decoded: FirewallRule = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded.family, FirewallFamily::Ipv4);
    let rendered = render(&cfg).unwrap();
    assert!(rendered.sysctl.contains("net.ipv6.conf.all.forwarding=0"));
    assert!(!rendered.nftables.contains("chain output"));
}

#[test]
fn static_ipv6_renders_ra_dns_neighbor_discovery_pmtu_and_scoped_forwarding() {
    let mut cfg = base();
    cfg.ipv6 = Some(v6());
    let output = render(&cfg).unwrap();
    assert!(output
        .network_setup
        .contains("ip -6 address add '2001:db8:1::2/64' dev 'eth0'"));
    assert!(output
        .network_setup
        .contains("ip -6 route replace default via '2001:db8:1::1' dev 'eth0'"));
    assert!(output
        .network_setup
        .contains("ip -6 address add '2001:db8:88::1/64' dev 'eth1'"));
    assert!(output.dnsmasq.contains("constructor:eth1,ra-only,64,12h"));
    assert!(output
        .dnsmasq
        .contains("option6:dns-server,[2001:db8:88::1]"));
    assert!(output.dnsmasq.contains("server=2001:4860:4860::8888"));
    assert!(output.nftables.contains("ip6 hoplimit 255 meta l4proto ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert }"));
    assert!(output.nftables.contains("packet-too-big"));
    assert!(output
        .nftables
        .contains("iifname \"eth1\" oifname \"eth0\" ip6 saddr 2001:db8:88::/64 accept"));
    assert!(!output
        .nftables
        .contains("ip6 saddr 2001:db8:88::/64 tcp dport 443"));
    assert!(output.sysctl.contains("net.ipv6.conf.all.forwarding=1"));
    assert!(output.sysctl.contains("net.ipv6.conf.all.accept_ra=0"));
}

#[test]
fn ipv6_vlan_ra_survives_disabled_ipv4_dhcp_and_isolation() {
    let mut cfg = base();
    cfg.vlans.push(Vlan {
        interface: "guest".into(),
        parent: "eth1".into(),
        id: 10,
        address: "192.168.10.1/24".into(),
        dhcp: None,
        internet: false,
    });
    let mut ipv6 = v6();
    ipv6.vlans.push(Ipv6Vlan {
        interface: "guest".into(),
        address: "fd10::1/64".into(),
    });
    cfg.ipv6 = Some(ipv6);
    let output = render(&cfg).unwrap();
    assert!(!output.dnsmasq.contains("no-dhcpv4-interface=guest"));
    assert!(!output.dnsmasq.contains("no-dhcp-interface=guest"));
    assert!(output
        .dnsmasq
        .contains("dhcp-range=set:rt6-guest,::,constructor:guest,ra-only,64,12h"));
    assert!(!output.dnsmasq.contains("dhcp-range=set:rt-guest,"));
    assert!(!output
        .nftables
        .lines()
        .any(|line| line.contains("iifname \"guest\"") && line.contains("udp dport 67")));
    assert!(output.dnsmasq.contains("ra-param=guest,0,0"));
    assert!(!output
        .nftables
        .contains("iifname \"guest\" oifname \"eth0\" ip6"));
    cfg.vlans[0].internet = true;
    assert!(render(&cfg)
        .unwrap()
        .nftables
        .contains("iifname \"guest\" oifname \"eth0\" ip6 saddr fd10::/64 accept"));
    cfg.ipv6 = None;
    assert!(render(&cfg)
        .unwrap()
        .dnsmasq
        .contains("no-dhcp-interface=guest"));
}

#[test]
fn ipv6_address_prefix_gateway_and_dns_validation() {
    for address in [
        "2001:db8:88::1/63",
        "2001:DB8:88::1/64",
        "2001:0db8:88::1/64",
        "2001:db8:88::/64",
        "fe80::1/64",
        "ff02::1/64",
        "::1/64",
        "::ffff:192.0.2.1/128",
        "fd88::1/064",
        "fd88::1/64;reboot",
    ] {
        let mut cfg = base();
        let mut ipv6 = v6();
        ipv6.lan_address = address.into();
        cfg.ipv6 = Some(ipv6);
        assert!(render(&cfg).is_err(), "{address}");
    }
    for gateway in [
        "fe80::1%eth0",
        "2001:db8:2::1",
        "2001:db8:1::2",
        "::",
        "ff02::1",
    ] {
        let mut cfg = base();
        let mut ipv6 = v6();
        ipv6.wan_gateway = Some(gateway.into());
        cfg.ipv6 = Some(ipv6);
        assert!(validate(&cfg).is_err(), "{gateway}");
    }
    let mut cfg = base();
    let mut ipv6 = v6();
    ipv6.wan_gateway = Some("fe80::1".into());
    cfg.ipv6 = Some(ipv6);
    assert!(validate(&cfg).is_ok());
    for upstream in [
        "::1",
        "fe80::1",
        "ff02::1",
        "2001:db8:88::1",
        "2001:db8:88::",
        "invalid\nserver=foo",
    ] {
        cfg.ipv6.as_mut().unwrap().dns_upstream = vec![upstream.into()];
        assert!(validate(&cfg).is_err(), "{upstream}");
    }
    cfg.ipv6.as_mut().unwrap().dns_upstream = vec![];
    assert!(validate(&cfg).is_ok());
}

#[test]
fn connected_ipv6_subnets_and_vlan_references_must_be_disjoint() {
    let mut cfg = base();
    let mut ipv6 = v6();
    ipv6.lan_address = "2001:db8:1::3/64".into();
    cfg.ipv6 = Some(ipv6);
    assert!(validate(&cfg).is_err());
    cfg.ipv6 = Some(v6());
    cfg.ipv6.as_mut().unwrap().vlans.push(Ipv6Vlan {
        interface: "ghost".into(),
        address: "fd10::1/64".into(),
    });
    assert!(validate(&cfg).is_err());
    cfg.ipv6 = Some(v6());
    let mut wg = tunnel();
    wg.address_v6 = Some("2001:db8:88::2/64".into());
    cfg.wireguard.push(wg);
    assert!(validate(&cfg).is_err());
}

#[test]
fn full_tunnel_contract_rejects_ambiguous_or_incomplete_defaults() {
    assert!(validate(&full()).is_ok());
    for allowed in [
        vec!["::/0"],
        vec!["0.0.0.0/0", "0.0.0.0/0"],
        vec!["0.0.0.0/0", "10.20.0.0/16"],
        vec!["0.0.0.0/1", "128.0.0.0/1"],
    ] {
        let mut cfg = full();
        cfg.wireguard[0].peers[0].allowed_ips = allowed.into_iter().map(str::to_string).collect();
        assert!(validate(&cfg).is_err());
    }
    let mut cfg = full();
    cfg.wireguard[0].internet = true;
    assert!(validate(&cfg).is_err());
    let mut cfg = full();
    cfg.wireguard[0].peers[0].endpoint = None;
    assert!(validate(&cfg).is_err());
    let mut cfg = full();
    cfg.wireguard[0].address_v6 = None;
    assert!(validate(&cfg).is_err());
    let mut cfg = full();
    cfg.wireguard[0].mtu = 1279;
    assert!(validate(&cfg).is_err());
    let mut cfg = full();
    cfg.wireguard[0].full_tunnel = false;
    assert!(validate(&cfg).is_err());
    let mut cfg = full();
    let mut second = tunnel();
    second.interface = "wg1".into();
    second.address = "10.45.0.1/24".into();
    second.address_v6 = Some("fd45::1/64".into());
    second.listen_port = 51821;
    cfg.wireguard.push(second);
    assert!(validate(&cfg).is_err());
}

#[test]
fn full_tunnel_policy_routes_preserve_main_and_mark_transport_before_linkup() {
    let output = render(&full()).unwrap();
    let setup = &output.network_setup;
    assert!(setup.contains("ip -4 route replace default dev 'wg0' table 51820"));
    assert!(setup.contains("ip -6 route replace default dev 'wg0' table 51820"));
    assert!(setup.contains("priority 100 table main suppress_prefixlength 0"));
    assert!(setup.contains("priority 110 not fwmark 21076 table 51820"));
    assert!(!setup.contains("ip route replace '0.0.0.0/0'"));
    assert!(!setup.contains("ip -6 route replace '::/0'"));
    assert!(
        setup.find("wg set 'wg0' fwmark 21076").unwrap()
            < setup.find("ip link set dev 'wg0' up").unwrap()
    );
    assert!(output.sysctl.contains("net.ipv4.conf.all.src_valid_mark=1"));
}

#[test]
fn full_tunnel_wan_kill_switch_precedes_established_and_custom_accepts() {
    let mut cfg = full();
    let mut allow = rule("allow-v6");
    allow.action = FirewallAction::Accept;
    cfg.firewall.rules.push(allow);
    let output = render(&cfg).unwrap();
    let forward = output.nftables.split("chain forward").nth(1).unwrap();
    let gate = forward.find("full-tunnel direct WAN blocked").unwrap();
    assert!(gate < forward.find("ct state established,related").unwrap());
    assert!(gate < forward.find("allow-v6:").unwrap());
    let out = output
        .nftables
        .split("chain output")
        .nth(1)
        .unwrap()
        .split("chain postrouting")
        .next()
        .unwrap();
    assert!(out.contains("meta mark 21076 udp sport { 51820 } accept"));
    assert!(out.contains("udp sport 68 udp dport 67 accept"));
    assert!(out.contains("full-tunnel router WAN blocked"));
    assert!(!out.contains("ct state established"));
    assert!(!out.contains("dport 53 accept"));
    assert!(output
        .nftables
        .contains("oifname \"wg0\" ip saddr 192.168.88.0/24 masquerade"));
    assert!(output
        .nftables
        .contains("oifname \"wg0\" ip6 saddr 2001:db8:88::/64 masquerade"));
}

#[test]
fn ipv4_only_full_tunnel_blocks_ipv6_forwarding_but_keeps_local_ra_nd() {
    let mut cfg = full();
    cfg.wireguard[0].peers[0].allowed_ips = vec!["0.0.0.0/0".into()];
    cfg.wireguard[0].address_v6 = None;
    cfg.wireguard[0].nat66 = false;
    let output = render(&cfg).unwrap();
    let forward = output.nftables.split("chain forward").nth(1).unwrap();
    assert!(
        forward
            .find("IPv4-only full tunnel blocks IPv6 forwarding")
            .unwrap()
            < forward.find("ct state established,related").unwrap()
    );
    assert!(!output.network_setup.contains("ip -6 rule add"));
    assert!(output.dnsmasq.contains("constructor:eth1,ra-only"));
    assert!(output.dnsmasq.contains("ra-param=eth1,0,0"));
    assert!(output.nftables.contains("nd-neighbor-solicit"));
    assert!(output
        .nftables
        .contains("tcp dport 443 ct state new accept"));
}

#[test]
fn full_and_split_wireguard_sockets_share_transport_mark_without_broad_wan_udp_allow() {
    let mut cfg = full();
    let mut split = tunnel();
    split.interface = "wg1".into();
    split.address = "10.45.0.1/24".into();
    split.address_v6 = Some("fd45::1/64".into());
    split.full_tunnel = false;
    split.nat66 = false;
    split.listen_port = 51821;
    split.peers[0].allowed_ips = vec!["10.45.0.2/32".into(), "fd45::2/128".into()];
    cfg.wireguard.push(split);
    let output = render(&cfg).unwrap();
    assert!(output.network_setup.contains("wg set 'wg1' fwmark 21076"));
    assert!(output
        .nftables
        .contains("meta mark 21076 udp sport { 51820, 51821 } accept"));
    assert!(!output.nftables.contains("oifname \"eth0\" udp accept"));
}

#[test]
fn routed_v6_option_and_ipv6_over_ipv4_only_transport_are_explicit() {
    let mut cfg = full();
    cfg.wireguard[0].nat66 = false;
    let output = render(&cfg).unwrap();
    assert!(!output
        .nftables
        .contains("ip6 saddr 2001:db8:88::/64 masquerade"));
    cfg.ipv6.as_mut().unwrap().wan_address = None;
    cfg.ipv6.as_mut().unwrap().wan_gateway = None;
    assert!(render(&cfg).is_ok());
    cfg.wireguard.clear();
    assert!(validate(&cfg).is_err());
}

#[test]
fn ipv6_peer_routes_support_own_host_and_remote_site_but_reject_overlap() {
    let mut cfg = base();
    let mut split = tunnel();
    split.full_tunnel = false;
    split.nat66 = false;
    split.peers[0].allowed_ips = vec!["fd44::2/128".into(), "2001:db8:20::/64".into()];
    cfg.wireguard.push(split);
    assert!(validate(&cfg).is_ok());
    for allowed in [
        "fd44::1/128",
        "fd44::/64",
        "2001:db8:20::1/64",
        "ff00::/8",
        "fe80::/10",
        "::/0",
        "fd44::128/65",
    ] {
        cfg.wireguard[0].peers[0].allowed_ips = vec![allowed.into()];
        assert!(validate(&cfg).is_err(), "{allowed}");
    }
    cfg.wireguard[0].peers[0].allowed_ips = vec!["2001:db8:20::/64".into()];
    let mut other = cfg.wireguard[0].peers[0].clone();
    other.public_key = STANDARD.encode([2u8; 32]);
    other.allowed_ips = vec!["2001:db8:20::/80".into()];
    cfg.wireguard[0].peers.push(other);
    assert!(validate(&cfg).is_err());
}

#[test]
fn firewall_family_protocol_network_matching_and_ipv6_order() {
    let mut cfg = base();
    cfg.ipv6 = Some(v6());
    let mut first = rule("first");
    first.protocol = FirewallProtocol::Icmpv6;
    first.destination_port = None;
    cfg.firewall.rules.push(first);
    let mut second = rule("second");
    second.action = FirewallAction::Accept;
    cfg.firewall.rules.push(second);
    let output = render(&cfg).unwrap();
    assert!(output.nftables.contains("meta nfproto ipv6 iifname \"eth1\" oifname \"eth0\" ip6 saddr 2001:db8:88::/64 meta l4proto ipv6-icmp counter drop"));
    assert!(output.nftables.find("first:").unwrap() < output.nftables.find("second:").unwrap());
    assert!(
        output.nftables.find("second:").unwrap()
            < output
                .nftables
                .find("iifname \"eth1\" oifname \"eth0\" ip6 saddr 2001:db8:88::/64 accept")
                .unwrap()
    );
    cfg.firewall.rules[0].source = Some("192.168.88.0/24".into());
    assert!(validate(&cfg).is_err());
    cfg.firewall.rules[0].source = None;
    cfg.firewall.rules[0].protocol = FirewallProtocol::Icmp;
    assert!(validate(&cfg).is_err());
    cfg.firewall.rules[0].family = FirewallFamily::Ipv4;
    cfg.firewall.rules[0].protocol = FirewallProtocol::Icmpv6;
    assert!(validate(&cfg).is_err());
}

#[test]
fn strict_ipv6_json_and_roundtrip_no_private_fields() {
    let mut value = serde_json::to_value(v6()).unwrap();
    value["post_up"] = json!("reboot");
    assert!(serde_json::from_value::<Ipv6Config>(value).is_err());
    let cfg = full();
    let encoded = toml::to_string(&cfg).unwrap();
    let decoded = parse_config(&encoded).unwrap();
    assert_eq!(
        render(&cfg).unwrap().nftables,
        render(&decoded).unwrap().nftables
    );
    assert!(!encoded.contains("private_key"));
    assert!(!render(&cfg).unwrap().network_setup.contains("private_key"));
}

#[test]
fn live_wan_validator_exempts_full_defaults_but_not_specific_conflicts() {
    let cfg = full();
    assert!(routertop::network::validate_wan_subnets(&cfg, &["198.18.0.2/24".into()]).is_ok());
    let mut cfg = cfg;
    let mut split = tunnel();
    split.interface = "wg1".into();
    split.address = "10.45.0.1/24".into();
    split.address_v6 = None;
    split.full_tunnel = false;
    split.nat66 = false;
    split.listen_port = 51821;
    split.peers[0].endpoint = None;
    split.peers[0].allowed_ips = vec!["198.18.0.0/24".into()];
    cfg.wireguard.push(split);
    assert!(routertop::network::validate_wan_subnets(&cfg, &["198.18.0.2/24".into()]).is_err());
}
