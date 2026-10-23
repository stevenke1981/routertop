use base64::{engine::general_purpose::STANDARD, Engine};
use routertop::{
    parse_config, render, validate, Config, Dhcp, FirewallAction, FirewallChain, FirewallProtocol,
    FirewallRule, Peer, Route, Vlan, WireGuard,
};
use serde_json::json;

const SAMPLE: &str = include_str!("../../../configs/routertop.toml");
fn sample() -> Config {
    parse_config(SAMPLE).unwrap()
}
fn vlan() -> Vlan {
    Vlan {
        interface: "guest10".into(),
        parent: "eth1".into(),
        id: 10,
        address: "192.168.10.1/24".into(),
        dhcp: Some(Dhcp {
            start: "192.168.10.100".into(),
            end: "192.168.10.199".into(),
            lease_hours: 12,
        }),
        internet: false,
    }
}
fn peer() -> Peer {
    Peer {
        public_key: STANDARD.encode([1u8; 32]),
        allowed_ips: vec!["10.7.0.2/32".into()],
        endpoint: Some("198.18.0.2:51820".into()),
        persistent_keepalive: 25,
    }
}
fn wg() -> WireGuard {
    WireGuard {
        interface: "wg0".into(),
        address: "10.7.0.1/24".into(),
        listen_port: 51820,
        mtu: 1420,
        internet: false,
        peers: vec![peer()],
    }
}
fn rule(id: &str) -> FirewallRule {
    FirewallRule {
        id: id.into(),
        enabled: true,
        chain: FirewallChain::Forward,
        action: FirewallAction::Drop,
        protocol: FirewallProtocol::Tcp,
        in_interface: Some("eth1".into()),
        out_interface: Some("eth0".into()),
        source: Some("192.168.88.0/24".into()),
        destination: None,
        destination_port: Some(80),
        comment: "block web".into(),
    }
}

#[test]
fn legacy_config_defaults_and_extended_toml_roundtrip() {
    let mut config = sample();
    assert!(
        config.vlans.is_empty() && config.wireguard.is_empty() && config.firewall.rules.is_empty()
    );
    config.vlans.push(vlan());
    config.wireguard.push(wg());
    config.firewall.rules.push(rule("block-web"));
    let encoded = toml::to_string(&config).unwrap();
    let decoded = parse_config(&encoded).unwrap();
    assert_eq!(
        render(&config).unwrap().nftables,
        render(&decoded).unwrap().nftables
    );
    assert_eq!(
        render(&config).unwrap().network_setup,
        render(&decoded).unwrap().network_setup
    );
}

#[test]
fn new_models_reject_unknown_fields_private_keys_and_missing_required_values() {
    let mut model = serde_json::to_value(vlan()).unwrap();
    model["raw_script"] = json!("reboot");
    assert!(serde_json::from_value::<Vlan>(model).is_err());
    let mut model = serde_json::to_value(vlan()).unwrap();
    model.as_object_mut().unwrap().remove("internet");
    assert!(serde_json::from_value::<Vlan>(model).is_err());
    let mut model = serde_json::to_value(wg()).unwrap();
    model["private_key"] = json!(STANDARD.encode([9u8; 32]));
    assert!(serde_json::from_value::<WireGuard>(model).is_err());
    let mut model = serde_json::to_value(peer()).unwrap();
    model["private_key"] = json!("forbidden");
    assert!(serde_json::from_value::<Peer>(model).is_err());
    for field in ["chain", "action", "protocol"] {
        let mut model = serde_json::to_value(rule("a")).unwrap();
        model[field] = json!("accept; flush ruleset");
        assert!(serde_json::from_value::<FirewallRule>(model).is_err());
    }
    let mut model = serde_json::to_value(rule("a")).unwrap();
    model["nft"] = json!("accept");
    assert!(serde_json::from_value::<FirewallRule>(model).is_err());
}

#[test]
fn vlan_tags_parents_names_and_subnets_have_strict_boundaries() {
    for tag in [1, 4094] {
        let mut config = sample();
        let mut entry = vlan();
        entry.id = tag;
        config.vlans.push(entry);
        assert!(validate(&config).is_ok());
    }
    for tag in [0, 4095, u16::MAX] {
        let mut config = sample();
        let mut entry = vlan();
        entry.id = tag;
        config.vlans.push(entry);
        assert!(render(&config).is_err());
    }
    for name in [
        "eth0",
        "eth1",
        "lo",
        "guest;reboot",
        "guest\nup",
        "../guest",
        "$(id)",
        "abcdefghijklmnop",
    ] {
        let mut config = sample();
        let mut entry = vlan();
        entry.interface = name.into();
        config.vlans.push(entry);
        assert!(render(&config).is_err(), "{name}");
    }
    let mut config = sample();
    config.vlans.push(vlan());
    let mut second = vlan();
    second.interface = "guest20".into();
    second.address = "192.168.20.1/24".into();
    second.dhcp = None;
    config.vlans.push(second);
    assert!(validate(&config).is_err()); // duplicate tag on same parent
    config.vlans[1].parent = "eth0".into();
    assert!(validate(&config).is_ok()); // same tag on another physical parent
    config.vlans[1].parent = "guest10".into();
    assert!(validate(&config).is_err()); // nesting
    for address in [
        "192.168.88.2/24",
        "192.168.0.1/16",
        "192.168.10.0/24",
        "192.168.10.255/24",
        "192.168.10.1/31",
        "192.168.10.1/024",
        "224.0.0.1/24",
    ] {
        let mut config = sample();
        let mut entry = vlan();
        entry.address = address.into();
        entry.dhcp = None;
        config.vlans.push(entry);
        assert!(validate(&config).is_err(), "{address}");
    }
}

#[test]
fn vlan_dhcp_dns_and_route_conflicts_fail_before_rendering() {
    for (start, end, lease) in [
        ("192.168.10.1", "192.168.10.199", 12),
        ("192.168.10.0", "192.168.10.199", 12),
        ("192.168.10.100", "192.168.10.255", 12),
        ("192.168.10.199", "192.168.10.100", 12),
        ("192.168.10.100", "192.168.20.199", 12),
        ("192.168.10.100", "192.168.10.199", 0),
        ("192.168.10.100", "192.168.10.199", 8761),
    ] {
        let mut config = sample();
        let mut entry = vlan();
        entry.dhcp = Some(Dhcp {
            start: start.into(),
            end: end.into(),
            lease_hours: lease,
        });
        config.vlans.push(entry);
        assert!(render(&config).is_err());
    }
    let mut config = sample();
    config.vlans.push(vlan());
    config.dns.upstream = vec!["192.168.10.1".into()];
    assert!(validate(&config).is_err());
    config.dns.upstream = vec!["1.1.1.1".into()];
    config.routes.push(Route {
        destination: "192.168.10.0/24".into(),
        gateway: "192.168.88.2".into(),
    });
    assert!(validate(&config).is_err());
    config.routes[0].destination = "10.7.0.0/24".into();
    config.vlans.clear();
    config.wireguard.push(wg());
    assert!(validate(&config).is_err());
}

#[test]
fn isolated_vlan_rendering_scopes_services_and_internet_is_opt_in() {
    let mut config = sample();
    config.vlans.push(vlan());
    let rendered = render(&config).unwrap();
    assert!(rendered
        .network_setup
        .contains("ip link add link 'eth1' name 'guest10' type vlan id 10"));
    assert!(rendered
        .dnsmasq
        .contains("dhcp-range=set:rt-guest10,192.168.10.100,192.168.10.199,255.255.255.0,12h"));
    assert!(rendered
        .dnsmasq
        .contains("dhcp-option=tag:rt-guest10,option:router,192.168.10.1"));
    assert!(rendered
        .dnsmasq
        .contains("dhcp-option=tag:rt-guest10,option:dns-server,192.168.10.1"));
    assert!(rendered.nftables.contains(
        "iifname \"guest10\" ip saddr 192.168.10.0/24 ip daddr 192.168.10.1 udp dport 53 accept"
    ));
    assert!(!rendered.nftables.contains("iifname \"guest10\" oifname"));
    assert!(!rendered
        .nftables
        .contains("ip saddr 192.168.10.0/24 masquerade"));
    assert!(!rendered
        .nftables
        .contains("iifname \"guest10\" ip saddr 192.168.10.0/24 tcp dport 443"));
    config.vlans[0].internet = true;
    config.vlans[0].dhcp = None;
    let rendered = render(&config).unwrap();
    assert!(rendered
        .nftables
        .contains("iifname \"guest10\" oifname \"eth0\" ip saddr 192.168.10.0/24 accept"));
    assert!(rendered
        .nftables
        .contains("oifname \"eth0\" ip saddr 192.168.10.0/24 masquerade"));
    assert!(!rendered
        .nftables
        .contains("iifname \"guest10\" oifname \"eth1\""));
    assert!(rendered.dnsmasq.contains("no-dhcp-interface=guest10"));
}

#[test]
fn public_key_endpoint_mtu_and_listener_validation() {
    for key in [
        "".to_string(),
        STANDARD.encode([0u8; 32]),
        STANDARD.encode([1u8; 31]),
        STANDARD.encode([1u8; 33]),
        format!("{}\n", STANDARD.encode([1u8; 32])),
        STANDARD.encode([1u8; 32]).trim_end_matches('=').to_string(),
    ] {
        let mut config = sample();
        let mut entry = wg();
        entry.peers[0].public_key = key;
        config.wireguard.push(entry);
        assert!(render(&config).is_err());
    }
    for endpoint in [
        "router.test:51820",
        "198.18.0.2:0",
        "198.18.0.2:65536",
        "198.18.0.2:051820",
        "127.0.0.1:51820",
        "224.1.1.1:51820",
        "198.18.0.2:51820;reboot",
        "192.168.88.1:51820",
        "[::1]:51820",
    ] {
        let mut config = sample();
        let mut entry = wg();
        entry.peers[0].endpoint = Some(endpoint.into());
        config.wireguard.push(entry);
        assert!(render(&config).is_err(), "{endpoint}");
    }
    for port in [0, 53, 67, 68] {
        let mut config = sample();
        let mut entry = wg();
        entry.listen_port = port;
        config.wireguard.push(entry);
        assert!(validate(&config).is_err());
    }
    for mtu in [575, 9001] {
        let mut config = sample();
        let mut entry = wg();
        entry.mtu = mtu;
        config.wireguard.push(entry);
        assert!(validate(&config).is_err());
    }
    for mtu in [576, 9000] {
        let mut config = sample();
        let mut entry = wg();
        entry.mtu = mtu;
        entry.listen_port = 443;
        config.wireguard.push(entry);
        assert!(validate(&config).is_ok());
    } // UDP may share TCP HTTPS port
}

#[test]
fn peer_routes_reject_default_noncanonical_local_and_overlapping_prefixes() {
    for allowed in [
        "0.0.0.0/0",
        "10.20.1.0/16",
        "10.20.0.0/016",
        "224.0.0.0/4",
        "127.0.0.0/8",
        "192.168.88.0/24",
        "192.168.10.0/24",
        "10.7.0.1/32",
        "10.7.0.0/24",
        "10.7.0.128/25",
        "198.18.0.0/24",
        "10.20.0.0/16;reboot",
    ] {
        let mut config = sample();
        config.vlans.push(vlan());
        let mut entry = wg();
        entry.peers[0].allowed_ips = vec![allowed.into()];
        config.wireguard.push(entry);
        assert!(render(&config).is_err(), "{allowed}");
    }
    let mut config = sample();
    config.wireguard.push(wg());
    assert!(validate(&config).is_ok()); // own WG /32 host exception
    config.wireguard[0].peers[0]
        .allowed_ips
        .push("10.20.0.0/16".into());
    assert!(validate(&config).is_ok()); // remote site
    let mut second = peer();
    second.public_key = STANDARD.encode([2u8; 32]);
    second.allowed_ips = vec!["10.20.128.0/17".into()];
    config.wireguard[0].peers.push(second);
    assert!(validate(&config).is_err());
    config.wireguard[0].peers.pop();
    config.wireguard[0].peers[0].allowed_ips.clear();
    assert!(validate(&config).is_err());
}

#[test]
fn cross_interface_peer_endpoint_and_static_route_conflicts() {
    let mut config = sample();
    config.wireguard.push(wg());
    let mut second = wg();
    second.interface = "wg1".into();
    second.address = "10.8.0.1/24".into();
    second.listen_port = 51821;
    second.peers[0].public_key = STANDARD.encode([2u8; 32]);
    second.peers[0].allowed_ips = vec!["10.8.0.2/32".into()];
    config.wireguard.push(second);
    assert!(validate(&config).is_ok());
    config.wireguard[1].peers[0].allowed_ips = vec!["10.7.0.3/32".into()];
    assert!(validate(&config).is_err()); // other WG connected subnet
    config.wireguard[0].peers[0]
        .allowed_ips
        .push("10.20.0.0/16".into());
    config.wireguard[1].peers[0].allowed_ips = vec!["10.20.128.0/17".into()];
    assert!(validate(&config).is_err()); // peer route overlap
    config.wireguard[1].peers[0].allowed_ips = vec!["10.8.0.2/32".into()];
    config.wireguard[1].peers[0].endpoint = Some("10.20.1.2:51820".into());
    assert!(validate(&config).is_err()); // endpoint captured by another WG
    config.wireguard[1].peers[0].endpoint = None;
    config.routes.push(Route {
        destination: "10.20.0.0/16".into(),
        gateway: "192.168.88.2".into(),
    });
    assert!(validate(&config).is_err());
    config.routes.clear();
    config.wireguard[1].listen_port = 51820;
    assert!(validate(&config).is_err());
}

#[test]
fn wireguard_setup_has_no_keys_and_nat_covers_remote_site_sources() {
    let mut config = sample();
    let mut entry = wg();
    entry.peers[0].allowed_ips.push("10.20.0.0/16".into());
    config.wireguard.push(entry);
    let rendered = render(&config).unwrap();
    assert!(rendered
        .network_setup
        .contains("wg setconf 'wg0' '/run/routertop/wireguard/wg0.conf'"));
    assert!(rendered
        .network_setup
        .contains("ip route replace '10.7.0.2/32' dev 'wg0'"));
    assert!(!rendered
        .network_setup
        .contains(&config.wireguard[0].peers[0].public_key));
    assert!(!rendered.network_setup.contains("private"));
    assert!(!rendered.nftables.contains("iifname \"wg0\" oifname"));
    config.wireguard[0].internet = true;
    let rendered = render(&config).unwrap();
    for source in ["10.7.0.2/32", "10.20.0.0/16"] {
        assert!(rendered.nftables.contains(&format!(
            "iifname \"wg0\" oifname \"eth0\" ip saddr {source} accept"
        )));
        assert!(rendered
            .nftables
            .contains(&format!("oifname \"eth0\" ip saddr {source} masquerade")));
    }
    assert!(!rendered
        .nftables
        .contains("iifname \"wg0\" oifname \"eth1\""));
}

#[test]
fn custom_rules_preserve_order_before_forward_defaults_after_input_reservations() {
    let mut config = sample();
    config.wireguard.push(wg());
    let first = rule("first");
    let mut second = rule("second");
    second.action = FirewallAction::Accept;
    let mut input = rule("input-drop");
    input.chain = FirewallChain::Input;
    input.protocol = FirewallProtocol::Any;
    input.out_interface = None;
    input.destination_port = None;
    config.firewall.rules = vec![first, second, input];
    let rendered = render(&config).unwrap();
    let rules = &rendered.nftables;
    let input_pos = rules.find("comment \"input-drop:").unwrap();
    assert!(rules.find("udp dport 51820 accept").unwrap() < input_pos);
    assert!(rules.find("tcp dport 443 ct state new accept").unwrap() < input_pos);
    let first_pos = rules.find("comment \"first:").unwrap();
    let second_pos = rules.find("comment \"second:").unwrap();
    let implicit = rules
        .find("iifname \"eth1\" oifname \"eth0\" ip saddr 192.168.88.0/24 accept")
        .unwrap();
    assert!(first_pos < second_pos && second_pos < implicit);
    config.firewall.rules.swap(0, 1);
    let rendered = render(&config).unwrap();
    assert!(
        rendered.nftables.find("comment \"second:").unwrap()
            < rendered.nftables.find("comment \"first:").unwrap()
    );
    config.firewall.rules[0].enabled = false;
    assert!(!render(&config)
        .unwrap()
        .nftables
        .contains("comment \"second:"));
    assert_eq!(rendered.nftables.matches("policy drop;").count(), 2);
}

#[test]
fn firewall_names_ports_comments_and_networks_reject_injection() {
    for comment in [
        "newline\naccept",
        "\"; flush ruleset",
        "back\\slash",
        "中文",
    ] {
        let mut config = sample();
        let mut entry = rule("safe");
        entry.comment = comment.into();
        config.firewall.rules.push(entry);
        assert!(render(&config).is_err());
    }
    for id in ["", "id;reboot", "has space", "id\naccept"] {
        let mut config = sample();
        config.firewall.rules.push(rule(id));
        assert!(render(&config).is_err());
    }
    let mut config = sample();
    config.firewall.rules.push(rule("safe"));
    config.firewall.rules[0].in_interface = Some("ghost".into());
    assert!(validate(&config).is_err());
    config.firewall.rules[0].in_interface = Some("eth1".into());
    config.firewall.rules[0].chain = FirewallChain::Input;
    assert!(validate(&config).is_err());
    config.firewall.rules[0].chain = FirewallChain::Forward;
    config.firewall.rules[0].destination_port = Some(0);
    assert!(validate(&config).is_err());
    config.firewall.rules[0].destination_port = Some(80);
    config.firewall.rules[0].protocol = FirewallProtocol::Icmp;
    assert!(validate(&config).is_err());
    config.firewall.rules[0].destination_port = None;
    config.firewall.rules[0].source = Some("192.168.88.1/24".into());
    assert!(validate(&config).is_err());
    config.firewall.rules[0].source = Some("0.0.0.0/0".into());
    config.firewall.rules[0].action = FirewallAction::Reject;
    assert!(render(&config)
        .unwrap()
        .nftables
        .contains("counter reject comment"));
    config.firewall.rules.push(config.firewall.rules[0].clone());
    assert!(validate(&config).is_err());
}

#[test]
fn configured_collection_limits_are_enforced() {
    let mut config = sample();
    config.vlans = vec![vlan(); 17];
    assert!(validate(&config).is_err());
    let mut config = sample();
    config.wireguard = vec![wg(); 5];
    assert!(validate(&config).is_err());
    let mut config = sample();
    let mut entry = wg();
    entry.peers = vec![peer(); 33];
    config.wireguard.push(entry);
    assert!(validate(&config).is_err());
    let mut config = sample();
    config.firewall.rules = (0..65).map(|i| rule(&format!("r{i}"))).collect();
    assert!(validate(&config).is_err());
}

#[test]
fn endpoint_must_avoid_all_wireguard_connected_routes_but_may_use_lan_or_vlan() {
    let mut config = sample();
    config.vlans.push(vlan());
    config.wireguard.push(wg());
    // These are outside this peer's /32 allowed IP but inside the automatically
    // installed connected route, which would send encrypted transport into WG.
    for endpoint in ["10.7.0.3:51820", "10.7.0.0:51820", "10.7.0.255:51820"] {
        config.wireguard[0].peers[0].endpoint = Some(endpoint.into());
        let error = validate(&config).unwrap_err();
        assert!(error.contains("connected subnet"), "{error}");
    }
    let mut other = wg();
    other.interface = "wg1".into();
    other.address = "10.8.0.1/24".into();
    other.listen_port = 51821;
    other.peers[0].allowed_ips = vec!["10.8.0.2/32".into()];
    other.peers[0].endpoint = None;
    config.wireguard.push(other);
    config.wireguard[0].peers[0].endpoint = Some("10.8.0.3:51821".into());
    assert!(validate(&config).unwrap_err().contains("connected subnet"));
    // Connected LAN/VLAN endpoints are legitimate directly reachable peers.
    for endpoint in ["192.168.88.2:51820", "192.168.10.2:51820"] {
        config.wireguard[0].peers[0].endpoint = Some(endpoint.into());
        assert!(validate(&config).is_ok(), "{endpoint}");
    }
}

#[test]
fn wan_subnets_reject_equal_more_specific_and_covering_wireguard_routes() {
    use routertop::network::validate_wan_subnets;
    let wan = vec!["198.18.0.2/24".to_string()];
    let mut config = sample();
    let mut tunnel = wg();
    tunnel.peers[0].endpoint = None;
    config.wireguard.push(tunnel);
    assert!(validate_wan_subnets(&config, &wan).is_ok());
    for allowed in [
        "198.18.0.0/24",
        "198.18.0.1/32",
        "198.18.0.128/25",
        "198.18.0.0/16",
    ] {
        config.wireguard[0].peers[0].allowed_ips = vec![allowed.into()];
        let error = validate_wan_subnets(&config, &wan).unwrap_err();
        assert!(
            error.contains("overlaps live WAN connected network 198.18.0.0/24"),
            "{error}"
        );
    }
}

#[test]
fn wan_subnets_reject_local_lan_vlan_wireguard_and_static_route_collisions() {
    use routertop::network::validate_wan_subnets;
    let wan = vec!["198.18.0.2/24".to_string()];
    let mut config = sample();
    config.lan.address = "198.18.0.1/24".into();
    config.dhcp.start = "198.18.0.100".into();
    config.dhcp.end = "198.18.0.199".into();
    assert!(validate_wan_subnets(&config, &wan)
        .unwrap_err()
        .contains("overlaps live WAN"));
    let mut config = sample();
    let mut vlan = vlan();
    vlan.address = "198.18.0.1/24".into();
    vlan.dhcp = None;
    config.vlans.push(vlan);
    assert!(validate_wan_subnets(&config, &wan)
        .unwrap_err()
        .contains("overlaps live WAN"));
    let mut config = sample();
    let mut tunnel = wg();
    tunnel.address = "198.18.0.1/24".into();
    tunnel.peers.clear();
    config.wireguard.push(tunnel);
    assert!(validate_wan_subnets(&config, &wan)
        .unwrap_err()
        .contains("overlaps live WAN"));
    let mut config = sample();
    config.routes.push(Route {
        destination: "198.18.0.0/24".into(),
        gateway: "192.168.88.2".into(),
    });
    assert!(validate_wan_subnets(&config, &wan)
        .unwrap_err()
        .contains("overlaps live WAN"));
}

#[test]
fn wan_subnets_handle_unknown_wan_prefix_extremes_and_validate_configuration_first() {
    use routertop::network::validate_wan_subnets;
    let mut config = sample();
    assert!(validate_wan_subnets(&config, &[]).is_ok());
    config.vlans.push(vlan());
    assert!(validate_wan_subnets(&config, &[]).is_ok());
    config.wireguard.push(wg());
    assert!(validate_wan_subnets(&config, &[])
        .unwrap_err()
        .contains("known WAN IPv4 lease"));
    assert!(validate_wan_subnets(&config, &["198.18.0.2/32".into()]).is_ok());
    assert!(validate_wan_subnets(&config, &["198.18.0.2/31".into()]).is_ok());
    assert!(validate_wan_subnets(&config, &["198.18.0.2/0".into()])
        .unwrap_err()
        .contains("overlaps live WAN"));
    assert!(
        validate_wan_subnets(&config, &["198.18.0.2/24".into(), "192.168.10.2/24".into()]).is_err()
    );
    for invalid in [
        "198.18.0.2",
        "198.18.0.2/33",
        "198.18.0.2/-1",
        "::1/32",
        "198.18.0.2/24;reboot",
    ] {
        assert!(
            validate_wan_subnets(&config, &[invalid.into()]).is_err(),
            "{invalid}"
        );
    }
    config.wireguard.clear();
    config.vlans.clear();
    config.wan.interface = "unsafe;reboot".into();
    assert!(validate_wan_subnets(&config, &[]).is_err());
}
