use routertop::{parse_config, render, validate, Config, WanProtocol};
use serde_json::{json, Value};
fn base() -> Value {
    serde_json::to_value(parse_config(include_str!("../../../configs/routertop.toml")).unwrap())
        .unwrap()
}
fn decode(value: Value) -> Config {
    serde_json::from_value(value).unwrap()
}
fn dual(primary: &str, backup: &str) -> Config {
    let mut value = base();
    for (key, dev, mode) in [("wan", "eth0", primary), ("wan_backup", "eth2", backup)] {
        value[key] = json!({"interface":dev,"mode":mode,"pppoe":null,"static_ipv4":null});
        if mode == "static" {
            value[key]["static_ipv4"] = json!({"address":"198.18.0.2/24","gateway":"198.18.0.1"});
        }
        if mode == "pppoe" {
            value[key]["pppoe"] = json!({"username":format!("{dev}-account"),"password":format!("{dev}-private-credential"),"mtu":1492});
        }
    }
    value["failover"] = json!({"primary_target":"203.0.113.9","backup_target":"203.0.113.9"});
    decode(value)
}
#[test]
fn static_single_wan_renders_address_gateway_without_dhcp_or_secret() {
    let mut value = base();
    value["wan"] = json!({"interface":"eth0","mode":"static","static_ipv4":{"address":"198.18.0.2/24","gateway":"198.18.0.1"}});
    let config = decode(value);
    validate(&config).unwrap();
    let out = render(&config).unwrap();
    assert!(out.interfaces.contains("iface eth0 inet static\n    address 198.18.0.2\n    netmask 255.255.255.0\n    gateway 198.18.0.1"));
    assert!(!out.interfaces.contains("dhcp-program"));
    assert!(out
        .nftables
        .contains("oifname \"eth0\" ip saddr 192.168.88.0/24 masquerade"));
}
#[test]
fn every_supported_dual_protocol_pair_validates_and_has_private_acquisition() {
    for primary in ["dhcp", "static", "pppoe"] {
        for backup in ["dhcp", "static", "pppoe"] {
            let config = dual(primary, backup);
            validate(&config).unwrap();
            let out = render(&config).unwrap();
            assert!(out.interfaces.contains("iface eth0 inet manual"));
            assert!(out.interfaces.contains("iface eth2 inet manual"));
            assert!(!out.interfaces.contains("gateway "));
            assert!(!out.interfaces.contains("dhcp-program"));
            for (slot, w) in routertop::wan::uplinks(&config).iter().enumerate() {
                let dev = routertop::wan::device(w, slot);
                assert!(out.nftables.contains(&format!(
                    "oifname \"{dev}\" ip saddr 192.168.88.0/24 masquerade"
                )));
            }
            assert!(!out.nftables.contains("private-credential"));
            assert!(!out.interfaces.contains("private-credential"));
        }
    }
}
#[test]
fn failover_gates_precede_conntrack_and_both_ppp_mss_are_present() {
    let out = render(&dual("pppoe", "pppoe")).unwrap();
    let forward = out.nftables.split("chain forward {").nth(1).unwrap();
    assert!(
        forward.find("oifname != @active_wan drop").unwrap()
            < forward.find("ct state established,related accept").unwrap()
    );
    assert!(
        forward.find("oifname != @primary_v6 drop").unwrap()
            < forward.find("ct state established,related accept").unwrap()
    );
    for dev in ["ppp0", "ppp1"] {
        assert!(forward.contains(&format!(
            "oifname \"{dev}\" tcp flags syn tcp option maxseg size set rt mtu"
        )));
    }
    assert!(out
        .nftables
        .contains("set active_wan { type ifname; flags timeout;"));
}
#[test]
fn static_boundaries_conflicts_and_protocol_options_fail_closed() {
    let valid = dual("static", "dhcp");
    for (address, gateway) in [
        ("198.18.0.0/24", "198.18.0.1"),
        ("198.18.0.255/24", "198.18.0.1"),
        ("198.18.0.2/31", "198.18.0.3"),
        ("198.18.0.2/24", "198.18.1.1"),
        ("198.18.0.2/24", "198.18.0.2"),
        ("192.168.88.2/24", "192.168.88.254"),
        ("198.18.0.2/024", "198.18.0.1"),
        ("198.18.0.2/24;touch bad", "198.18.0.1"),
    ] {
        let mut c = valid.clone();
        let s = c.wan.static_ipv4.as_mut().unwrap();
        s.address = address.into();
        s.gateway = gateway.into();
        assert!(validate(&c).is_err(), "{address} {gateway}");
    }
    let mut c = valid.clone();
    c.wan.mode = WanProtocol::Dhcp;
    assert!(validate(&c).is_err());
    let mut c = valid;
    c.wan.static_ipv4 = None;
    assert!(validate(&c).is_err());
}
#[test]
fn backup_contract_rejects_missing_failover_interface_aliases_and_local_probe_targets() {
    let valid = dual("dhcp", "pppoe");
    let mut c = valid.clone();
    c.failover = None;
    assert!(validate(&c).is_err());
    let mut c = valid.clone();
    c.wan_backup = None;
    assert!(validate(&c).is_err());
    for dev in ["eth0", "eth1", "ppp0", "ppp1", "bad;sh"] {
        let mut c = valid.clone();
        c.wan_backup.as_mut().unwrap().interface = dev.into();
        assert!(validate(&c).is_err(), "{dev}");
    }
    for target in [
        "127.0.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "192.168.88.1",
        "example.com",
        "203.0.113.9;reboot",
    ] {
        let mut c = valid.clone();
        c.failover.as_mut().unwrap().primary_target = target.into();
        assert!(validate(&c).is_err(), "{target}");
    }
    for (interval, fail, recovery) in [
        (1, 3, 3),
        (61, 3, 3),
        (5, 0, 3),
        (5, 11, 3),
        (5, 3, 0),
        (5, 3, 11),
    ] {
        let mut c = valid.clone();
        let f = c.failover.as_mut().unwrap();
        f.interval_seconds = interval;
        f.failure_threshold = fail;
        f.recovery_threshold = recovery;
        assert!(validate(&c).is_err());
    }
}
#[test]
fn dual_wan_automatic_ipv6_is_primary_only_and_static_v6_requires_single_wan() {
    let mut value = serde_json::to_value(dual("dhcp", "dhcp")).unwrap();
    value["ipv6"] = json!({"wan_mode":"auto","pd":{"prefix_length":56,"lan_subnet_id":0,"vlans":[]},"vlans":[],"dns_upstream":[]});
    let config = decode(value.clone());
    validate(&config).unwrap();
    let out = render(&config).unwrap();
    assert!(out.dhcpcd.contains("interface eth0"));
    assert!(!out.dhcpcd.contains("interface eth2"));
    assert!(out.nftables.contains("primary_v6"));
    value["ipv6"] = json!({"wan_mode":"static","wan_address":"2001:db8:1::2/64","wan_gateway":"2001:db8:1::1","lan_address":"fd88::1/64","vlans":[],"dns_upstream":[]});
    assert!(validate(&decode(value.clone()))
        .unwrap_err()
        .contains("automatic primary IPv6"));
    value["wan_backup"] = Value::Null;
    value["failover"] = Value::Null;
    let c = decode(value);
    validate(&c).unwrap();
    assert!(render(&c)
        .unwrap()
        .network_setup
        .contains("ip -6 route replace default"));
}
#[test]
fn schema_defaults_roundtrip_and_backup_debug_redacts_credentials() {
    let c = parse_config(include_str!("../../../configs/routertop.toml")).unwrap();
    assert!(c.wan_backup.is_none());
    assert!(c.failover.is_none());
    assert!(c.wan.static_ipv4.is_none());
    let c = dual("dhcp", "pppoe");
    assert_eq!(c.failover.as_ref().unwrap().interval_seconds, 5);
    assert_eq!(c.failover.as_ref().unwrap().failure_threshold, 3);
    assert_eq!(c.failover.as_ref().unwrap().recovery_threshold, 3);
    let serialized = toml::to_string(&c).unwrap();
    let decoded = parse_config(&serialized).unwrap();
    assert_eq!(decoded.wan_backup.unwrap().mode, WanProtocol::Pppoe);
    assert!(!format!("{c:?}").contains("eth2-private-credential"));
}

#[test]
fn explicit_interface_firewall_rules_are_never_broadened_to_another_uplink() {
    let mut value = serde_json::to_value(dual("dhcp", "dhcp")).unwrap();
    value["firewall"]["rules"] = json!([
        {"id":"primary-only-admin","enabled":true,"chain":"input","action":"accept","protocol":"tcp","in_interface":"eth0","out_interface":null,"source":null,"destination":null,"destination_port":8443,"comment":"primary scope"},
        {"id":"backup-only-deny","enabled":true,"chain":"forward","action":"drop","protocol":"tcp","in_interface":"eth2","out_interface":null,"source":null,"destination":null,"destination_port":8444,"comment":"backup scope"}
    ]);
    let rendered = render(&decode(value)).unwrap();
    for (id, dev) in [("primary-only-admin", "eth0"), ("backup-only-deny", "eth2")] {
        let lines: Vec<_> = rendered
            .nftables
            .lines()
            .filter(|l| l.contains(id))
            .collect();
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains(&format!("iifname \"{dev}\"")));
    }
}

#[test]
fn dual_probe_reverse_path_policy_covers_existing_underlays_and_future_ppp_only_in_dual_mode() {
    for primary in ["dhcp", "static", "pppoe"] {
        let out = render(&dual(primary, "pppoe")).unwrap();
        assert!(out.sysctl.contains("net.ipv4.conf.all.rp_filter=0\n"));
        assert!(out.sysctl.contains("net.ipv4.conf.default.rp_filter=0\n"));
        for dev in ["eth0", "eth2"] {
            assert!(out
                .sysctl
                .contains(&format!("net/ipv4/conf/{dev}/rp_filter=0\n")));
        }
        assert!(!out.sysctl.contains("net/ipv4/conf/ppp0/rp_filter"));
        assert!(!out.sysctl.contains("net/ipv4/conf/ppp1/rp_filter"));
    }
    let out = render(&decode(base())).unwrap();
    assert!(!out.sysctl.contains("rp_filter"));
}
