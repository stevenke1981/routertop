use base64::{engine::general_purpose::STANDARD, Engine};
use routertop::pd::{delegated, lease_from_env, Lease, LeasePrefix};
use routertop::{parse_config, render, validate, Config, WanMode};
use serde_json::json;
use std::collections::BTreeMap;

fn config() -> Config {
    let base = parse_config(include_str!("../../../configs/routertop.toml")).unwrap();
    let mut value = serde_json::to_value(base).unwrap();
    value["vlans"] = json!([{"interface":"guest","parent":"eth1","id":20,"address":"192.168.20.1/24","dhcp":null,"internet":true}]);
    value["ipv6"] = json!({"wan_mode":"auto","wan_address":null,"wan_gateway":null,"lan_address":"","vlans":[],"dns_upstream":[],"dns_auto":true,"pd":{"prefix_length":56,"lan_subnet_id":0,"vlans":[{"interface":"guest","subnet_id":1}]}});
    serde_json::from_value(value).unwrap()
}
fn lease() -> Lease {
    Lease {
        acquired: 100,
        prefixes: vec![LeasePrefix {
            prefix: "2001:db8:100::/56".into(),
            preferred_seconds: 30,
            valid_seconds: 60,
        }],
        dns: vec!["2001:db8:1::53".into()],
        dns_lifetime: 60,
    }
}

#[test]
fn legacy_static_ipv6_defaults_remain_compatible() {
    let mut value = serde_json::to_value(config()).unwrap();
    value["ipv6"] = json!({"wan_address":"2001:db8:1::2/64","wan_gateway":"fe80::1","lan_address":"2001:db8:88::1/64","vlans":[],"dns_upstream":[]});
    let cfg: Config = serde_json::from_value(value).unwrap();
    validate(&cfg).unwrap();
    let v6 = cfg.ipv6.as_ref().unwrap();
    assert_eq!(v6.wan_mode, WanMode::Static);
    assert!(v6.pd.is_none());
    let output = render(&cfg).unwrap();
    assert!(output.dhcpcd.is_empty());
    assert!(!output.nftables.contains("auto_wan"));
    assert!(!output.dnsmasq.contains("/run/routertop/pd"));
}

#[test]
fn dynamic_model_rejects_conflicts_unknown_fields_and_id_aliases() {
    let original = serde_json::to_value(config()).unwrap();
    let bad = [
        ("/ipv6/wan_address", json!("2001:db8:1::2/64")),
        ("/ipv6/wan_gateway", json!("fe80::1")),
        ("/ipv6/lan_address", json!("fd88::1/64")),
        ("/ipv6/wan_mode", json!("static")),
        ("/ipv6/pd/prefix_length", json!(47)),
        ("/ipv6/pd/prefix_length", json!(65)),
        ("/ipv6/pd/lan_subnet_id", json!(256)),
        ("/ipv6/pd/vlans/0/subnet_id", json!(256)),
        ("/ipv6/pd/vlans/0/subnet_id", json!(0)),
        ("/ipv6/pd/vlans/0/interface", json!("eth1")),
        ("/ipv6/pd/vlans/0/interface", json!("guest;reboot")),
    ];
    for (pointer, scalar) in bad {
        let mut value = original.clone();
        *value.pointer_mut(pointer).unwrap() = scalar;
        let cfg: Config = serde_json::from_value(value).unwrap();
        assert!(validate(&cfg).is_err(), "{pointer}");
        assert!(render(&cfg).is_err(), "render must revalidate {pointer}");
    }
    for pointer in ["/ipv6", "/ipv6/pd", "/ipv6/pd/vlans/0"] {
        let mut value = original.clone();
        value.pointer_mut(pointer).unwrap()["unexpected"] = json!(true);
        assert!(serde_json::from_value::<Config>(value).is_err());
    }
}

#[test]
fn pd_boundary_sizes_unique_networks_and_actual_grant_capacity() {
    let mut cfg = config();
    let pd = cfg.ipv6.as_mut().unwrap().pd.as_mut().unwrap();
    pd.prefix_length = 48;
    pd.vlans[0].subnet_id = 65535;
    validate(&cfg).unwrap();
    let mut grant = lease();
    grant.prefixes[0].prefix = "2001:db8::/48".into();
    let entries = delegated(&cfg, &grant, 110).unwrap();
    assert_eq!(entries[0].address, "2001:db8::1/64");
    assert_eq!(entries[1].address, "2001:db8:0:ffff::1/64");
    assert_eq!(entries[0].preferred_seconds, 20);
    assert_eq!(entries[0].valid_seconds, 50);
    grant.prefixes[0].prefix = "2001:db8:100::/56".into();
    assert!(delegated(&cfg, &grant, 110)
        .unwrap_err()
        .contains("too small"));
    let pd = cfg.ipv6.as_mut().unwrap().pd.as_mut().unwrap();
    pd.prefix_length = 64;
    pd.vlans.clear();
    validate(&cfg).unwrap();
    grant.prefixes[0].prefix = "2001:db8:100::/64".into();
    assert_eq!(delegated(&cfg, &grant, 110).unwrap().len(), 1);
}

#[test]
fn lease_renumber_deprecation_and_expiry_use_monotonic_remaining_time() {
    let cfg = config();
    let mut grant = lease();
    assert!(delegated(&cfg, &grant, 160).unwrap().is_empty());
    assert_eq!(
        delegated(&cfg, &grant, 135).unwrap()[0].preferred_seconds,
        0
    );
    grant.prefixes[0].valid_seconds = 0;
    grant.prefixes[0].preferred_seconds = 0;
    grant.prefixes.push(LeasePrefix {
        prefix: "2001:db8:200::/56".into(),
        preferred_seconds: 20,
        valid_seconds: 40,
    });
    let entries = delegated(&cfg, &grant, 110).unwrap();
    assert_eq!(entries.len(), 2);
    assert!(entries
        .iter()
        .all(|e| e.prefix.starts_with("2001:db8:200:")));
    grant.prefixes.push(grant.prefixes[1].clone());
    assert!(delegated(&cfg, &grant, 110).is_err());
}

#[test]
fn dhcpcd_environment_is_typed_and_no_untrusted_strings_reach_commands() {
    let mut env = BTreeMap::from([
        ("new_dhcp6_ia_pd1_prefix1".into(), "2001:db8:100::".into()),
        ("new_dhcp6_ia_pd1_prefix1_length".into(), "56".into()),
        ("new_dhcp6_ia_pd1_prefix1_pltime".into(), "30".into()),
        ("new_dhcp6_ia_pd1_prefix1_vltime".into(), "60".into()),
        (
            "new_dhcp6_name_servers".into(),
            "2001:db8:1::53 ::1 fe80::1 ;reboot".into(),
        ),
    ]);
    let parsed = lease_from_env(&env, 100).unwrap();
    assert_eq!(parsed.dns, vec!["2001:db8:1::53"]);
    assert_eq!(parsed.dns_lifetime, 60);
    assert_eq!(parsed.prefixes.len(), 1);
    assert_eq!(parsed.prefixes[0].prefix, "2001:db8:100::/56");
    assert_eq!(delegated(&config(), &parsed, 100).unwrap().len(), 2);
    env.insert(
        "new_dhcp6_ia_pd1_prefix1".into(),
        "2001:db8::;reboot".into(),
    );
    assert!(lease_from_env(&env, 100).is_err());
    env.insert("new_dhcp6_ia_pd1_prefix1".into(), "2001:db8:100::".into());
    env.insert("new_dhcp6_ia_pd1_prefix1_pltime".into(), "61".into());
    assert!(lease_from_env(&env, 100).is_err());
}

#[test]
fn dynamic_render_has_scoped_client_finite_sets_and_pre_conntrack_guards() {
    let cfg = config();
    let output = render(&cfg).unwrap();
    assert!(output.dhcpcd.contains("ipv6only\nnoipv6rs\n"));
    assert!(output.dhcpcd.contains("allowinterfaces eth0 eth1 guest"));
    assert!(output
        .dhcpcd
        .contains("ia_pd 2/::/56 eth1/0/64/1 guest/1/64/1"));
    assert!(output
        .nftables
        .contains("flags interval,timeout; timeout 5s"));
    let forward = output.nftables.split("chain forward").nth(1).unwrap();
    assert!(
        forward.find("ip6 saddr != @pd_net0 drop").unwrap()
            < forward.find("ct state established").unwrap()
    );
    assert!(forward.contains("oifname \"eth0\" oifname != @auto_wan drop"));
    assert!(!output.dnsmasq.contains("no-dhcp-interface=guest"));
    assert!(!output.dnsmasq.contains("dhcp-range=set:rt-guest,"));
    assert!(output.dnsmasq.contains("constructor:guest,ra-only"));
    assert!(output
        .dnsmasq
        .contains("resolv-file=/run/routertop/pd/resolv.conf"));
    assert!(output
        .nftables
        .contains("iifname \"eth0\" ip6 saddr fe80::/10 ip6 hoplimit 255"));
    assert!(!output
        .nftables
        .contains("udp dport 546 accept\n        iifname \"guest\""));
}

#[test]
fn identity_survives_reinitialization_but_corruption_never_resets_it() {
    let cfg = config();
    let base = std::env::temp_dir().join(format!(
        "routertop-pd-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let identity = base.join("identity/duid");
    let runtime = base.join("runtime");
    routertop::pd::initialize(&cfg, &runtime, &identity).unwrap();
    let first = std::fs::read(&identity).unwrap();
    std::fs::write(runtime.join("lease.json"), "old lease").unwrap();
    routertop::pd::initialize(&cfg, &runtime, &identity).unwrap();
    assert_eq!(std::fs::read(&identity).unwrap(), first);
    assert_eq!(
        std::fs::read_to_string(runtime.join("lease.json")).unwrap(),
        "{}"
    );
    std::fs::write(&identity, "broken").unwrap();
    assert!(routertop::pd::initialize(&cfg, &runtime, &identity).is_err());
    assert_eq!(std::fs::read_to_string(&identity).unwrap(), "broken");
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn pd_with_full_tunnel_preserves_wan_gate_and_never_uses_learned_dns() {
    let mut value = serde_json::to_value(config()).unwrap();
    value["wireguard"] = json!([{"interface":"wg0","address":"10.44.0.1/24","address_v6":"fd44::1/64","listen_port":51820,"mtu":1420,"internet":false,"full_tunnel":true,"nat66":true,"peers":[{"public_key":STANDARD.encode([1u8;32]),"allowed_ips":["0.0.0.0/0","::/0"],"endpoint":"198.18.0.3:51820","persistent_keepalive":25}]}]);
    let cfg: Config = serde_json::from_value(value.clone()).unwrap();
    let output = render(&cfg).unwrap();
    assert!(output.nftables.contains("full-tunnel direct WAN blocked"));
    assert!(output.nftables.contains("ip6 saddr @pd_net0 masquerade"));
    assert!(output
        .nftables
        .contains("meta nfproto ipv6 udp sport 546 udp dport 547 accept"));
    assert!(output
        .nftables
        .contains("ip6 daddr ff02::2 ip6 hoplimit 255"));
    assert!(output.dnsmasq.contains("no-resolv\n"));
    assert!(!output.dnsmasq.contains("resolv-file="));
    value["wireguard"][0]["peers"][0]["allowed_ips"] = json!(["0.0.0.0/0"]);
    value["wireguard"][0]["nat66"] = json!(false);
    let cfg: Config = serde_json::from_value(value).unwrap();
    let output = render(&cfg).unwrap();
    assert!(output
        .nftables
        .contains("IPv4-only full tunnel blocks IPv6 forwarding"));
    assert!(output.dnsmasq.contains("ra-param=eth1,5,0"));
    assert!(!output
        .nftables
        .contains("oifname \"wg0\" ip6 saddr @pd_net0 accept"));
}

#[test]
fn actual_delegation_rejects_wireguard_connected_and_remote_site_overlap() {
    let mut value = serde_json::to_value(config()).unwrap();
    value["wireguard"] = json!([{"interface":"wg0","address":"10.44.0.1/24","address_v6":"2001:db8:100::1/64","listen_port":51820,"mtu":1420,"internet":false,"peers":[{"public_key":STANDARD.encode([1u8;32]),"allowed_ips":["10.44.0.2/32"],"endpoint":"198.18.0.3:51820","persistent_keepalive":25}]}]);
    let cfg: Config = serde_json::from_value(value.clone()).unwrap();
    validate(&cfg).unwrap();
    assert!(delegated(&cfg, &lease(), 100)
        .unwrap_err()
        .contains("WireGuard interface"));
    value["wireguard"][0]["address_v6"] = json!("fd44::1/64");
    value["wireguard"][0]["peers"][0]["allowed_ips"] = json!(["2001:db8:100::/64"]);
    let cfg: Config = serde_json::from_value(value).unwrap();
    validate(&cfg).unwrap();
    assert!(delegated(&cfg, &lease(), 100)
        .unwrap_err()
        .contains("WireGuard route"));
}
