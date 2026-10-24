use routertop::{parse_config, render, validate, Config, WanProtocol};
use serde_json::json;
fn config() -> Config {
    let mut value = serde_json::to_value(
        parse_config(include_str!("../../../configs/routertop.toml")).unwrap(),
    )
    .unwrap();
    value["wan"]["mode"] = json!("pppoe");
    value["wan"]["pppoe"] = json!({"username":"dial account","password":"pass\\\"word","mtu":1492});
    serde_json::from_value(value).unwrap()
}
#[test]
fn backward_compatible_and_logical_wan_policies() {
    let old = parse_config(include_str!("../../../configs/routertop.toml")).unwrap();
    assert_eq!(old.wan.mode, WanProtocol::Dhcp);
    assert_eq!(old.wan.device(), "eth0");
    let cfg = config();
    let r = render(&cfg).unwrap();
    assert_eq!(cfg.wan.device(), "ppp0");
    assert!(r.interfaces.contains("iface eth0 inet manual"));
    assert!(!r.interfaces.contains("dhcp-program"));
    assert!(r
        .nftables
        .contains("oifname \"ppp0\" ip saddr 192.168.88.0/24 masquerade"));
    for public in [
        r.interfaces,
        r.nftables,
        r.network_setup,
        r.dhcpcd,
        r.dnsmasq,
    ] {
        assert!(!public.contains("dial account"));
        assert!(!public.contains("word"));
    }
    assert!(!format!("{cfg:?}").contains("pass\\\"word"));
}
#[test]
fn private_options_escape_credentials_and_reject_injection() {
    let cfg = config();
    let text =
        routertop::pppoe::peer_options(&cfg, std::path::Path::new("/run/routertop/pppoe")).unwrap();
    assert!(text.contains("persist\nmaxfail 0\nholdoff 5"));
    assert!(text.contains("unit 0\nifname ppp0"));
    assert!(text.contains("user \"dial account\""));
    assert!(text.contains("password \"pass\\\\\\\"word\""));
    for field in ["username", "password"] {
        for value in [
            json!(""),
            json!("bad\nplugin /tmp/evil"),
            json!("x".repeat(129)),
            json!("非ASCII"),
        ] {
            let mut j = serde_json::to_value(config()).unwrap();
            j["wan"]["pppoe"][field] = value;
            let cfg: Config = serde_json::from_value(j).unwrap();
            let error = validate(&cfg).unwrap_err();
            assert!(!error.contains("evil"));
        }
    }
}
#[test]
fn rejects_mode_collisions_and_mtu_and_static_ppp_ipv6() {
    for mtu in [1279, 1493] {
        let mut c = config();
        c.wan.pppoe.as_mut().unwrap().mtu = mtu;
        assert!(validate(&c).is_err());
    }
    let mut c = config();
    c.wan.mode = WanProtocol::Dhcp;
    assert!(validate(&c).is_err());
    let mut c = config();
    c.lan.interface = "ppp0".into();
    assert!(validate(&c).is_err());
    let mut c = config();
    c.wan.pppoe = None;
    assert!(validate(&c).is_err());
    let mut c = config();
    c.ipv6=Some(serde_json::from_value(json!({"vlans":[],"dns_upstream":[],"wan_mode":"static","wan_address":"2001:db8:1::2/64","wan_gateway":"2001:db8:1::1","lan_address":"2001:db8:88::1/64"})).unwrap());
    assert!(validate(&c).is_err());
}
#[test]
fn ppp_ipv6cp_uses_dhcpv6_without_router_advertisement() {
    let mut c = config();
    c.ipv6=Some(serde_json::from_value(json!({"vlans":[],"dns_upstream":[],"wan_mode":"auto","lan_address":"","pd":{"prefix_length":56,"lan_subnet_id":0,"vlans":[]}})).unwrap());
    let r = render(&c).unwrap();
    assert!(r.dhcpcd.contains("interface ppp0\n noipv6rs\n ia_na 1"));
    let text =
        routertop::pppoe::peer_options(&c, std::path::Path::new("/run/routertop/pppoe")).unwrap();
    assert!(text.contains("+ipv6\n"));
    assert!(text.contains("defaultroute6"));
    assert!(r
        .nftables
        .contains("iifname \"ppp0\" meta nfproto ipv6 udp sport 547 udp dport 546 accept"));
}
#[test]
fn malformed_toml_never_echoes_credentials() {
    let e = parse_config("[wan]\npassword = \"TOP_SECRET").unwrap_err();
    assert!(!e.contains("TOP_SECRET"));
}

#[test]
fn ppp_tcp_mss_uses_kernel_path_mtu_in_both_directions_before_established() {
    let cfg = config();
    let peer =
        routertop::pppoe::peer_options(&cfg, std::path::Path::new("/run/routertop/pppoe")).unwrap();
    assert!(peer.contains("/usr/sbin/pppoe -I eth0 -T 15"));
    assert!(!peer.contains(" -m "));
    let nft = render(&cfg).unwrap().nftables;
    let forward = nft.split("chain forward").nth(1).unwrap();
    let established = forward.find("ct state established,related accept").unwrap();
    for interface in ["iifname", "oifname"] {
        let rule = format!("{interface} \"ppp0\" tcp flags syn tcp option maxseg size set rt mtu");
        assert!(forward.find(&rule).unwrap() < established);
    }
    assert_eq!(nft.matches("maxseg size set rt mtu").count(), 2);
    let dhcp =
        render(&parse_config(include_str!("../../../configs/routertop.toml")).unwrap()).unwrap();
    assert!(!dhcp.nftables.contains("maxseg"));
    let mut lower = cfg;
    lower.wan.pppoe.as_mut().unwrap().mtu = 1280;
    assert_eq!(
        render(&lower)
            .unwrap()
            .nftables
            .matches("maxseg size set rt mtu")
            .count(),
        2
    );
}
