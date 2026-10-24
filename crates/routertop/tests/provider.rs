use routertop::provider::{accepts, Epoch};
use routertop::{parse_config, render, validate, Config, ProviderPolicy};
use serde_json::json;
use std::collections::BTreeMap;

fn config(primary: &str, backup: &str) -> Config {
    let mut value = serde_json::to_value(
        parse_config(include_str!("../../../configs/routertop.toml")).unwrap(),
    )
    .unwrap();
    for (field, mode, interface) in [("wan", primary, "eth0"), ("wan_backup", backup, "eth2")] {
        value[field] = json!({"interface":interface,"mode":mode,"pppoe":if mode=="pppoe"{json!({"username":"user","password":"secret","mtu":1492})}else{serde_json::Value::Null},"static_ipv4":null});
    }
    value["failover"] = json!({"primary_target":"203.0.113.9","backup_target":"203.0.113.10","interval_seconds":2,"failure_threshold":1,"recovery_threshold":1});
    value["ipv6"] = json!({"provider_policy":"active-standby","wan_mode":"auto","wan_address":null,"wan_gateway":null,"lan_address":"","vlans":[],"dns_upstream":[],"pd":{"prefix_length":56,"lan_subnet_id":0,"vlans":[]}});
    serde_json::from_value(value).unwrap()
}

#[test]
fn optin_is_strict_and_legacy_defaults_do_not_enable_backup() {
    for a in ["dhcp", "pppoe"] {
        for b in ["dhcp", "pppoe"] {
            validate(&config(a, b)).unwrap();
        }
    }
    let base = config("dhcp", "dhcp");
    let mut value = serde_json::to_value(&base).unwrap();
    value["ipv6"]
        .as_object_mut()
        .unwrap()
        .remove("provider_policy");
    let legacy: Config = serde_json::from_value(value).unwrap();
    assert_eq!(
        legacy.ipv6.unwrap().provider_policy,
        ProviderPolicy::PrimaryOnly
    );
    let mut no_pd = base.clone();
    no_pd.ipv6.as_mut().unwrap().pd = None;
    assert!(validate(&no_pd).unwrap_err().contains("active-standby"));
    let mut single = base;
    single.wan_backup = None;
    single.failover = None;
    assert!(validate(&single).unwrap_err().contains("active-standby"));
}

#[test]
fn backup_uses_real_ppp1_and_finite_gates_precede_user_and_conntrack_accepts() {
    let cfg = config("dhcp", "pppoe");
    let output = render(&cfg).unwrap();
    let nft = &output.nftables;
    assert!(nft.contains("iifname \"ppp1\" meta nfproto ipv6 udp sport 547 udp dport 546 accept"));
    assert!(nft.contains("oifname \"ppp1\" oifname != @auto_wan drop"));
    assert!(nft.contains("oifname \"ppp1\" ip6 saddr @pd_net0 accept"));
    assert!(nft.contains("ip6 saddr != @auto_sources drop"));
    assert!(!nft.contains("iifname != @primary_v6 drop"));
    assert!(output.sysctl.contains("net.ipv6.conf.default.autoconf=0"));
    let mut backup = cfg.clone();
    backup.wan = cfg.wan_backup.unwrap();
    let client = routertop::pd::render_client_for(&backup, "ppp1").unwrap();
    assert!(client.contains("interface ppp1\n noipv6rs"));
    assert!(!client.contains("interface ppp0"));
    let epoch = Epoch {
        boot: "boot".into(),
        generation: 3,
        slot: Some(1),
        logical_interface: "ppp1".into(),
        incarnation: "session".into(),
    };
    assert_eq!(epoch.provider(), Some("backup"));
}

#[test]
fn origin_epoch_rejects_aba_reconnect_interface_and_boot_reuse() {
    let current = Epoch {
        boot: "boot-a".into(),
        generation: 5,
        slot: Some(0),
        logical_interface: "ppp0".into(),
        incarnation: "session-2".into(),
    };
    let mut env = BTreeMap::from([
        ("interface".into(), "ppp0".into()),
        ("ROUTERTOP_PD_EPOCH".into(), current.token()),
    ]);
    assert!(accepts(&current, &env));
    for old in [
        Epoch {
            generation: 3,
            ..current.clone()
        },
        Epoch {
            incarnation: "session-1".into(),
            ..current.clone()
        },
        Epoch {
            boot: "boot-b".into(),
            ..current.clone()
        },
        Epoch {
            slot: Some(1),
            logical_interface: "ppp1".into(),
            ..current.clone()
        },
    ] {
        env.insert("ROUTERTOP_PD_EPOCH".into(), old.token());
        assert!(!accepts(&current, &env));
    }
    env.remove("ROUTERTOP_PD_EPOCH");
    assert!(!accepts(&current, &env));
}

#[test]
fn production_event_never_mutates_lease_for_stale_aba_or_unstamped_origin() {
    let cfg = config("dhcp", "dhcp");
    let dir = std::env::temp_dir().join(format!(
        "routertop-epoch-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let current = Epoch {
        boot: "boot".into(),
        generation: 5,
        slot: Some(0),
        logical_interface: "eth0".into(),
        incarnation: "".into(),
    };
    std::fs::write(
        dir.join("provider.json"),
        serde_json::to_vec(&current).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("lease.json"), b"sentinel").unwrap();
    for reason in ["BOUND6", "STOP6", "EXPIRE6"] {
        let old = Epoch {
            generation: 3,
            ..current.clone()
        };
        let mut env = BTreeMap::from([
            ("interface".into(), "eth0".into()),
            ("reason".into(), reason.into()),
            ("ROUTERTOP_PD_EPOCH".into(), old.token()),
        ]);
        routertop::pd::event(&cfg, &dir, &env).unwrap();
        env.remove("ROUTERTOP_PD_EPOCH");
        routertop::pd::event(&cfg, &dir, &env).unwrap();
        assert_eq!(std::fs::read(dir.join("lease.json")).unwrap(), b"sentinel");
    }
    std::fs::remove_dir_all(dir).unwrap();
}
