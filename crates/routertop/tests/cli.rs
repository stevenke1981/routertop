use std::{fs, process::Command};

fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_routertop"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn cli_validates_exports_and_rejects_invalid_arguments() {
    let config = concat!(env!("CARGO_MANIFEST_DIR"), "/../../configs/routertop.toml");
    assert!(cli(&["check", config]).status.success());
    let exported = cli(&["export", config]);
    assert!(exported.status.success());
    routertop::parse_config(std::str::from_utf8(&exported.stdout).unwrap()).unwrap();
    // Public configurations remain exportable without privilege, but an ISP
    // credential-bearing export is a local root administration operation.
    let root = std::env::temp_dir().join(format!("routertop-cli-private-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let private = root.join("pppoe.toml");
    let mut value =
        routertop::parse_config(include_str!("../../../configs/routertop.toml")).unwrap();
    value.wan.mode = routertop::WanProtocol::Pppoe;
    value.wan.pppoe = Some(routertop::Pppoe {
        username: "test-isp-account".into(),
        password: "test-only-export-credential".into(),
        mtu: 1492,
    });
    fs::write(&private, toml::to_string(&value).unwrap()).unwrap();
    let result = cli(&["export", private.to_str().unwrap()]);
    let local_root = !cfg!(target_os = "linux")
        || Command::new("id")
            .arg("-u")
            .output()
            .is_ok_and(|output| output.status.success() && output.stdout == b"0\n");
    assert_eq!(result.status.success(), local_root);
    if !local_root {
        assert!(
            result.stdout.is_empty(),
            "denied export must not disclose credentials"
        );
    }
    fs::remove_dir_all(root).unwrap();
    assert!(!cli(&["apply", config]).status.success());
    assert!(!cli(&["check", config, "unexpected"]).status.success());
    assert!(!cli(&["check", "missing-config-file.toml"]).status.success());
}

#[test]
fn invalid_config_does_not_create_render_output() {
    let root = std::env::temp_dir().join(format!("routertop-cli-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let config = root.join("invalid.toml");
    let output = root.join("rendered");
    fs::write(&config, "hostname = 'invalid'\n").unwrap();
    let result = cli(&[
        "render",
        config.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(!result.status.success());
    assert!(!output.exists());
    fs::remove_dir_all(root).unwrap();
}
