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
