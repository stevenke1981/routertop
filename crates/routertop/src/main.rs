use routertop::{parse_config, render};
use std::{
    env, fs,
    io::Write,
    path::Path,
    process::{self, Command},
};

fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|e| format!("{program}: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{program} failed: {status}"))
    }
}

fn require_local_root() -> Result<(), String> {
    if cfg!(target_os = "linux") {
        let uid = Command::new("id")
            .arg("-u")
            .output()
            .map_err(|e| e.to_string())?;
        if !uid.status.success() || uid.stdout != b"0\n" {
            return Err("this local administration command requires root".into());
        }
    }
    Ok(())
}

fn write_rendered(config: &routertop::Config, directory: &Path) -> Result<(), String> {
    let rendered = render(config)?;
    fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    for (name, text) in [
        ("interfaces", rendered.interfaces),
        ("nftables.nft", rendered.nftables),
        ("dnsmasq.conf", rendered.dnsmasq),
        ("sysctl.conf", rendered.sysctl),
        ("network-setup.sh", rendered.network_setup),
        ("dhcpcd.conf", rendered.dhcpcd),
    ] {
        fs::write(directory.join(name), text).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn check_live_wan(config: &routertop::Config) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("network-check requires Linux".into());
    }
    if config.wan_backup.is_some() {
        return Ok(());
    }
    let output = Command::new("ip")
        .args(["-j", "-4", "address", "show", "dev", config.wan.device()])
        .output()
        .map_err(|error| format!("WAN address query: {error}"))?;
    if !output.status.success() {
        if config.wan.mode == routertop::WanProtocol::Pppoe {
            return Ok(());
        }
        return Err("cannot inspect WAN addresses".into());
    }
    let devices: Vec<serde_json::Value> =
        serde_json::from_slice(&output.stdout).map_err(|error| error.to_string())?;
    let mut addresses = Vec::new();
    for device in devices {
        let entries = device["addr_info"]
            .as_array()
            .ok_or("missing WAN address list")?;
        for entry in entries {
            if entry["family"] == "inet" {
                let address = entry["local"].as_str().ok_or("missing WAN IPv4 address")?;
                let prefix = entry["prefixlen"].as_u64().ok_or("missing WAN prefix")?;
                addresses.push(format!("{address}/{prefix}"));
            }
        }
    }
    routertop::network::validate_wan_subnets(config, &addresses)
}

/// Replace the active configuration without exposing its PPP credentials,
/// including when the previous file came from a legacy 0644 image.
fn write_active_config(path: &Path, source: &str, owner: Option<(u32, u32)>) -> Result<(), String> {
    let temporary = path.with_extension(format!("private-{}", process::id()));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|_| "cannot create private active configuration")?;
        #[cfg(unix)]
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::chown(&temporary, Some(uid), Some(gid))
                .map_err(|_| "cannot set private configuration owner")?;
        }
        #[cfg(not(unix))]
        let _ = owner;
        file.write_all(source.as_bytes())
            .map_err(|_| "cannot write active configuration")?;
        file.sync_all()
            .map_err(|_| "cannot sync active configuration")?;
        drop(file);
        fs::rename(&temporary, path).map_err(|_| "cannot commit active configuration")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn apply(config: &routertop::Config, source: &str) -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("apply requires a Linux RouterTop appliance".into());
    }
    if !Path::new("/etc/routertop-release").is_file() {
        return Err("missing /etc/routertop-release appliance marker".into());
    }
    let uid = Command::new("id")
        .arg("-u")
        .output()
        .map_err(|e| e.to_string())?;
    if !uid.status.success() || uid.stdout != b"0\n" {
        return Err("apply requires root".into());
    }
    if Path::new("/run/routertop/applied").exists() {
        return Err(
            "already provisioned; save configuration and reboot to activate network changes".into(),
        );
    }
    let stage = Path::new("/run/routertop/staged");
    write_rendered(config, stage)?;
    let auto = config
        .ipv6
        .as_ref()
        .is_some_and(|v| v.wan_mode == routertop::WanMode::Auto);
    if auto {
        if !Path::new("/run/routertop/persistent").is_file() {
            return Err("dynamic IPv6 requires persistent storage".into());
        }
        routertop::pd::initialize(
            config,
            Path::new("/run/routertop/pd"),
            Path::new("/data/routertop-dhcpcd/duid"),
        )?;
        fs::copy(stage.join("dhcpcd.conf"), "/run/routertop/dhcpcd.conf")
            .map_err(|e| e.to_string())?;
    }
    if !config.wireguard.is_empty() {
        if routertop::web::stored_config(Path::new("/data/routertop"))?
            != toml::to_string(config).map_err(|e| e.to_string())?
        {
            return Err("WireGuard boot configuration must match the persistent bundle".into());
        }
        routertop::web::write_wireguard_configs(
            Path::new("/data/routertop"),
            Path::new("/run/routertop/wireguard"),
        )?;
    }
    run("nft", &["-c", "-f", "/run/routertop/staged/nftables.nft"])?;
    run(
        "dnsmasq",
        &["--test", "--conf-file=/run/routertop/staged/dnsmasq.conf"],
    )?;
    // Firewall installation precedes any network or forwarding changes.
    run("nft", &["-f", "/run/routertop/staged/nftables.nft"])?;
    let result = (|| {
        fs::create_dir_all("/etc/network").map_err(|e| e.to_string())?;
        for (name, destination) in [
            ("interfaces", "/etc/network/interfaces"),
            ("nftables.nft", "/etc/nftables.nft"),
            ("dnsmasq.conf", "/etc/dnsmasq.conf"),
            ("sysctl.conf", "/etc/sysctl.conf"),
        ] {
            fs::copy(stage.join(name), destination).map_err(|e| e.to_string())?;
        }
        run("hostname", &[&config.hostname])?;
        run("ifup", &["-a"])?;
        check_live_wan(config)?;
        run("sh", &["/run/routertop/staged/network-setup.sh"])?;
        run("sysctl", &["-p", "/etc/sysctl.conf"])?;
        run("dnsmasq", &["--conf-file=/etc/dnsmasq.conf"])?;
        fs::create_dir_all("/etc/routertop").map_err(|e| e.to_string())?;
        write_active_config(
            Path::new("/etc/routertop/routertop.toml"),
            source,
            Some((1000, 1000)),
        )?;
        if auto {
            run("/usr/sbin/routertop-ipv6-start", &[])?;
        }
        run("/usr/sbin/routertop-wan-start", &[])?;
        fs::write("/run/routertop/applied", "boot provisioned\n").map_err(|e| e.to_string())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = run("sysctl", &["-w", "net.ipv4.ip_forward=0"]);
        let _ = run("sysctl", &["-w", "net.ipv6.conf.all.forwarding=0"]);
    }
    result
}

fn execute(args: &[String]) -> Result<(), String> {
    match args {
        [cmd, file, dir] if cmd == "wan-run" || cmd == "wan-step" => {
            require_local_root()?;
            let config =
                parse_config(&fs::read_to_string(file).map_err(|_| "cannot read configuration")?)?;
            if cmd == "wan-run" {
                routertop::wan::supervise(&config, Path::new(file), Path::new(dir))
            } else {
                routertop::wan::step(&config, Path::new(file), Path::new(dir))
            }
        }
        [cmd, file, dir, interface, event] if cmd == "wan-dhcp-event" => {
            require_local_root()?;
            let config =
                parse_config(&fs::read_to_string(file).map_err(|_| "cannot read configuration")?)?;
            routertop::wan::dhcp_event(
                &config,
                Path::new(dir),
                interface,
                event,
                &env::vars().collect(),
            )
        }
        [cmd, file, dir] if cmd == "pppoe-init" || cmd == "pppoe-run" => {
            require_local_root()?;
            let config =
                parse_config(&fs::read_to_string(file).map_err(|_| "cannot read configuration")?)?;
            if cmd == "pppoe-init" {
                routertop::pppoe::initialize(&config, Path::new(file), Path::new(dir))
            } else {
                routertop::pppoe::supervise(&config, Path::new(dir))
            }
        }
        [cmd, file, dir, event, interface] if cmd == "pppoe-event" => {
            require_local_root()?;
            let config =
                parse_config(&fs::read_to_string(file).map_err(|_| "cannot read configuration")?)?;
            routertop::pppoe::event(&config, Path::new(file), Path::new(dir), event, interface)
        }
        [cmd, file] if cmd == "wan-count" => {
            let config =
                parse_config(&fs::read_to_string(file).map_err(|_| "cannot read configuration")?)?;
            println!("{}", routertop::wan::uplinks(&config).len());
            Ok(())
        }
        [cmd, file] if cmd == "wan-mode" => {
            let config =
                parse_config(&fs::read_to_string(file).map_err(|_| "cannot read configuration")?)?;
            println!(
                "{}",
                if config.wan.mode == routertop::WanProtocol::Pppoe {
                    "pppoe"
                } else if config.wan.mode == routertop::WanProtocol::Static {
                    "static"
                } else {
                    "dhcp"
                }
            );
            Ok(())
        }
        [cmd, file, dir, identity] if cmd == "ipv6-init" => {
            require_local_root()?;
            let config = parse_config(&fs::read_to_string(file).map_err(|e| e.to_string())?)?;
            routertop::pd::initialize(&config, Path::new(dir), Path::new(identity))?;
            if routertop::provider::enabled(&config) {
                routertop::provider::initialize(&config, Path::new(dir), Path::new(identity))?;
            }
            Ok(())
        }
        [cmd, file, dir, slot] | [cmd, file, dir, slot, _] if cmd == "ipv6-select" => {
            require_local_root()?;
            let config = parse_config(&fs::read_to_string(file).map_err(|e| e.to_string())?)?;
            let selected = match slot.as_str() {
                "0" | "primary" => Some(0),
                "1" | "backup" => Some(1),
                "none" => None,
                _ => return Err("invalid IPv6 provider slot".into()),
            };
            routertop::provider::select(
                &config,
                Path::new(file),
                Path::new(dir),
                selected,
                args.get(4).map(String::as_str).unwrap_or(""),
            )
        }
        [cmd, file, dir] if cmd == "ipv6-reconcile" => {
            require_local_root()?;
            let config = parse_config(&fs::read_to_string(file).map_err(|e| e.to_string())?)?;
            routertop::pd::reconcile_once(&config, Path::new(dir))
        }
        [cmd, file, dir] if cmd == "ipv6-monitor" || cmd == "ipv6-event" => {
            require_local_root()?;
            let config = parse_config(&fs::read_to_string(file).map_err(|e| e.to_string())?)?;
            if cmd == "ipv6-event" {
                routertop::pd::event(&config, Path::new(dir), &env::vars().collect())
            } else {
                routertop::pd::monitor(&config, Path::new(dir))
            }
        }
        [cmd, data, runtime] if cmd == "console" => {
            routertop::console::run(Path::new(data), Path::new(runtime))
        }
        [cmd, file] if cmd == "network-check" => {
            let config = parse_config(&fs::read_to_string(file).map_err(|e| e.to_string())?)?;
            check_live_wan(&config)
        }
        [cmd, data, output] if cmd == "wg-configs" => {
            require_local_root()?;
            routertop::web::write_wireguard_configs(Path::new(data), Path::new(output))?;
            Ok(())
        }
        [cmd] if cmd == "cgi" => routertop::web::run_cgi(),
        [cmd, data, config] if cmd == "storage-init" => {
            require_local_root()?;
            let source = fs::read_to_string(config).map_err(|e| e.to_string())?;
            routertop::web::initialize_store(Path::new(data), &source)
        }
        [cmd, data] if cmd == "stored-config" => {
            require_local_root()?;
            print!("{}", routertop::web::stored_config(Path::new(data))?);
            Ok(())
        }
        [cmd] if cmd == "bootstrap-token" => {
            require_local_root()?;
            println!(
                "{}",
                routertop::web::bootstrap_token(Path::new("/data/routertop"))?
            );
            Ok(())
        }
        [cmd, data] if cmd == "bootstrap-token" => {
            require_local_root()?;
            println!("{}", routertop::web::bootstrap_token(Path::new(data))?);
            Ok(())
        }
        [cmd, file] if cmd == "web-info" => {
            let config = parse_config(&fs::read_to_string(file).map_err(|e| e.to_string())?)?;
            println!(
                "{} {}",
                config.lan.address.split('/').next().unwrap(),
                config.firewall.https_port.unwrap_or(0)
            );
            Ok(())
        }
        [] => Err("use routertop --help".into()),
        [cmd] if cmd == "--help" || cmd == "help" => {
            println!("RouterTop {}\ncheck CONFIG\nrender CONFIG --output DIRECTORY\nexport CONFIG\napply CONFIG --boot\nstatus\nstorage-init DATA CONFIG\nstored-config DATA\nwg-configs DATA OUTPUT\nnetwork-check CONFIG\nconsole DATA RUNTIME\nbootstrap-token [DATA]\n\nWeb management stores validated configuration on the data volume; reboot to activate changes.", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [cmd] if cmd == "--version" => {
            println!("routertop {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [cmd] if cmd == "status" => {
            if !cfg!(target_os = "linux") {
                return Err("status requires Linux".into());
            }
            run("ip", &["-brief", "address"])?;
            run("ip", &["route", "show"])?;
            run("nft", &["list", "table", "inet", "routertop"])
        }
        [cmd, file] if cmd == "check" || cmd == "export" || cmd == "hostname" => {
            let text = fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
            let config = parse_config(&text)?;
            if cmd == "check" {
                println!("configuration valid");
            } else if cmd == "hostname" {
                println!("{}", config.hostname);
            } else {
                if routertop::wan::uplinks(&config)
                    .iter()
                    .any(|w| w.mode == routertop::WanProtocol::Pppoe)
                {
                    require_local_root()?;
                }
                print!(
                    "{}",
                    toml::to_string_pretty(&config).map_err(|e| e.to_string())?
                );
            }
            Ok(())
        }
        [cmd, file, flag, directory] if cmd == "render" && flag == "--output" => {
            let text = fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
            let config = parse_config(&text)?;
            write_rendered(&config, Path::new(directory))?;
            println!("rendered configuration to {directory}");
            Ok(())
        }
        [cmd, file, flag] if cmd == "apply" && flag == "--boot" => {
            let text = fs::read_to_string(file).map_err(|e| format!("{file}: {e}"))?;
            apply(&parse_config(&text)?, &text)
        }
        _ => Err("invalid arguments; use routertop --help".into()),
    }
}

fn main() {
    let result = if env::args()
        .next()
        .is_some_and(|s| s.ends_with("routertop.cgi"))
    {
        routertop::web::run_cgi()
    } else {
        execute(&env::args().skip(1).collect::<Vec<_>>())
    };
    if let Err(error) = result {
        eprintln!("routertop: {error}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn active_credentials_are_private_on_create_and_replace() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = env::temp_dir().join(format!("routertop-active-{}-{nonce}", process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("routertop.toml");
        for source in ["first-private-value", "replacement-private-value"] {
            if path.exists() {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                }
            }
            write_active_config(&path, source, None).unwrap();
            assert_eq!(fs::read_to_string(&path).unwrap(), source);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
