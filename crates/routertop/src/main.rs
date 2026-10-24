use routertop::{parse_config, render};
use std::{
    env, fs,
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
    let output = Command::new("ip")
        .args(["-j", "-4", "address", "show", "dev", &config.wan.interface])
        .output()
        .map_err(|error| format!("WAN address query: {error}"))?;
    if !output.status.success() {
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
        fs::write("/etc/routertop/routertop.toml", source).map_err(|e| e.to_string())?;
        if auto {
            run("/usr/sbin/routertop-ipv6-start", &[])?;
        }
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
        [cmd, file, dir, identity] if cmd == "ipv6-init" => {
            require_local_root()?;
            let config = parse_config(&fs::read_to_string(file).map_err(|e| e.to_string())?)?;
            routertop::pd::initialize(&config, Path::new(dir), Path::new(identity))
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
