//! Single-session PPPoE WAN. Credentials are written only to private runtime files.
use crate::{Config, WanProtocol};
use fs2::FileExt;
use serde_json::{json, Value};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

pub(crate) fn validate(config: &Config) -> Result<(), String> {
    if config.wan.mode != WanProtocol::Pppoe {
        if config.wan.pppoe.is_some() {
            return Err("non-PPPoE WAN cannot contain PPPoE credentials".into());
        }
        return Ok(());
    }
    let ppp = config
        .wan
        .pppoe
        .as_ref()
        .ok_or("PPPoE settings are required")?;
    for value in [&ppp.username, &ppp.password] {
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|b| (0x20..=0x7e).contains(&b))
        {
            return Err("PPPoE username and password require 1-128 printable ASCII bytes".into());
        }
    }
    if !(1280..=1492).contains(&ppp.mtu) {
        return Err("PPPoE MTU must be 1280 through 1492".into());
    }
    if config.wan.interface == "ppp0" || config.lan.interface == "ppp0" {
        return Err("ppp0 is reserved for the PPPoE WAN".into());
    }
    if config
        .ipv6
        .as_ref()
        .is_some_and(|v| v.wan_mode != crate::WanMode::Auto)
    {
        return Err("IPv6 on PPPoE requires automatic WAN mode".into());
    }
    Ok(())
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}

/// This is a private credential-bearing options file, never part of render().
pub fn peer_options(config: &Config, runtime: &Path) -> Result<String, String> {
    validate(config)?;
    let ppp = config.wan.pppoe.as_ref().ok_or("PPPoE is not configured")?;
    let runtime = runtime.to_str().ok_or("runtime path must be UTF-8")?;
    if !runtime.starts_with('/') || runtime.bytes().any(|b| b.is_ascii_control()) {
        return Err("invalid PPPoE runtime path".into());
    }
    let mut options = format!("# RouterTop private PPPoE options\npty {}\nunit 0\nifname ppp0\nnodetach\npersist\nmaxfail 0\nholdoff 5\nnoauth\nhide-password\nnoipdefault\ndefaultroute\nreplacedefaultroute\nipcp-accept-local\nipcp-accept-remote\nmtu {}\nmru {}\nlcp-echo-interval 3\nlcp-echo-failure 3\nuser {}\npassword {}\nipparam {}\nip-up-script /usr/sbin/routertop-ppp-ip-up\nip-down-script /usr/sbin/routertop-ppp-ip-down\n",quote(&format!("/usr/sbin/pppoe -I {} -T 15", config.wan.interface)), ppp.mtu, ppp.mtu, quote(&ppp.username), quote(&ppp.password), quote(runtime));
    if config.ipv6.is_some() {
        options.push_str("+ipv6\nipv6cp-accept-local\ndefaultroute6\nipv6-up-script /usr/sbin/routertop-ppp-ipv6-up\nipv6-down-script /usr/sbin/routertop-ppp-ipv6-down\n");
    } else {
        options.push_str("noipv6\n");
    }
    Ok(options)
}

pub(crate) fn private_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|_| "cannot create PPPoE runtime")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| "cannot protect PPPoE runtime")?;
    }
    Ok(())
}
pub(crate) fn write(path: &Path, bytes: &[u8], _public: bool) -> Result<(), String> {
    let temporary = path.with_extension("new");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if _public { 0o644 } else { 0o600 });
    }
    let mut file = options
        .open(&temporary)
        .map_err(|_| "cannot write PPPoE runtime")?;
    // PPP hooks inherit pppd's restrictive umask. The separate public status
    // must remain readable by the CGI user; secret files stay explicitly 0600.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(if _public {
            0o644
        } else {
            0o600
        }))
        .map_err(|_| "cannot protect PPPoE runtime")?;
    }
    file.write_all(bytes)
        .map_err(|_| "cannot write PPPoE runtime")?;
    file.sync_all().map_err(|_| "cannot sync PPPoE runtime")?;
    fs::rename(temporary, path).map_err(|_| "cannot commit PPPoE runtime".into())
}
fn status(
    config: &Config,
    dir: &Path,
    state: &str,
    address: Option<String>,
    ipv6_ready: bool,
) -> Result<(), String> {
    let value = json!({"mode":"pppoe","interface":config.wan.interface,"logical_interface":"ppp0","state":state,"ipv4_address":address,"ipv6_ready":ipv6_ready});
    write(
        &dir.parent()
            .ok_or("runtime parent missing")?
            .join("wan-status.json"),
        value.to_string().as_bytes(),
        true,
    )
}
pub fn initialize(config: &Config, source: &Path, dir: &Path) -> Result<(), String> {
    crate::validate(config)?;
    if config.wan.mode != WanProtocol::Pppoe {
        return Err("PPPoE is not configured".into());
    }
    private_dir(dir)?;
    write(
        &dir.join("peer"),
        peer_options(config, dir)?.as_bytes(),
        false,
    )?;
    let path = source.to_str().ok_or("configuration path must be UTF-8")?;
    if !path.starts_with('/') || path.bytes().any(|b| b.is_ascii_control()) {
        return Err("invalid configuration path".into());
    }
    write(&dir.join("config-path"), path.as_bytes(), false)?;
    status(config, dir, "dialing", None, false)
}
fn run(program: &str, args: &[&str]) -> Result<(), String> {
    let result = Command::new("timeout")
        .arg("8")
        .arg(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "PPP lifecycle command unavailable")?;
    if result.success() {
        Ok(())
    } else {
        Err("PPP lifecycle command failed".into())
    }
}
fn address() -> Option<String> {
    let result = Command::new("ip")
        .args(["-j", "-4", "address", "show", "dev", "ppp0"])
        .output()
        .ok()?;
    let devices: Vec<Value> = serde_json::from_slice(&result.stdout).ok()?;
    devices
        .iter()
        .flat_map(|d| d["addr_info"].as_array().into_iter().flatten())
        .find_map(|a| a["local"].as_str().map(str::to_owned))
}
fn lifecycle_lock(dir: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join("lifecycle.lock"))
        .map_err(|_| "cannot lock PPP lifecycle")?;
    file.lock_exclusive()
        .map_err(|_| "cannot lock PPP lifecycle")?;
    Ok(file)
}
pub fn event(
    config: &Config,
    source: &Path,
    dir: &Path,
    action: &str,
    interface: &str,
) -> Result<(), String> {
    if config.wan_backup.is_some() {
        return crate::wan::ppp_event(config, source, dir, action, interface);
    }
    if config.wan.mode != WanProtocol::Pppoe || interface != "ppp0" {
        return Ok(());
    }
    let _guard = lifecycle_lock(dir)?;
    let pd = dir.parent().ok_or("runtime parent missing")?.join("pd");
    match action {
        "ipv4-up" => {
            if let Some(ip) = address() {
                if crate::network::validate_wan_subnets(config, &[format!("{ip}/32")]).is_err() {
                    let _ = run(
                        "sysctl",
                        &[
                            "-w",
                            "net.ipv4.ip_forward=0",
                            "net.ipv6.conf.all.forwarding=0",
                        ],
                    );
                    let _ = run("ip", &["link", "set", "dev", "ppp0", "down"]);
                    return Err("PPP WAN overlaps configured networks; forwarding disabled".into());
                }
            }
            let ipv6 = read_status(config)["ipv6_ready"].as_bool().unwrap_or(false);
            status(config, dir, "connected", address(), ipv6)
        }
        "ipv4-down" => status(config, dir, "reconnecting", None, false),
        "ipv6-up" if config.ipv6.is_some() => {
            // PPP IPv6CP establishes the link-local peer/default. DHCPv6 must
            // start immediately: a PPP ISP need not send an Ethernet-style RA.
            crate::wan::start_v6(source, &pd, false)?;
            status(config, dir, "connected", address(), true)
        }
        "ipv6-down" => {
            let stopped = crate::wan::stop_v6(&pd);
            if config.ipv6.is_some() {
                crate::pd::disconnect(config, &pd)?;
            }
            stopped?;
            status(config, dir, "reconnecting", address(), false)
        }
        _ => Err("unknown PPP lifecycle event".into()),
    }
}
pub fn supervise(config: &Config, dir: &Path) -> Result<(), String> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join("supervisor.lock"))
        .map_err(|_| "cannot lock PPP supervisor")?;
    file.try_lock_exclusive()
        .map_err(|_| "PPP supervisor already running")?;
    loop {
        let _ = Command::new("pppd")
            .arg("file")
            .arg(dir.join("peer"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        status(config, dir, "reconnecting", None, false)?;
        thread::sleep(Duration::from_secs(5));
    }
}
pub fn read_status(config: &Config) -> Value {
    if config.wan.mode != WanProtocol::Pppoe {
        return json!({"mode":"dhcp","interface":config.wan.interface,"logical_interface":config.wan.device(),"state":"disabled","ipv4_address":null,"ipv6_ready":false});
    }
    let value = fs::read("/run/routertop/wan-status.json")
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    if let Some(v) = value.filter(|v| {
        matches!(
            v["state"].as_str(),
            Some("dialing" | "connected" | "reconnecting")
        )
    }) {
        return json!({"mode":"pppoe","interface":config.wan.interface,"logical_interface":"ppp0","state":v["state"],"ipv4_address":v["ipv4_address"],"ipv6_ready":v["ipv6_ready"] == true});
    }
    json!({"mode":"pppoe","interface":config.wan.interface,"logical_interface":"ppp0","state":"dialing","ipv4_address":null,"ipv6_ready":false})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_public_status_and_private_credentials_have_explicit_modes() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("routertop-ppp-mode-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        for (name, public, mode) in [("status.json", true, 0o644), ("peer", false, 0o600)] {
            let file = dir.join(name);
            write(&file, b"bounded test value", public).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    fs::metadata(file).unwrap().permissions().mode() & 0o777,
                    mode
                );
            }
            #[cfg(not(unix))]
            let _ = mode;
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
