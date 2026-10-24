//! Small active/standby IPv4 WAN manager. Every health probe has an isolated
//! device-bound routing table; acquisition clients never own the main default.
use crate::{cidr, interface, ipv4, unicast, Config, Wan, WanProtocol};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    net::Ipv4Addr,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StaticIpv4 {
    pub address: String,
    pub gateway: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Failover {
    pub primary_target: String,
    pub backup_target: String,
    #[serde(default = "interval")]
    pub interval_seconds: u16,
    #[serde(default = "threshold")]
    pub failure_threshold: u8,
    #[serde(default = "threshold")]
    pub recovery_threshold: u8,
}
fn interval() -> u16 {
    5
}
fn threshold() -> u8 {
    3
}
pub fn device(wan: &Wan, slot: usize) -> &str {
    if wan.mode == WanProtocol::Pppoe {
        if slot == 0 {
            "ppp0"
        } else {
            "ppp1"
        }
    } else {
        &wan.interface
    }
}
pub fn uplinks(config: &Config) -> Vec<&Wan> {
    std::iter::once(&config.wan)
        .chain(config.wan_backup.iter())
        .collect()
}
fn label(slot: usize) -> &'static str {
    if slot == 0 {
        "primary"
    } else {
        "backup"
    }
}
fn overlap(a: crate::Cidr, b: crate::Cidr) -> bool {
    a.network() <= b.broadcast() && b.network() <= a.broadcast()
}
pub(crate) fn validate(config: &Config) -> Result<(), String> {
    if config.wan_backup.is_some() != config.failover.is_some() {
        return Err("backup WAN and failover settings must be configured together".into());
    }
    if config.wan_backup.is_some()
        && config
            .ipv6
            .as_ref()
            .is_some_and(|v| v.wan_mode == crate::WanMode::Static)
    {
        return Err(
            "dual WAN requires automatic primary IPv6; static IPv6 is supported with one WAN"
                .into(),
        );
    }
    let mut names = vec![config.lan.interface.as_str()];
    names.extend(config.vlans.iter().map(|v| v.interface.as_str()));
    names.extend(config.wireguard.iter().map(|v| v.interface.as_str()));
    if (config.wan.mode == WanProtocol::Pppoe && names.contains(&"ppp0"))
        || (config
            .wan_backup
            .as_ref()
            .is_some_and(|w| w.mode == WanProtocol::Pppoe)
            && names.contains(&"ppp1"))
    {
        return Err("logical PPP interfaces are reserved from local interfaces".into());
    }
    for (slot, wan) in uplinks(config).iter().enumerate() {
        interface(&wan.interface)?;
        if matches!(wan.interface.as_str(), "ppp0" | "ppp1")
            || names.contains(&wan.interface.as_str())
        {
            return Err(
                "WAN interfaces must be distinct from LAN/VLAN/WireGuard and reserved PPP names"
                    .into(),
            );
        }
        names.push(&wan.interface);
        if slot == 1 {
            let mut single = config.clone();
            single.wan = (*wan).clone();
            single.ipv6 = None;
            crate::pppoe::validate(&single)?;
        }
        match (&wan.static_ipv4, wan.mode) {
            (Some(value), WanProtocol::Static) => {
                let net = cidr(&value.address, "static WAN address")?;
                let gateway = ipv4(&value.gateway, "static WAN gateway")?;
                if !(1..=30).contains(&net.prefix)
                    || !unicast(net.ip)
                    || !net.contains_host(net.ip)
                    || !unicast(gateway)
                    || !net.contains_host(gateway)
                    || gateway == net.ip
                    || value.address != format!("{}/{}", Ipv4Addr::from(net.ip), net.prefix)
                    || value.gateway != Ipv4Addr::from(gateway).to_string()
                {
                    return Err("static WAN requires a canonical usable IPv4 host /1..30 and distinct on-link gateway".into());
                }
                let mut local = vec![cidr(&config.lan.address, "LAN")?];
                for v in &config.vlans {
                    local.push(cidr(&v.address, "VLAN")?);
                }
                for v in &config.wireguard {
                    local.push(cidr(&v.address, "WireGuard")?);
                    for p in &v.peers {
                        for a in &p.allowed_ips {
                            if !a.contains(':') && a != "0.0.0.0/0" {
                                local.push(cidr(a, "WireGuard peer")?);
                            }
                        }
                    }
                }
                for r in &config.routes {
                    local.push(cidr(&r.destination, "route")?);
                }
                if local.iter().any(|other| overlap(net, *other)) {
                    return Err("static WAN overlaps a configured local network or route".into());
                }
            }
            (None, WanProtocol::Static) => {
                return Err("static WAN requires static_ipv4 settings".into())
            }
            (Some(_), _) => return Err("static_ipv4 settings require static WAN mode".into()),
            _ => {}
        }
    }
    if let Some(f) = &config.failover {
        for target in [&f.primary_target, &f.backup_target] {
            let ip = ipv4(target, "health target")?;
            if !unicast(ip) || *target != Ipv4Addr::from(ip).to_string() {
                return Err(
                    "WAN health targets require canonical literal unicast IPv4 addresses".into(),
                );
            }
            let local = std::iter::once(config.lan.address.as_str())
                .chain(config.vlans.iter().map(|v| v.address.as_str()))
                .chain(config.wireguard.iter().map(|w| w.address.as_str()));
            for address in local {
                let net = cidr(address, "local network")?;
                if ip >= net.network() && ip <= net.broadcast() {
                    return Err(
                        "WAN health target cannot be a local LAN/VLAN/WireGuard address".into(),
                    );
                }
            }
            for wan in uplinks(config) {
                if wan
                    .static_ipv4
                    .as_ref()
                    .is_some_and(|v| cidr(&v.address, "WAN address").is_ok_and(|n| ip == n.ip))
                {
                    return Err("WAN health target cannot be the router WAN address".into());
                }
            }
        }
        if !(2..=60).contains(&f.interval_seconds)
            || !(1..=10).contains(&f.failure_threshold)
            || !(1..=10).contains(&f.recovery_threshold)
        {
            return Err("failover interval requires 2..60 seconds and thresholds 1..10".into());
        }
    }
    Ok(())
}
fn cmd(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}
fn ip(args: &[&str]) -> Result<(), String> {
    if cmd("ip", args) {
        Ok(())
    } else {
        Err("WAN routing command failed".into())
    }
}
fn read(path: &Path) -> Value {
    fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(Value::Null)
}
fn save(path: &Path, value: &Value, public: bool) -> Result<(), String> {
    crate::pppoe::write(path, value.to_string().as_bytes(), public)
}
fn inspect(dev: &str) -> Vec<Value> {
    Command::new("ip")
        .args(["-j", "-4", "address", "show", "dev", dev])
        .output()
        .ok()
        .and_then(|o| serde_json::from_slice::<Vec<Value>>(&o.stdout).ok())
        .unwrap_or_default()
}
fn address(dev: &str) -> Option<String> {
    inspect(dev)
        .iter()
        .flat_map(|d| d["addr_info"].as_array().into_iter().flatten())
        .find_map(|a| a["local"].as_str().map(str::to_string))
}
fn carrier(dev: &str) -> bool {
    inspect(dev).iter().any(|d| {
        d["flags"]
            .as_array()
            .is_some_and(|f| f.iter().any(|v| v == "LOWER_UP"))
    })
}
fn lease_path(dir: &Path, slot: usize) -> std::path::PathBuf {
    dir.join(format!("lease-{slot}.json"))
}
fn routing(config: &Config, dir: &Path, slot: usize) -> Result<bool, String> {
    let links = uplinks(config);
    let wan = links[slot];
    let dev = device(wan, slot);
    let table = (201 + slot).to_string();
    // oif rules match locally bound probes, not forwarded client traffic.
    let priority = (80 + slot).to_string();
    let _ = cmd(
        "ip",
        &[
            "-4", "rule", "del", "priority", &priority, "oif", dev, "table", &table,
        ],
    );
    ip(&[
        "-4", "rule", "add", "priority", &priority, "oif", dev, "table", &table,
    ])?;
    let _ = cmd("ip", &["-4", "route", "flush", "table", &table]);
    // A terminal route prevents policy lookup falling through to the other WAN.
    ip(&[
        "-4",
        "route",
        "add",
        "unreachable",
        "default",
        "table",
        &table,
        "metric",
        "32767",
    ])?;
    let lease = if let Some(s) = &wan.static_ipv4 {
        json!({"address":s.address,"gateway":s.gateway})
    } else {
        read(&lease_path(dir, slot))
    };
    if !carrier(dev) || address(dev).is_none() {
        return Ok(false);
    }
    let Some(addr) = lease["address"].as_str() else {
        return Ok(false);
    };
    if crate::network::validate_wan_subnets(config, &[addr.to_string()]).is_err() {
        return Ok(false);
    }
    let subnet = cidr(addr, "WAN runtime address")?;
    ip(&[
        "-4",
        "route",
        "replace",
        &subnet.network_text(),
        "dev",
        dev,
        "scope",
        "link",
        "table",
        &table,
    ])?;
    if wan.mode == WanProtocol::Pppoe {
        ip(&[
            "-4", "route", "replace", "default", "dev", dev, "table", &table, "metric", "10",
        ])?;
    } else {
        let Some(gateway) = lease["gateway"].as_str() else {
            return Ok(false);
        };
        if ipv4(gateway, "runtime gateway").is_err() {
            return Ok(false);
        };
        ip(&[
            "-4", "route", "replace", "default", "via", gateway, "dev", dev, "onlink", "table",
            &table, "metric", "10",
        ])?;
    }
    Ok(true)
}
#[derive(Clone, Default, Serialize, Deserialize)]
struct Health {
    healthy: bool,
    consecutive_failures: u8,
    consecutive_successes: u8,
}
fn update(h: &mut Health, ok: bool, f: &Failover) {
    if ok {
        h.consecutive_failures = 0;
        h.consecutive_successes = h
            .consecutive_successes
            .saturating_add(1)
            .min(f.recovery_threshold);
        if h.consecutive_successes >= f.recovery_threshold {
            h.healthy = true
        }
    } else {
        h.consecutive_successes = 0;
        h.consecutive_failures = h
            .consecutive_failures
            .saturating_add(1)
            .min(f.failure_threshold);
        if h.consecutive_failures >= f.failure_threshold {
            h.healthy = false
        }
    }
}
fn nft(script: &str) -> Result<(), String> {
    use std::io::Write;
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "WAN firewall unavailable")?;
    child
        .stdin
        .take()
        .ok_or("WAN firewall stdin unavailable")?
        .write_all(script.as_bytes())
        .map_err(|_| "WAN firewall update failed")?;
    if child.wait().is_ok_and(|s| s.success()) {
        Ok(())
    } else {
        Err("WAN firewall update failed".into())
    }
}
pub fn primary_active(dir: &Path) -> bool {
    read(&dir.join("status.json"))["active"] == "primary"
}
pub fn step(config: &Config, source: &Path, dir: &Path) -> Result<(), String> {
    crate::validate(config)?;
    fs::create_dir_all(dir).map_err(|_| "cannot create WAN runtime")?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join("step.lock"))
        .map_err(|_| "cannot open WAN lock")?;
    lock.lock_exclusive().map_err(|_| "cannot lock WAN state")?;
    let result = step_inner(config, source, dir);
    if result.is_err() {
        // A routing/client/firewall failure cannot leave last round's default
        // usable until its nft lease expires. Keep management on the LAN.
        let _ = nft("flush set inet routertop active_wan\nflush set inet routertop primary_v6\n");
        let _ = cmd("ip", &["-4", "route", "del", "default", "metric", "5"]);
        let mut status = read(&dir.join("status.json"));
        if !status.is_object() {
            status = json!({"dual_wan":true,"ipv6_policy":"primary-only"});
        }
        status["active"] = json!("none");
        status["state"] = json!("unavailable");
        status["ipv6_ready"] = json!(false);
        let _ = save(&dir.join("status.json"), &status, true);
        if config
            .ipv6
            .as_ref()
            .is_some_and(|v| v.wan_mode == crate::WanMode::Auto)
        {
            if let Some(parent) = dir.parent() {
                let _ = stop_v6(&parent.join("pd"));
                let _ = crate::pd::disconnect(config, &parent.join("pd"));
            }
        }
    }
    result
}
fn step_inner(config: &Config, source: &Path, dir: &Path) -> Result<(), String> {
    let f = config
        .failover
        .as_ref()
        .ok_or("dual WAN is not configured")?;
    let previous = read(&dir.join("status.json"));
    let old = previous["active"].as_str().unwrap_or("none");
    let mut health: [Health; 2] = [Health::default(), Health::default()];
    let mut reports = Vec::new();
    for slot in 0..2 {
        health[slot] = serde_json::from_value(previous[label(slot)].clone()).unwrap_or_default();
        let ready = routing(config, dir, slot)?;
        let wan = uplinks(config)[slot];
        let target = if slot == 0 {
            &f.primary_target
        } else {
            &f.backup_target
        };
        let owns_target = uplinks(config)
            .iter()
            .enumerate()
            .any(|(index, w)| address(device(w, index)).as_deref() == Some(target.as_str()));
        let ok = ready
            && !owns_target
            && cmd(
                "timeout",
                &[
                    "3",
                    "ping",
                    "-4",
                    "-n",
                    "-c",
                    "1",
                    "-W",
                    "1",
                    "-I",
                    device(wan, slot),
                    target,
                ],
            );
        update(&mut health[slot], ok, f);
        let mut report = serde_json::to_value(&health[slot]).unwrap();
        report["mode"] = json!(wan.mode);
        report["interface"] = json!(wan.interface);
        report["logical_interface"] = json!(device(wan, slot));
        report["ipv4_address"] = json!(address(device(wan, slot)));
        report["state"] = json!(if health[slot].healthy {
            "connected"
        } else if ready {
            "probing"
        } else {
            "unavailable"
        });
        reports.push(report);
    }
    let active = if health[0].healthy {
        "primary"
    } else if health[1].healthy {
        "backup"
    } else {
        "none"
    };
    // Close forwarding before changing a route; refresh a finite lease each round.
    if old != active {
        nft("flush set inet routertop active_wan\nflush set inet routertop primary_v6\n")?;
        let _ = cmd("ip", &["-4", "route", "del", "default", "metric", "5"]);
    }
    let mut authorization =
        "flush set inet routertop active_wan\nflush set inet routertop primary_v6\n".to_string();
    if active != "none" {
        let slot = usize::from(active == "backup");
        let wan = uplinks(config)[slot];
        let dev = device(wan, slot);
        let lease = if let Some(s) = &wan.static_ipv4 {
            json!({"gateway":s.gateway})
        } else {
            read(&lease_path(dir, slot))
        };
        if wan.mode == WanProtocol::Pppoe {
            ip(&[
                "-4", "route", "replace", "default", "dev", dev, "metric", "5",
            ])?;
        } else {
            let gateway = lease["gateway"].as_str().ok_or("WAN gateway missing")?;
            ip(&[
                "-4", "route", "replace", "default", "via", gateway, "dev", dev, "onlink",
                "metric", "5",
            ])?;
        }
        let ttl = (u32::from(f.interval_seconds) * 3 + 10).to_string();
        authorization.push_str(&format!(
            "add element inet routertop active_wan {{ \"{dev}\" timeout {ttl}s }}\n"
        ));
        if slot == 0 {
            authorization.push_str(&format!(
                "add element inet routertop primary_v6 {{ \"{}\" timeout {ttl}s }}\n",
                config.wan.device()
            ));
        }
    }
    nft(&authorization)?;
    let value = json!({"dual_wan":true,"active":active,"ipv6_policy":"primary-only","primary":reports[0],"backup":reports[1],"mode":config.wan.mode,"interface":config.wan.interface,"logical_interface":config.wan.device(),"state":if active=="none"{"unavailable"}else{"connected"},"ipv4_address":if active=="backup"{reports[1]["ipv4_address"].clone()}else{reports[0]["ipv4_address"].clone()},"ipv6_ready":active=="primary"&&config.ipv6.is_some()});
    save(&dir.join("status.json"), &value, true)?;
    if config.ipv6.is_some() {
        let pd = dir.parent().ok_or("WAN parent missing")?.join("pd");
        if active != "primary" {
            let stopped = stop_v6(&pd);
            crate::pd::disconnect(config, &pd)?;
            stopped?;
        } else {
            // This is idempotent and retries a failed launch next round.
            start_v6(source, &pd, true)?;
        }
    }
    Ok(())
}
pub fn dhcp_event(
    config: &Config,
    dir: &Path,
    dev: &str,
    event: &str,
    env: &BTreeMap<String, String>,
) -> Result<(), String> {
    let slot = uplinks(config)
        .iter()
        .enumerate()
        .find(|(_, w)| w.interface == dev && w.mode == WanProtocol::Dhcp)
        .map(|(i, _)| i)
        .ok_or("unknown DHCP WAN")?;
    if matches!(event, "deconfig" | "nak" | "leasefail") {
        let _ = cmd("ip", &["-4", "address", "flush", "dev", dev]);
        return save(&lease_path(dir, slot), &Value::Null, false);
    }
    if !matches!(event, "bound" | "renew") {
        return Ok(());
    }
    let ip_text = env.get("ip").ok_or("DHCP address missing")?;
    let ip_value = ipv4(ip_text, "DHCP address")?;
    let mask = ipv4(
        env.get("subnet").ok_or("DHCP subnet missing")?,
        "DHCP subnet",
    )?;
    let prefix = mask.leading_ones();
    if mask
        != if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        }
    {
        return Err("invalid DHCP subnet mask".into());
    }
    let address = format!("{ip_text}/{prefix}");
    let subnet = cidr(&address, "DHCP lease")?;
    let gateway = env
        .get("router")
        .and_then(|r| r.split_whitespace().next())
        .ok_or("DHCP gateway missing")?;
    let gw = ipv4(gateway, "DHCP gateway")?;
    if !unicast(ip_value)
        || !unicast(gw)
        || !subnet.contains_host(ip_value)
        || !subnet.contains_host(gw)
        || gw == ip_value
    {
        return Err("invalid DHCP WAN lease".into());
    }
    crate::network::validate_wan_subnets(config, std::slice::from_ref(&address))?;
    let previous = read(&lease_path(dir, slot));
    if previous["address"] != address {
        ip(&["-4", "address", "flush", "dev", dev])?;
    }
    ip(&["-4", "address", "replace", &address, "dev", dev])?;
    save(
        &lease_path(dir, slot),
        &json!({"address":address,"gateway":gateway}),
        false,
    )
}
fn client_pid(pidfile: &Path, proc_root: &Path) -> Result<Option<u32>, String> {
    let text = match fs::read_to_string(pidfile) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cannot read DHCPv6 client identity".into()),
    };
    let pid = text
        .trim()
        .parse::<u32>()
        .map_err(|_| "invalid DHCPv6 client identity")?;
    if pid <= 1 || pid == std::process::id() {
        return Err("invalid DHCPv6 client identity".into());
    }
    let process = proc_root.join(pid.to_string());
    let executable = match fs::read_link(process.join("exe")) {
        Ok(v) => v,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("cannot verify DHCPv6 client identity".into()),
    };
    let namespace = fs::read_link(process.join("ns/net"))
        .map_err(|_| "cannot verify DHCPv6 network namespace")?;
    let current = fs::read_link(proc_root.join("self/ns/net"))
        .map_err(|_| "cannot verify router network namespace")?;
    if executable.file_name().is_none_or(|v| v != "dhcpcd") || namespace != current {
        return Err("DHCPv6 client identity does not match this router".into());
    }
    Ok(Some(pid))
}
fn client_lock(pd: &Path) -> Result<std::fs::File, String> {
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(pd.join("client.lock"))
        .map_err(|_| "cannot open DHCPv6 lifecycle lock")?;
    lock.lock_exclusive()
        .map_err(|_| "cannot lock DHCPv6 lifecycle")?;
    Ok(lock)
}
fn stop_existing_client(
    pidfile: &Path,
    proc_root: &Path,
    signal: impl FnOnce(u32) -> bool,
) -> Result<(), String> {
    let Some(pid) = client_pid(pidfile, proc_root)? else {
        return Ok(());
    };
    // Never use `dhcpcd -x` here: with no live master, 10.5.2 starts a new
    // default-config daemon instead of exiting. Signal the verified master.
    if !signal(pid) {
        return Err("cannot stop DHCPv6 client".into());
    }
    for _ in 0..100 {
        if client_pid(pidfile, proc_root)? != Some(pid) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("DHCPv6 client did not stop in time".into())
}
pub(crate) fn stop_v6(pd: &Path) -> Result<(), String> {
    let _lock = client_lock(pd)?;
    stop_existing_client(Path::new("/run/dhcpcd/pid"), Path::new("/proc"), |pid| {
        cmd(
            "timeout",
            &["3", "busybox", "kill", "-TERM", &pid.to_string()],
        )
    })
}
pub(crate) fn start_v6(source: &Path, pd: &Path, primary_only: bool) -> Result<(), String> {
    let _lock = client_lock(pd)?;
    // A PPP hook may have waited behind backup selection/stop. Recheck the
    // active role while holding the same client lifecycle lock.
    if primary_only && !primary_active(&pd.parent().ok_or("PD parent missing")?.join("wan")) {
        return Ok(());
    }
    if client_pid(Path::new("/run/dhcpcd/pid"), Path::new("/proc"))?.is_some() {
        return Ok(());
    }
    let status = Command::new("timeout")
        .args(["8", "dhcpcd", "-6", "-b", "-f"])
        .arg(pd.join("dhcpcd.conf"))
        .env("ROUTERTOP_CONFIG", source)
        .env("ROUTERTOP_PD_RUNTIME", pd)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| "cannot start primary IPv6 client")?;
    if !status.success() {
        return Err("cannot start primary IPv6 client".into());
    }
    for _ in 0..100 {
        if client_pid(Path::new("/run/dhcpcd/pid"), Path::new("/proc"))?.is_some() {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("primary IPv6 client did not become ready".into())
}
pub fn ppp_event(
    config: &Config,
    source: &Path,
    dir: &Path,
    action: &str,
    dev: &str,
) -> Result<(), String> {
    let slot = if dev == "ppp0" {
        0
    } else if dev == "ppp1" {
        1
    } else {
        return Ok(());
    };
    let root = dir.parent().ok_or("PPP runtime parent missing")?;
    if uplinks(config)
        .get(slot)
        .is_none_or(|w| w.mode != WanProtocol::Pppoe)
    {
        return Ok(());
    }
    if action == "ipv4-up" {
        let addr = address(dev).ok_or("PPP address missing")?;
        crate::network::validate_wan_subnets(config, &[format!("{addr}/32")])?;
        save(
            &lease_path(root, slot),
            &json!({"address":format!("{addr}/32")}),
            false,
        )
    } else if action == "ipv4-down" {
        save(&lease_path(root, slot), &Value::Null, false)
    } else if slot == 0 && action == "ipv6-down" && config.ipv6.is_some() {
        let pd = root.parent().ok_or("WAN parent missing")?.join("pd");
        let stopped = stop_v6(&pd);
        crate::pd::disconnect(config, &pd)?;
        stopped
    } else if slot == 0 && action == "ipv6-up" && config.ipv6.is_some() && primary_active(root) {
        start_v6(
            source,
            &root.parent().ok_or("WAN parent missing")?.join("pd"),
            true,
        )
    } else {
        Ok(())
    }
}
fn spawn(program: &str, args: &[&str]) -> Result<Child, String> {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "cannot start WAN client".into())
}
pub fn supervise(config: &Config, source: &Path, dir: &Path) -> Result<(), String> {
    crate::validate(config)?;
    if config.wan_backup.is_none() {
        return Err("dual WAN is not configured".into());
    }
    fs::create_dir_all(dir).map_err(|_| "cannot create WAN runtime")?;
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join("supervisor.lock"))
        .map_err(|_| "cannot open WAN supervisor")?;
    lock.try_lock_exclusive()
        .map_err(|_| "WAN supervisor already running")?;
    let source_text = source.to_str().ok_or("configuration path invalid")?;
    let runtime_text = dir.to_str().ok_or("runtime path invalid")?;
    let hook = dir.join("dhcp-hook");
    let hook_text=format!("#!/bin/sh\nexport PATH=/sbin:/usr/sbin:/bin:/usr/bin\nexec routertop wan-dhcp-event '{}' '{}' \"$interface\" \"$1\"\n",source_text.replace('\'',"'\\''"),runtime_text.replace('\'',"'\\''"));
    crate::pppoe::write(&hook, hook_text.as_bytes(), false)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o700))
            .map_err(|_| "cannot protect DHCP hook")?;
    }
    let mut clients: Vec<(String, Vec<String>, Option<Child>)> = Vec::new();
    for (slot, wan) in uplinks(config).iter().enumerate() {
        ip(&["link", "set", "dev", &wan.interface, "up"])?;
        match wan.mode {
            WanProtocol::Static => {
                let s = wan
                    .static_ipv4
                    .as_ref()
                    .ok_or("static WAN settings missing")?;
                ip(&[
                    "-4",
                    "address",
                    "replace",
                    &s.address,
                    "dev",
                    &wan.interface,
                ])?;
            }
            WanProtocol::Dhcp => {
                clients.push((
                    "udhcpc".into(),
                    vec![
                        "-f".into(),
                        "-i".into(),
                        wan.interface.clone(),
                        "-s".into(),
                        hook.to_string_lossy().into_owned(),
                        "-t".into(),
                        "3".into(),
                        "-T".into(),
                        "2".into(),
                        "-A".into(),
                        "5".into(),
                    ],
                    None,
                ));
            }
            WanProtocol::Pppoe => {
                let peer_dir = dir.join(format!("pppoe-{slot}"));
                crate::pppoe::private_dir(&peer_dir)?;
                let mut selected = config.clone();
                selected.wan = (*wan).clone();
                if slot == 1 {
                    selected.ipv6 = None;
                }
                let mut options = crate::pppoe::peer_options(&selected, &peer_dir)?;
                options =
                    options.replace("defaultroute\nreplacedefaultroute\n", "nodefaultroute\n");
                if slot == 1 {
                    options = options.replace("unit 0\nifname ppp0", "unit 1\nifname ppp1");
                }
                crate::pppoe::write(&peer_dir.join("peer"), options.as_bytes(), false)?;
                crate::pppoe::write(&peer_dir.join("config-path"), source_text.as_bytes(), false)?;
                clients.push((
                    "pppd".into(),
                    vec![
                        "file".into(),
                        peer_dir.join("peer").to_string_lossy().into_owned(),
                    ],
                    None,
                ));
            }
        }
    }
    loop {
        for (program, args, child) in &mut clients {
            let stopped = child
                .as_mut()
                .is_none_or(|p| p.try_wait().ok().flatten().is_some());
            if stopped {
                *child = Some(spawn(
                    program,
                    &args.iter().map(String::as_str).collect::<Vec<_>>(),
                )?);
            }
        }
        if let Err(e) = step(config, source, dir) {
            eprintln!("WAN manager: {e}");
        }
        thread::sleep(Duration::from_secs(u64::from(
            config.failover.as_ref().unwrap().interval_seconds,
        )));
    }
}
pub fn read_status(config: &Config) -> Value {
    if config.wan_backup.is_some() {
        let status = read(Path::new("/run/routertop/wan/status.json"));
        if status["dual_wan"] == true {
            return status;
        }
        return json!({"dual_wan":true,"active":"none","ipv6_policy":"primary-only","primary":{"state":"unavailable"},"backup":{"state":"unavailable"},"state":"unavailable"});
    }
    if config.wan.mode == WanProtocol::Pppoe {
        return crate::pppoe::read_status(config);
    }
    json!({"dual_wan":false,"mode":config.wan.mode,"interface":config.wan.interface,"logical_interface":config.wan.device(),"state":if address(config.wan.device()).is_some(){"connected"}else{"unavailable"},"ipv4_address":address(config.wan.device()),"ipv6_ready":config.ipv6.is_some()})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hysteresis_requires_consecutive_failures_and_successes() {
        let f = Failover {
            primary_target: "203.0.113.9".into(),
            backup_target: "203.0.113.9".into(),
            interval_seconds: 2,
            failure_threshold: 2,
            recovery_threshold: 3,
        };
        let mut h = Health::default();
        update(&mut h, true, &f);
        update(&mut h, true, &f);
        assert!(!h.healthy);
        update(&mut h, false, &f);
        update(&mut h, true, &f);
        assert!(!h.healthy);
        update(&mut h, true, &f);
        update(&mut h, true, &f);
        assert!(h.healthy);
        update(&mut h, false, &f);
        assert!(h.healthy);
        update(&mut h, false, &f);
        assert!(!h.healthy);
        for _ in 0..20 {
            update(&mut h, false, &f)
        }
        assert_eq!(h.consecutive_failures, 2);
    }
    #[test]
    fn stopping_absent_or_stale_ipv6_client_never_runs_a_command() {
        let dir = std::env::temp_dir().join(format!(
            "routertop-ipv6-stop-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let pidfile = dir.join("pid");
        let proc = dir.join("proc");
        stop_existing_client(&pidfile, &proc, |_| {
            panic!("missing client must not launch any command")
        })
        .unwrap();
        fs::write(&pidfile, b"123456789\n").unwrap();
        stop_existing_client(&pidfile, &proc, |_| {
            panic!("stale client must not launch any command")
        })
        .unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}
