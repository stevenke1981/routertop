//! One selected IPv6 provider follows the IPv4 WAN manager. Origin epochs are
//! embedded in each private client hook; an old process never reads a new epoch.
use crate::{Config, ProviderPolicy, WanProtocol};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
    thread,
    time::Duration,
};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Epoch {
    pub boot: String,
    pub generation: u64,
    pub slot: Option<usize>,
    pub logical_interface: String,
    pub incarnation: String,
}
impl Epoch {
    pub fn token(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.boot,
            self.generation,
            self.slot.map_or("none".into(), |v| v.to_string()),
            self.logical_interface,
            self.incarnation
        )
    }
    pub fn provider(&self) -> Option<&'static str> {
        self.slot.map(|v| if v == 0 { "primary" } else { "backup" })
    }
}
pub fn enabled(config: &Config) -> bool {
    config
        .ipv6
        .as_ref()
        .is_some_and(|v| v.provider_policy == ProviderPolicy::ActiveStandby)
}
pub fn read(dir: &Path) -> Result<Epoch, String> {
    serde_json::from_slice(
        &fs::read(dir.join("provider.json")).map_err(|_| "IPv6 provider epoch absent")?,
    )
    .map_err(|_| "invalid IPv6 provider epoch".into())
}
pub fn accepts(epoch: &Epoch, env: &BTreeMap<String, String>) -> bool {
    epoch.slot.is_some()
        && env.get("ROUTERTOP_PD_EPOCH") == Some(&epoch.token())
        && env.get("interface") == Some(&epoch.logical_interface)
}
pub(crate) fn selected(config: &Config, epoch: &Epoch) -> Result<Config, String> {
    let mut selected = config.clone();
    selected.wan = (*crate::wan::uplinks(config)
        .get(epoch.slot.ok_or("IPv6 inactive")?)
        .ok_or("invalid provider slot")?)
    .clone();
    Ok(selected)
}
fn boot() -> Result<String, String> {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().to_string())
        .map_err(|_| "cannot read boot identity".into())
}
fn locked(dir: &Path) -> Result<File, String> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(dir.join("selection.lock"))
        .map_err(|e| e.to_string())?;
    for _ in 0..600 {
        if file.try_lock_exclusive().is_ok() {
            return Ok(file);
        }
        thread::sleep(Duration::from_millis(20));
    }
    Err("IPv6 selection lock timeout".into())
}
pub fn initialize(config: &Config, dir: &Path, identity: &Path) -> Result<(), String> {
    crate::pd::identity(identity)?;
    crate::pd::identity(&identity.with_file_name("backup-duid"))?;
    crate::pd::atomic(
        &dir.join("identity-root"),
        identity.to_string_lossy().as_bytes(),
    )?;
    let epoch = Epoch {
        boot: boot()?,
        generation: read(dir).map_or(0, |e| e.generation.saturating_add(1)),
        slot: None,
        logical_interface: String::new(),
        incarnation: String::new(),
    };
    let _lock = crate::pd::lock(dir)?;
    save(dir, &epoch)?;
    inactive(config, dir, &epoch)
}
fn save(dir: &Path, epoch: &Epoch) -> Result<(), String> {
    crate::pd::atomic(
        &dir.join("provider.json"),
        &serde_json::to_vec(epoch).unwrap(),
    )
}
fn inactive(config: &Config, dir: &Path, epoch: &Epoch) -> Result<(), String> {
    crate::pd::atomic(&dir.join("lease.json"), b"{}")?;
    crate::pd::atomic(&dir.join("ra-dns.json"), b"{}")?;
    crate::pd::atomic(&dir.join("resolv.conf"), b"")?;
    crate::pd::update_ra(config, dir, false)?;
    crate::pd::atomic(&dir.join("status.json"),json!({"wan_mode":"auto","state":"waiting","phase":"inactive","provider":null,"generation":epoch.generation,"logical_interface":null,"wan_addresses":[],"delegated":[],"dns_servers":[],"error":null}).to_string().as_bytes())
}
fn ip(args: &[&str]) -> Result<(), String> {
    let status = std::process::Command::new("timeout")
        .args(["4", "ip"])
        .args(args)
        .status()
        .map_err(|e| e.to_string())?;
    if status.success() {
        Ok(())
    } else {
        Err("IPv6 withdrawal failed".into())
    }
}
fn withdraw(config: &Config, dir: &Path, old: &Epoch) -> Result<(), String> {
    let status: serde_json::Value = fs::read(dir.join("status.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let mut addresses: Vec<serde_json::Value> =
        status["delegated"].as_array().cloned().unwrap_or_default();
    addresses.extend(
        fs::read(dir.join("owned-addresses.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Vec<serde_json::Value>>(&b).ok())
            .unwrap_or_default(),
    );
    addresses.sort_by_key(|e| format!("{}:{}", e["interface"], e["address"]));
    addresses.dedup();
    let kernel = std::process::Command::new("timeout")
        .args(["4", "ip", "-j", "-6", "address", "show"])
        .output()
        .map_err(|e| e.to_string())?;
    if !kernel.status.success() {
        return Err("cannot inspect owned IPv6 addresses".into());
    }
    let devices: Vec<serde_json::Value> =
        serde_json::from_slice(&kernel.stdout).map_err(|e| e.to_string())?;
    for entry in &addresses {
        if let (Some(address), Some(dev)) = (entry["address"].as_str(), entry["interface"].as_str())
        {
            if devices
                .iter()
                .filter(|d| d["ifname"] == dev)
                .flat_map(|d| d["addr_info"].as_array().into_iter().flatten())
                .any(|a| {
                    format!("{}/{}", a["local"].as_str().unwrap_or(""), a["prefixlen"]) == address
                })
            {
                ip(&["-6", "address", "del", address, "dev", dev])?;
            }
        }
    }
    crate::pd::atomic(&dir.join("owned-addresses.json"), b"[]")?;
    if old.slot.is_some() {
        ip(&[
            "-6",
            "route",
            "flush",
            "default",
            "dev",
            &old.logical_interface,
        ])?;
        // dhcpcd exclusively owns global IPv6 addresses on these provider links.
        // Link-local addresses remain available for NDP/IPv6CP on standby.
        ip(&[
            "-6",
            "address",
            "flush",
            "dev",
            &old.logical_interface,
            "scope",
            "global",
        ])?;
    }
    let _ = config;
    Ok(())
}
/// Serialize switches separately from PD event/reconcile locks. Invalidation and
/// closed gates precede stopping the old daemon; stop hooks can take the PD lock.
pub fn select(
    config: &Config,
    source: &Path,
    dir: &Path,
    slot: Option<usize>,
    incarnation: &str,
) -> Result<(), String> {
    if !enabled(config) {
        return Err("active-standby IPv6 is not configured".into());
    }
    if slot.is_some_and(|s| s > 1) {
        return Err("invalid provider slot".into());
    }
    if incarnation.len() > 128
        || !incarnation
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err("invalid provider incarnation".into());
    }
    let _selection = locked(dir)?;
    let old = read(dir)?;
    let device = slot
        .map(|s| crate::wan::device(crate::wan::uplinks(config)[s], s).to_string())
        .unwrap_or_default();
    if old.slot == slot
        && old.logical_interface == device
        && old.incarnation == incarnation
        && old.boot == boot()?
    {
        if slot.is_some() {
            crate::wan::start_v6(source, dir, false)?;
        }
        return Ok(());
    }
    let mut next = Epoch {
        boot: boot()?,
        generation: old
            .generation
            .checked_add(1)
            .ok_or("IPv6 generation exhausted")?,
        slot: None,
        logical_interface: String::new(),
        incarnation: String::new(),
    };
    {
        let _pd = crate::pd::lock(dir)?;
        save(dir, &next)?;
        crate::pd::nft(
            &(crate::pd::set_update(config, &[])
                + "flush set inet routertop auto_wan\nflush set inet routertop auto_sources\n"),
        )?;
        // DNS/RA are withdrawn before a potentially slow client stop.
        crate::pd::atomic(&dir.join("resolv.conf"), b"")?;
        crate::pd::update_ra(config, dir, false)?;
    }
    crate::wan::stop_v6(dir)?;
    {
        let _pd = crate::pd::lock(dir)?;
        withdraw(config, dir, &old)?;
        inactive(config, dir, &next)?;
    }
    let Some(slot) = slot else {
        return Ok(());
    };
    next.slot = Some(slot);
    next.logical_interface = device;
    next.incarnation = incarnation.into();
    let selected = selected(config, &next)?;
    let root = fs::read_to_string(dir.join("identity-root"))
        .map_err(|_| "persistent IPv6 identity path missing")?;
    let identity = if slot == 0 {
        Path::new(&root).to_path_buf()
    } else {
        Path::new(&root).with_file_name("backup-duid")
    };
    crate::pd::initialize_for(&selected, dir, &identity, &next.logical_interface)?;
    let hook = dir.join(format!("hook-{}", next.generation));
    let mut script = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&hook)
        .map_err(|e| e.to_string())?;
    let quote = |s: &str| format!("'{}'", s.replace('\'', "'\\''"));
    writeln!(
        script,
        "#!/bin/sh\nexport ROUTERTOP_PD_EPOCH={}\nexport ROUTERTOP_CONFIG={}\nexport ROUTERTOP_PD_RUNTIME={}\nexec /usr/sbin/routertop-ipv6-hook",
        quote(&next.token()), quote(&source.to_string_lossy()), quote(&dir.to_string_lossy())
    )
    .map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    let client = fs::read_to_string(dir.join("dhcpcd.conf"))
        .map_err(|e| e.to_string())?
        .replace(
            "script /usr/sbin/routertop-ipv6-hook",
            &format!("script {}", hook.display()),
        );
    crate::pd::atomic(&dir.join("dhcpcd.conf"), client.as_bytes())?;
    {
        let _pd = crate::pd::lock(dir)?;
        save(dir, &next)?;
        crate::pd::atomic(&dir.join("status.json"),json!({"wan_mode":"auto","state":"waiting","phase":"acquiring","provider":next.provider(),"generation":next.generation,"logical_interface":next.logical_interface,"wan_addresses":[],"delegated":[],"dns_servers":[],"error":null}).to_string().as_bytes())?;
    }
    if selected.wan.mode == WanProtocol::Pppoe {
        ip(&[
            "-6",
            "route",
            "replace",
            "default",
            "dev",
            &next.logical_interface,
            "metric",
            "5",
        ])?;
    }
    crate::wan::start_v6(source, dir, false)
}
