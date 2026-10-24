use base64::{engine::general_purpose::STANDARD, Engine as _};
use routertop::web::{
    bootstrap_token, handle_request, initialize_store, stored_config, write_wireguard_configs,
    Paths, Request, Response,
};
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use x25519_dalek::{PublicKey, StaticSecret};

static LAB_SEQUENCE: AtomicU64 = AtomicU64::new(0);

const SAMPLE: &str = include_str!("../../../configs/routertop.toml");
const PASSWORD: &str = "test-only strong administrator password";
struct Lab {
    root: PathBuf,
    paths: Paths,
    cookie: String,
    csrf: String,
}
impl Lab {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "rt-network-web-{}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            LAB_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        let paths = Paths {
            data: root.join("data"),
            runtime: root.join("runtime"),
            active: root.join("active.toml"),
        };
        fs::write(&paths.active, SAMPLE).unwrap();
        initialize_store(&paths.data, SAMPLE).unwrap();
        let mut lab = Self {
            root,
            paths,
            cookie: String::new(),
            csrf: String::new(),
        };
        let response = lab.request(
            "POST",
            "/setup",
            Some(json!({"token":bootstrap_token(&lab.paths.data).unwrap(),"password":PASSWORD})),
            false,
        );
        lab.authenticate(response);
        lab
    }
    fn authenticate(&mut self, response: Response) {
        assert_eq!(response.status, 200, "{}", response.body);
        self.cookie = response
            .headers
            .iter()
            .find(|(k, _)| k == "Set-Cookie")
            .unwrap()
            .1
            .split(';')
            .next()
            .unwrap()
            .to_string();
        self.csrf = serde_json::from_str::<Value>(&response.body).unwrap()["csrf_token"]
            .as_str()
            .unwrap()
            .to_string();
    }
    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        authenticated: bool,
    ) -> Response {
        let body = body.map(|v| v.to_string().into_bytes()).unwrap_or_default();
        handle_request(
            &self.paths,
            &Request {
                method: method.into(),
                path: path.into(),
                host: "routertop.test".into(),
                origin: Some("https://routertop.test".into()),
                content_type: Some("application/json".into()),
                content_length: Some(body.len().to_string()),
                cookie: authenticated.then(|| self.cookie.clone()),
                csrf: authenticated.then(|| self.csrf.clone()),
                body,
                https: true,
            },
            1_800_000_000,
        )
    }
    fn get(&self, path: &str) -> Value {
        let r = self.request("GET", path, None, true);
        assert_eq!(r.status, 200, "{}", r.body);
        serde_json::from_str(&r.body).unwrap()
    }
    fn save(&self, config: Value, revision: u64) -> Response {
        self.request(
            "POST",
            "/config",
            Some(json!({"config":config,"revision":revision})),
            true,
        )
    }
}
impl Drop for Lab {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn tunnel() -> Value {
    json!({"interface":"wg0","address":"10.44.0.1/24","listen_port":51820,"mtu":1420,"internet":false,"peers":[]})
}

#[test]
fn wireguard_secret_is_atomic_persistent_private_and_never_in_public_config() {
    let mut lab = Lab::new();
    assert_eq!(
        lab.request("GET", "/wireguard/keys", None, false).status,
        401
    );
    let mut config = lab.get("/config")["config"].clone();
    config["wireguard"] = json!([tunnel()]);
    config["vlans"] = json!([{"interface":"vlan20","parent":"eth1","id":20,"address":"192.168.20.1/24","dhcp":null,"internet":false}]);
    assert_eq!(lab.save(config.clone(), 1).status, 200);
    let public = lab.get("/wireguard/keys")["public_keys"]["wg0"]
        .as_str()
        .unwrap()
        .to_string();
    let file = lab.paths.data.join("state.json");
    let state: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    let private = state["wireguard_keys"]["wg0"].as_str().unwrap().to_string();
    let bytes: [u8; 32] = STANDARD.decode(&private).unwrap().try_into().unwrap();
    assert_eq!(
        public,
        STANDARD.encode(PublicKey::from(&StaticSecret::from(bytes)).as_bytes())
    );
    for path in ["/session", "/config", "/wireguard/keys"] {
        assert!(!lab.get(path).to_string().contains(&private));
    }
    assert!(!stored_config(&lab.paths.data).unwrap().contains(&private));
    let output = lab.root.join("wg-private");
    assert_eq!(
        write_wireguard_configs(&lab.paths.data, &output).unwrap(),
        1
    );
    let wg = output.join("wg0.conf");
    assert!(fs::read_to_string(&wg)
        .unwrap()
        .contains(&format!("PrivateKey = {private}")));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&output).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&wg).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let snapshot = fs::read(&file).unwrap();
    assert_eq!(lab.save(config.clone(), 1).status, 409);
    let mut invalid = config.clone();
    invalid["wireguard"][0]["listen_port"] = json!(53);
    assert_eq!(lab.save(invalid, 2).status, 400);
    assert_eq!(snapshot, fs::read(&file).unwrap());
    // A process/reboot boundary has no in-memory key cache to recreate identity.
    fs::remove_dir_all(&lab.paths.runtime).unwrap();
    initialize_store(&lab.paths.data, SAMPLE).unwrap();
    let reply = lab.request(
        "POST",
        "/login",
        Some(json!({"username":"admin","password":PASSWORD})),
        false,
    );
    lab.authenticate(reply);
    assert_eq!(lab.get("/wireguard/keys")["public_keys"]["wg0"], public);
    assert_eq!(
        lab.get("/config")["config"],
        serde_json::to_value(serde_json::from_value::<routertop::Config>(config.clone()).unwrap())
            .unwrap()
    );
    config["hostname"] = json!("after-restart");
    assert_eq!(lab.save(config.clone(), 2).status, 200);
    assert_eq!(lab.get("/wireguard/keys")["public_keys"]["wg0"], public);
    config["wireguard"] = json!([]);
    assert_eq!(lab.save(config, 3).status, 200);
    let state: Value = serde_json::from_slice(&fs::read(file).unwrap()).unwrap();
    assert_eq!(state["wireguard_keys"], json!({}));
    assert_eq!(lab.get("/wireguard/keys")["public_keys"], json!({}));
}

#[test]
fn old_02_state_migrates_defaults_without_resetting_credentials_or_revision() {
    let mut lab = Lab::new();
    let file = lab.paths.data.join("state.json");
    let mut old: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
    let hash = old["admin_hash"].clone();
    old.as_object_mut().unwrap().remove("wireguard_keys");
    // A genuine 0.2 canonical bundle lacks all three new collection fields.
    let mut config: toml::Value = toml::from_str(old["config"].as_str().unwrap()).unwrap();
    config.as_table_mut().unwrap().remove("vlans");
    config.as_table_mut().unwrap().remove("wireguard");
    config["firewall"].as_table_mut().unwrap().remove("rules");
    old["config"] = json!(toml::to_string(&config).unwrap());
    old["revision"] = json!(7);
    fs::write(&file, serde_json::to_vec(&old).unwrap()).unwrap();
    fs::remove_dir_all(&lab.paths.runtime).unwrap();
    initialize_store(&lab.paths.data, SAMPLE).unwrap();
    assert!(bootstrap_token(&lab.paths.data).is_err());
    let reply = lab.request(
        "POST",
        "/login",
        Some(json!({"username":"admin","password":PASSWORD})),
        false,
    );
    lab.authenticate(reply);
    let fetched = lab.get("/config");
    assert_eq!(fetched["revision"], 7);
    assert_eq!(fetched["pending_reboot"], false);
    assert_eq!(fetched["config"]["vlans"], json!([]));
    assert_eq!(fetched["config"]["wireguard"], json!([]));
    assert_eq!(fetched["config"]["firewall"]["rules"], json!([]));
    assert_eq!(lab.save(fetched["config"].clone(), 7).status, 200);
    let migrated: Value = serde_json::from_slice(&fs::read(file).unwrap()).unwrap();
    assert_eq!(migrated["admin_hash"], hash);
    assert_eq!(migrated["revision"], 8);
}

#[test]
fn missing_or_corrupt_existing_private_key_never_silently_rotates_identity() {
    let lab = Lab::new();
    let mut config = lab.get("/config")["config"].clone();
    config["wireguard"] = json!([tunnel()]);
    assert_eq!(lab.save(config, 1).status, 200);
    let file = lab.paths.data.join("state.json");
    let good = fs::read(&file).unwrap();
    for replacement in [json!({}), json!({"wg0":"invalid-secret"})] {
        let mut state: Value = serde_json::from_slice(&good).unwrap();
        state["wireguard_keys"] = replacement;
        fs::write(&file, serde_json::to_vec(&state).unwrap()).unwrap();
        let damaged = fs::read(&file).unwrap();
        assert!(initialize_store(&lab.paths.data, SAMPLE).is_err());
        assert_eq!(
            lab.request("GET", "/wireguard/keys", None, true).status,
            500
        );
        assert_eq!(fs::read(&file).unwrap(), damaged);
    }
}
