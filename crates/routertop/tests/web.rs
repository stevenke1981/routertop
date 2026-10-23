use routertop::web::{
    bootstrap_token, handle_request, initialize_store, stored_config, Paths, Request, Response,
};
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Barrier},
    time::{SystemTime, UNIX_EPOCH},
};

const SAMPLE: &str = include_str!("../../../configs/routertop.toml");
const PASSWORD: &str = "correct horse battery staple";
const NOW: u64 = 1_800_000_000;
struct Fixture {
    root: PathBuf,
    paths: Paths,
}
impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("routertop-web-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let paths = Paths {
            data: root.join("data"),
            runtime: root.join("run"),
            active: root.join("active.toml"),
        };
        fs::write(&paths.active, SAMPLE).unwrap();
        initialize_store(&paths.data, SAMPLE).unwrap();
        Self { root, paths }
    }
    fn call(&self, request: &Request) -> Response {
        handle_request(&self.paths, request, NOW)
    }
    fn setup(&self) -> (String, String) {
        let reply = self.call(&post(
            "/setup",
            json!({"token":bootstrap_token(&self.paths.data).unwrap(),"password":PASSWORD}),
        ));
        assert_eq!(reply.status, 200, "{}", reply.body);
        credentials(&reply)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn request(method: &str, path: &str) -> Request {
    Request {
        method: method.into(),
        path: path.into(),
        host: "192.168.88.1".into(),
        origin: Some("https://192.168.88.1".into()),
        content_type: Some("application/json".into()),
        content_length: Some("0".into()),
        cookie: None,
        csrf: None,
        body: Vec::new(),
        https: true,
    }
}
fn post(path: &str, body: Value) -> Request {
    let mut req = request("POST", path);
    req.body = body.to_string().into_bytes();
    req.content_length = Some(req.body.len().to_string());
    req
}
fn authenticated(mut req: Request, credentials: &(String, String)) -> Request {
    req.cookie = Some(credentials.0.clone());
    req.csrf = Some(credentials.1.clone());
    req
}
fn credentials(reply: &Response) -> (String, String) {
    let cookie = reply
        .headers
        .iter()
        .find(|(key, _)| key == "Set-Cookie")
        .unwrap()
        .1
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let body: Value = serde_json::from_str(&reply.body).unwrap();
    (cookie, body["csrf_token"].as_str().unwrap().to_string())
}
fn body(reply: &Response) -> Value {
    serde_json::from_str(&reply.body).unwrap()
}

#[test]
fn enrollment_once_and_password_not_persisted_in_plaintext() {
    let fixture = Fixture::new();
    let before = fixture.call(&request("GET", "/session"));
    assert_eq!(
        body(&before),
        json!({"setup_required":true,"authenticated":false})
    );
    let enrollment = bootstrap_token(&fixture.paths.data).unwrap();
    assert!(!before.body.contains(&enrollment));
    let auth = fixture.setup();
    assert!(bootstrap_token(&fixture.paths.data).is_err());
    let after = fixture.call(&authenticated(request("GET", "/session"), &auth));
    assert_eq!(body(&after)["authenticated"], true);
    assert_eq!(
        fixture
            .call(&post(
                "/setup",
                json!({"token":enrollment,"password":PASSWORD})
            ))
            .status,
        409
    );
    let state = fs::read_to_string(fixture.paths.data.join("state.json")).unwrap();
    assert!(!state.contains(PASSWORD));
    assert!(state.contains("$argon2id$v=19$m=19456,t=2,p=1$"));
    initialize_store(&fixture.paths.data, SAMPLE).unwrap();
    assert!(bootstrap_token(&fixture.paths.data).is_err());
}

#[test]
fn corruption_and_missing_bundle_never_reset_administrator() {
    let fixture = Fixture::new();
    fixture.setup();
    fs::write(fixture.paths.data.join("state.json"), "broken").unwrap();
    assert!(initialize_store(&fixture.paths.data, SAMPLE).is_err());
    assert!(stored_config(&fixture.paths.data).is_err());
    assert_eq!(fixture.call(&request("GET", "/session")).status, 500);
    fs::remove_file(fixture.paths.data.join("state.json")).unwrap();
    assert!(initialize_store(&fixture.paths.data, SAMPLE).is_err());
    assert!(bootstrap_token(&fixture.paths.data).is_err());
}

#[test]
fn failed_login_throttles_across_independent_requests_and_recovers() {
    let fixture = Fixture::new();
    fixture.setup();
    let bad = post(
        "/login",
        json!({"username":"admin","password":"incorrect password"}),
    );
    for _ in 0..5 {
        assert_eq!(fixture.call(&bad).status, 401);
    }
    let good = post("/login", json!({"username":"admin","password":PASSWORD}));
    assert_eq!(fixture.call(&good).status, 429);
    assert_eq!(handle_request(&fixture.paths, &good, NOW + 301).status, 200);
}

#[test]
fn setup_wrong_token_counts_in_shared_throttle() {
    let fixture = Fixture::new();
    for _ in 0..5 {
        assert_eq!(
            fixture
                .call(&post(
                    "/setup",
                    json!({"token":"wrong","password":PASSWORD})
                ))
                .status,
            401
        );
    }
    assert_eq!(
        fixture
            .call(&post(
                "/setup",
                json!({"token":bootstrap_token(&fixture.paths.data).unwrap(),"password":PASSWORD})
            ))
            .status,
        429
    );
}

#[test]
fn csrf_origin_https_and_unknown_fields_are_enforced() {
    let fixture = Fixture::new();
    let auth = fixture.setup();
    let mut req = authenticated(post("/logout", json!({})), &auth);
    req.csrf = None;
    assert_eq!(fixture.call(&req).status, 403);
    req.csrf = Some("wrong".into());
    assert_eq!(fixture.call(&req).status, 403);
    req.csrf = Some(auth.1.clone());
    req.origin = Some("https://evil.example".into());
    assert_eq!(fixture.call(&req).status, 403);
    req.origin = None;
    assert_eq!(fixture.call(&req).status, 403);
    req.origin = Some("https://192.168.88.1".into());
    req.https = false;
    assert_eq!(fixture.call(&req).status, 403);
    assert_eq!(
        fixture
            .call(&authenticated(
                post("/logout", json!({"unexpected":true})),
                &auth
            ))
            .status,
        400
    );
    assert_eq!(fixture.call(&request("GET", "/config")).status, 401);
    let mut req = request("GET", "/session");
    req.host = "foo\r\nInjected: yes".into();
    assert_eq!(fixture.call(&req).status, 400);
}

#[test]
fn strict_content_length_content_type_and_password_boundaries() {
    let fixture = Fixture::new();
    let mut req = post("/login", json!({"username":"admin","password":PASSWORD}));
    for length in [None, Some("-1"), Some("+12"), Some("1x"), Some("0")] {
        req.content_length = length.map(str::to_string);
        assert_eq!(fixture.call(&req).status, 400);
    }
    req.content_length = Some("32769".into());
    assert_eq!(fixture.call(&req).status, 413);
    req.content_length = Some(req.body.len().to_string());
    req.content_type = Some("text/plain".into());
    assert_eq!(fixture.call(&req).status, 400);
    let token = bootstrap_token(&fixture.paths.data).unwrap();
    for password in ["a".repeat(11), "a".repeat(129)] {
        assert_eq!(
            fixture
                .call(&post("/setup", json!({"token":token,"password":password})))
                .status,
            400
        );
    }
    let mut req = request("GET", "/session");
    req.body = vec![b'a'];
    req.content_length = Some("1".into());
    assert_eq!(fixture.call(&req).status, 400);
}

#[test]
fn logout_expiry_password_change_and_reboot_invalidate_sessions() {
    let fixture = Fixture::new();
    let auth = fixture.setup();
    let req = authenticated(request("GET", "/config"), &auth);
    assert_eq!(handle_request(&fixture.paths, &req, NOW + 1800).status, 401);
    assert_eq!(handle_request(&fixture.paths, &req, NOW - 1).status, 401);
    assert_eq!(
        fixture
            .call(&authenticated(post("/logout", json!({})), &auth))
            .status,
        200
    );
    assert_eq!(fixture.call(&req).status, 401);
    let login = post("/login", json!({"username":"admin","password":PASSWORD}));
    let first = credentials(&fixture.call(&login));
    let second = credentials(&fixture.call(&login));
    let change = authenticated(
        post(
            "/password",
            json!({"current_password":PASSWORD,"new_password":"a different secure password"}),
        ),
        &first,
    );
    assert_eq!(fixture.call(&change).status, 200);
    for auth in [&first, &second] {
        assert_eq!(
            fixture
                .call(&authenticated(request("GET", "/config"), auth))
                .status,
            401
        );
    }
    assert_eq!(fixture.call(&login).status, 401);
    let next = fixture.call(&post(
        "/login",
        json!({"username":"admin","password":"a different secure password"}),
    ));
    assert_eq!(next.status, 200);
    let next = credentials(&next);
    assert_eq!(
        fixture
            .call(&authenticated(post("/reboot", json!({})), &next))
            .status,
        200
    );
    assert_eq!(
        fs::read_to_string(fixture.paths.runtime.join("reboot.request")).unwrap(),
        "reboot\n"
    );
    assert_eq!(
        fixture
            .call(&authenticated(request("GET", "/config"), &next))
            .status,
        401
    );
}

#[test]
fn simultaneous_configuration_writes_have_exactly_one_winner() {
    let fixture = Arc::new(Fixture::new());
    let auth = fixture.setup();
    let original = body(&fixture.call(&authenticated(request("GET", "/config"), &auth)));
    assert_eq!(original["pending_reboot"], false);
    let barrier = Arc::new(Barrier::new(3));
    let mut threads = Vec::new();
    for name in ["router-one", "router-two"] {
        let fixture = Arc::clone(&fixture);
        let barrier = Arc::clone(&barrier);
        let auth = auth.clone();
        let mut config = original["config"].clone();
        config["hostname"] = json!(name);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            fixture
                .call(&authenticated(
                    post("/config", json!({"config":config,"revision":1})),
                    &auth,
                ))
                .status
        }));
    }
    barrier.wait();
    let mut statuses: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    statuses.sort();
    assert_eq!(statuses, vec![200, 409]);
    let after = body(&fixture.call(&authenticated(request("GET", "/config"), &auth)));
    assert_eq!(after["revision"], 2);
    assert_eq!(after["pending_reboot"], true);
    let saved = stored_config(&fixture.paths.data).unwrap();
    assert!(saved.contains("router-one") || saved.contains("router-two"));
    // Compare parsed canonical config rather than whitespace/comment differences.
    fs::write(
        &fixture.paths.active,
        format!("# changed formatting\n{saved}\n"),
    )
    .unwrap();
    assert_eq!(
        body(&fixture.call(&authenticated(request("GET", "/config"), &auth)))["pending_reboot"],
        false
    );
}

#[test]
fn cookies_are_secure_and_duplicate_session_cookies_fail_closed() {
    let fixture = Fixture::new();
    let reply = fixture.call(&post(
        "/setup",
        json!({"token":bootstrap_token(&fixture.paths.data).unwrap(),"password":PASSWORD}),
    ));
    let cookie = reply
        .headers
        .iter()
        .find(|(key, _)| key == "Set-Cookie")
        .unwrap()
        .1
        .clone();
    for flag in [
        "HttpOnly",
        "Secure",
        "SameSite=Strict",
        "Path=/",
        "Max-Age=1800",
    ] {
        assert!(cookie.contains(flag));
    }
    assert!(reply
        .headers
        .contains(&("Cache-Control".into(), "no-store".into())));
    let auth = credentials(&reply);
    let mut req = authenticated(request("GET", "/config"), &auth);
    req.cookie = Some(format!("{}; {}", auth.0, auth.0));
    assert_eq!(fixture.call(&req).status, 401);
}

#[test]
fn wrong_current_password_does_not_change_credentials() {
    let fixture = Fixture::new();
    let auth = fixture.setup();
    assert_eq!(fixture.call(&authenticated(post("/password",json!({"current_password":"wrong current password","new_password":"a different secure password"})),&auth)).status,401);
    assert_eq!(
        fixture
            .call(&post(
                "/login",
                json!({"username":"admin","password":PASSWORD})
            ))
            .status,
        200
    );
}

#[cfg(unix)]
#[test]
fn persistent_secret_file_permissions_are_private() {
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new();
    fixture.setup();
    assert_eq!(
        fs::metadata(&fixture.paths.data)
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    for file in ["state.json", "initialized", ".lock"] {
        assert_eq!(
            fs::metadata(fixture.paths.data.join(file))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn write_failure_does_not_report_saved_or_destroy_previous_state() {
    let fixture = Fixture::new();
    let auth = fixture.setup();
    let before = stored_config(&fixture.paths.data).unwrap();
    let mut config = serde_json::to_value(routertop::parse_config(&before).unwrap()).unwrap();
    config["hostname"] = json!("must-not-save");
    fs::rename(&fixture.paths.runtime, fixture.root.join("run-backup")).unwrap();
    fs::write(&fixture.paths.runtime, "not a writable directory").unwrap();
    let reply = fixture.call(&authenticated(
        post("/config", json!({"config":config,"revision":1})),
        &auth,
    ));
    assert_eq!(reply.status, 500);
    assert_eq!(stored_config(&fixture.paths.data).unwrap(), before);
    assert!(bootstrap_token(&fixture.paths.data).is_err());
    assert!(!fs::read_to_string(fixture.paths.data.join("state.json"))
        .unwrap()
        .contains("must-not-save"));
}

#[test]
fn cross_process_write_helper() {
    let Ok(root) = std::env::var("ROUTERTOP_TEST_WORK") else {
        return;
    };
    let root = PathBuf::from(root);
    let id = std::env::var("ROUTERTOP_TEST_WRITER").unwrap();
    let auth: (String, String) =
        serde_json::from_slice(&fs::read(root.join("auth.json")).unwrap()).unwrap();
    let config: Value =
        serde_json::from_slice(&fs::read(root.join("config.json")).unwrap()).unwrap();
    let paths = Paths {
        data: root.join("data"),
        runtime: root.join("run"),
        active: root.join("active.toml"),
    };
    fs::write(root.join(format!("ready-{id}")), "ready").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !root.join("go").exists() {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let reply = handle_request(
        &paths,
        &authenticated(
            post("/config", json!({"config":config,"revision":1})),
            &auth,
        ),
        NOW,
    );
    fs::write(root.join(format!("result-{id}")), reply.status.to_string()).unwrap();
}

#[test]
fn separate_cgi_processes_serialize_configuration_revision() {
    let fixture = Fixture::new();
    let auth = fixture.setup();
    let mut config = serde_json::to_value(routertop::parse_config(SAMPLE).unwrap()).unwrap();
    config["hostname"] = json!("multiprocess-router");
    fs::write(
        fixture.root.join("auth.json"),
        serde_json::to_vec(&auth).unwrap(),
    )
    .unwrap();
    fs::write(
        fixture.root.join("config.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let mut children = Vec::new();
    for id in ["one", "two"] {
        children.push(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "cross_process_write_helper", "--nocapture"])
                .env("ROUTERTOP_TEST_WORK", &fixture.root)
                .env("ROUTERTOP_TEST_WRITER", id)
                .stdout(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        );
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !(fixture.root.join("ready-one").exists() && fixture.root.join("ready-two").exists()) {
        assert!(std::time::Instant::now() < deadline);
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    fs::write(fixture.root.join("go"), "go").unwrap();
    for mut child in children {
        assert!(child.wait().unwrap().success());
    }
    let mut statuses = [
        fs::read_to_string(fixture.root.join("result-one")).unwrap(),
        fs::read_to_string(fixture.root.join("result-two")).unwrap(),
    ];
    statuses.sort();
    assert_eq!(statuses, ["200", "409"]);
}

#[cfg(windows)]
#[test]
fn real_runtime_rename_failure_cannot_keep_old_password_sessions_alive() {
    use std::os::windows::fs::OpenOptionsExt;
    let fixture = Fixture::new();
    let auth = fixture.setup();
    let previous = fs::read(fixture.paths.runtime.join("sessions.json")).unwrap();
    // Keep reads/writes possible but deny DELETE sharing, so atomic replacement
    // of the runtime file fails only after the durable credential bundle saves.
    let held = fs::OpenOptions::new()
        .read(true)
        .share_mode(0x1 | 0x2)
        .open(fixture.paths.runtime.join("sessions.json"))
        .unwrap();
    let change = authenticated(
        post(
            "/password",
            json!({"current_password":PASSWORD,"new_password":"the new durable password"}),
        ),
        &auth,
    );
    assert_eq!(fixture.call(&change).status, 500);
    assert_eq!(
        fs::read(fixture.paths.runtime.join("sessions.json")).unwrap(),
        previous
    );
    drop(held);
    assert_eq!(
        fixture
            .call(&authenticated(request("GET", "/config"), &auth))
            .status,
        401
    );
    assert_eq!(
        fixture
            .call(&post(
                "/login",
                json!({"username":"admin","password":"the new durable password"})
            ))
            .status,
        200
    );
}
