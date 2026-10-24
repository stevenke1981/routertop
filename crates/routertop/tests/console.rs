use routertop::web::{self, ConsoleAuth, Paths, Request};
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

// Also compile the TTY gate while keeping this worktree's lib.rs ownership with
// the integrator. The production library exports the same source module.
#[path = "../src/console.rs"]
mod console;

const CONFIG: &str = include_str!("../../../configs/routertop.toml");
const PASSWORD: &str = "correct console administrator password";
const NEW_PASSWORD: &str = "changed console administrator password";
const NOW: u64 = 1_800_000_000;

struct Fixture {
    root: PathBuf,
    data: PathBuf,
    runtime: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("routertop-console-{}-{nonce}", std::process::id()));
        let data = root.join("data");
        let runtime = root.join("console-run");
        web::initialize_store(&data, CONFIG).unwrap();
        Self {
            root,
            data,
            runtime,
        }
    }
    fn enroll(&self) {
        web::console_setup(&self.data, PASSWORD, PASSWORD).unwrap();
    }
    fn authenticate(&self, password: &str, now: u64) -> ConsoleAuth {
        web::console_authenticate(&self.data, &self.runtime, password, now).unwrap()
    }
    fn paths(&self) -> Paths {
        Paths {
            data: self.data.clone(),
            runtime: self.root.join("web-run"),
            active: self.root.join("active.toml"),
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn post(path: &str, body: Value) -> Request {
    let body = serde_json::to_vec(&body).unwrap();
    Request {
        method: "POST".into(),
        path: path.into(),
        host: "192.168.88.1".into(),
        origin: Some("https://192.168.88.1".into()),
        content_type: Some("application/json".into()),
        content_length: Some(body.len().to_string()),
        cookie: None,
        csrf: None,
        body,
        https: true,
    }
}

#[test]
fn physical_setup_consumes_token_and_never_persists_plaintext() {
    let fixture = Fixture::new();
    assert!(web::console_setup_required(&fixture.data).unwrap());
    let token = web::bootstrap_token(&fixture.data).unwrap();
    assert!(web::console_setup(&fixture.data, "short", "short").is_err());
    assert!(web::console_setup(&fixture.data, PASSWORD, NEW_PASSWORD).is_err());
    assert_eq!(web::bootstrap_token(&fixture.data).unwrap(), token);
    fixture.enroll();
    assert!(!web::console_setup_required(&fixture.data).unwrap());
    assert!(web::bootstrap_token(&fixture.data).is_err());
    let text = fs::read_to_string(fixture.data.join("state.json")).unwrap();
    assert!(text.contains("argon2id"));
    assert!(!text.contains(PASSWORD));
    assert!(!text.contains(&token));
    assert!(web::console_setup(&fixture.data, NEW_PASSWORD, NEW_PASSWORD).is_err());
    assert_eq!(fixture.authenticate(PASSWORD, NOW), ConsoleAuth::Accepted);
    assert_eq!(
        fixture.authenticate(NEW_PASSWORD, NOW),
        ConsoleAuth::Rejected
    );
}

#[test]
fn throttling_is_shared_across_instances_and_reset_only_after_window() {
    let fixture = Fixture::new();
    fixture.enroll();
    for _ in 0..5 {
        assert_eq!(
            fixture.authenticate("wrong valid length", NOW),
            ConsoleAuth::Rejected
        );
    }
    // Helpers hold no process-local auth cache; reopening the same paths models
    // separate TTY processes and preserves the shared failure window.
    assert_eq!(
        fixture.authenticate(PASSWORD, NOW + 1),
        ConsoleAuth::Throttled
    );
    assert_eq!(
        fixture.authenticate(PASSWORD, NOW + 299),
        ConsoleAuth::Throttled
    );
    assert_eq!(
        fixture.authenticate(PASSWORD, NOW + 300),
        ConsoleAuth::Accepted
    );
    assert!(!fixture.paths().runtime.exists());
    let text = fs::read_to_string(fixture.runtime.join("attempts.json")).unwrap();
    assert!(!text.contains(PASSWORD));
}

#[test]
fn web_password_change_immediately_controls_new_console_login() {
    let fixture = Fixture::new();
    fixture.enroll();
    let paths = fixture.paths();
    let login = web::handle_request(
        &paths,
        &post("/login", json!({"username":"admin", "password":PASSWORD})),
        NOW,
    );
    assert_eq!(login.status, 200);
    let body: Value = serde_json::from_str(&login.body).unwrap();
    let cookie = login
        .headers
        .iter()
        .find(|(key, _)| key == "Set-Cookie")
        .unwrap()
        .1
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let mut change = post(
        "/password",
        json!({"current_password":PASSWORD,"new_password":NEW_PASSWORD}),
    );
    change.cookie = Some(cookie);
    change.csrf = Some(body["csrf_token"].as_str().unwrap().into());
    assert_eq!(web::handle_request(&paths, &change, NOW).status, 200);
    assert_eq!(fixture.authenticate(PASSWORD, NOW), ConsoleAuth::Rejected);
    assert_eq!(
        fixture.authenticate(NEW_PASSWORD, NOW),
        ConsoleAuth::Accepted
    );
    // Simulate a reboot's empty console runtime without replacing durable state.
    fs::remove_dir_all(&fixture.runtime).unwrap();
    web::initialize_store(&fixture.data, CONFIG).unwrap();
    assert_eq!(
        fixture.authenticate(NEW_PASSWORD, NOW + 400),
        ConsoleAuth::Accepted
    );
    assert_eq!(
        fixture.authenticate(PASSWORD, NOW + 400),
        ConsoleAuth::Rejected
    );
}

#[test]
fn web_enrollment_also_enables_console_without_second_account() {
    let fixture = Fixture::new();
    let token = web::bootstrap_token(&fixture.data).unwrap();
    let setup = post("/setup", json!({"token":token,"password":PASSWORD}));
    assert_eq!(
        web::handle_request(&fixture.paths(), &setup, NOW).status,
        200
    );
    assert_eq!(fixture.authenticate(PASSWORD, NOW), ConsoleAuth::Accepted);
    assert!(web::console_setup(&fixture.data, NEW_PASSWORD, NEW_PASSWORD).is_err());
}

#[test]
fn absent_corrupt_and_unenrolled_state_never_authorize() {
    let fixture = Fixture::new();
    assert!(web::console_authenticate(&fixture.data, &fixture.runtime, PASSWORD, NOW).is_err());
    fixture.enroll();
    fs::write(fixture.data.join("state.json"), "corrupt").unwrap();
    assert!(web::console_setup_required(&fixture.data).is_err());
    assert!(web::console_setup(&fixture.data, PASSWORD, PASSWORD).is_err());
    assert!(web::console_authenticate(&fixture.data, &fixture.runtime, PASSWORD, NOW).is_err());
    fs::remove_dir_all(&fixture.data).unwrap();
    assert!(web::console_setup_required(&fixture.data).is_err());
    assert!(web::console_authenticate(&fixture.data, &fixture.runtime, PASSWORD, NOW).is_err());
    assert!(!fixture.data.exists());
}

#[test]
fn damaged_throttle_state_fails_closed_even_for_correct_password() {
    let fixture = Fixture::new();
    fixture.enroll();
    assert_eq!(fixture.authenticate(PASSWORD, NOW), ConsoleAuth::Accepted);
    fs::write(fixture.runtime.join("attempts.json"), "corrupt").unwrap();
    assert!(web::console_authenticate(&fixture.data, &fixture.runtime, PASSWORD, NOW).is_err());
}

#[test]
fn tty_gate_rejects_non_terminal_input() {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || !cfg!(target_os = "linux")
    {
        let fixture = Fixture::new();
        assert!(console::run(&fixture.data, &fixture.runtime).is_err());
    }
}

#[cfg(unix)]
#[test]
fn root_console_enrollment_preserves_cgi_owned_state_and_private_modes() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let fixture = Fixture::new();
    if fs::metadata(&fixture.data).unwrap().uid() == 0 {
        std::os::unix::fs::chown(&fixture.data, Some(1000), Some(1000)).unwrap();
        std::os::unix::fs::chown(fixture.data.join("state.json"), Some(1000), Some(1000)).unwrap();
    }
    let before = fs::metadata(fixture.data.join("state.json")).unwrap();
    fixture.enroll();
    let after = fs::metadata(fixture.data.join("state.json")).unwrap();
    assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
    assert_eq!(after.permissions().mode() & 0o777, 0o600);
    assert_eq!(fixture.authenticate(PASSWORD, NOW), ConsoleAuth::Accepted);
    assert_eq!(
        fs::metadata(&fixture.runtime).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(fixture.runtime.join("attempts.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
}
