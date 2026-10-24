//! Small CGI management API. Durable changes are serialized and committed as
//! one fsync/rename bundle; sessions and rate limits live on volatile storage.
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use fs2::FileExt;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};

const MAX_BODY: usize = 32 * 1024;
const MAX_STATE: u64 = 256 * 1024;
const SESSION_SECONDS: u64 = 1800;
const COOKIE: &str = "routertop_session";

#[cfg(test)]
thread_local! { static FAIL_RUNTIME_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Durable {
    schema: u32,
    revision: u64,
    config: String,
    admin_hash: Option<String>,
    enrollment_token: Option<String>,
    #[serde(default)]
    auth_epoch: u64,
    #[serde(default)]
    wireguard_keys: BTreeMap<String, String>,
}
#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Volatile {
    sessions: Vec<Session>,
    failures: u32,
    window_start: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    token: String,
    csrf: String,
    issued: u64,
    expires: u64,
    #[serde(default)]
    auth_epoch: u64,
}

/// Explicit paths keep tests and callers independent of process environment.
pub struct Paths {
    pub data: PathBuf,
    pub runtime: PathBuf,
    pub active: PathBuf,
}
pub struct Request {
    pub method: String,
    pub path: String,
    pub host: String,
    pub origin: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<String>,
    pub cookie: Option<String>,
    pub csrf: Option<String>,
    pub body: Vec<u8>,
    pub https: bool,
}
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}
type ApiResult<T> = Result<T, (u16, &'static str)>;

fn io_error(_: impl std::fmt::Display) -> String {
    "管理資料無法讀寫；請由主控台檢查儲存裝置".into()
}
fn private_directory(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(io_error)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(io_error)?;
    }
    Ok(())
}
fn private_file(path: &Path, create_new: bool) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true).truncate(false);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(io_error)
}
fn lock(data: &Path) -> Result<File, String> {
    // Never create data directories from HTTP: absence means management unavailable.
    if !data.is_dir() {
        return Err("持久儲存尚未初始化".into());
    }
    let file = private_file(&data.join(".lock"), false)?;
    for _ in 0..100 {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(e) if e.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
                std::thread::sleep(Duration::from_millis(20))
            }
            Err(e) => return Err(io_error(e)),
        }
    }
    Err("管理資料忙碌中，請稍後重試".into())
}
fn token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut bytes).map_err(io_error)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
fn token_shape(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn equal_secret(a: &str, b: &str) -> bool {
    bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}
fn atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().ok_or_else(|| "儲存路徑無效".to_string())?;
    let temp = parent.join(format!(".write-{}", token()?));
    let result = (|| {
        let mut file = private_file(&temp, true)?;
        // The root console and the unprivileged CGI share durable credentials.
        // A root-created replacement must not make the next CGI write fail.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let owner = fs::metadata(path)
                .or_else(|_| fs::metadata(parent))
                .map_err(io_error)?;
            let current = file.metadata().map_err(io_error)?;
            if current.uid() != owner.uid() || current.gid() != owner.gid() {
                std::os::unix::fs::chown(&temp, Some(owner.uid()), Some(owner.gid()))
                    .map_err(io_error)?;
            }
        }
        file.write_all(bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        drop(file);
        #[cfg(test)]
        if path.file_name().is_some_and(|name| name == "sessions.json")
            && FAIL_RUNTIME_RENAME.with(|flag| flag.get())
        {
            return Err("injected runtime rename failure".into());
        }
        fs::rename(&temp, path).map_err(io_error)?;
        #[cfg(unix)]
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(io_error)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
fn read_json<T: for<'a> Deserialize<'a>>(path: &Path) -> Result<T, String> {
    let mut file = File::open(path).map_err(io_error)?;
    if file.metadata().map_err(io_error)?.len() > MAX_STATE {
        return Err("管理資料大小異常".into());
    }
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).map_err(io_error)?;
    serde_json::from_slice(&contents).map_err(|_| "管理資料損壞；請由主控台復原，帳號未重設".into())
}
fn save_json(path: &Path, data: &impl Serialize) -> Result<(), String> {
    atomic(path, &serde_json::to_vec(data).map_err(io_error)?)
}
fn canonical(source: &str) -> Result<String, String> {
    toml::to_string(&crate::parse_config(source)?).map_err(io_error)
}
fn durable(data: &Path) -> Result<Durable, String> {
    let mut state: Durable = read_json(&data.join("state.json"))?;
    if state.schema != 1 || state.revision == 0 {
        return Err("持久設定格式無效；帳號未重設".into());
    }
    // Normalize newly defaulted fields in older 0.2 configs without replacing
    // credentials, revision, or initialized markers. Invalid config still fails.
    state.config = canonical(&state.config)?;
    let config = crate::parse_config(&state.config)?;
    if config.wireguard.len() != state.wireguard_keys.len() {
        return Err("WireGuard 金鑰缺失；拒絕自動更換既有身分".into());
    }
    for tunnel in &config.wireguard {
        public_key(
            state
                .wireguard_keys
                .get(&tunnel.interface)
                .ok_or("WireGuard 金鑰缺失")?,
        )?;
    }
    match (&state.admin_hash, &state.enrollment_token) {
        (Some(hash), None) => {
            let hash = PasswordHash::new(hash).map_err(|_| "管理員憑證損壞".to_string())?;
            if hash.algorithm.as_str() != "argon2id"
                || hash.version != Some(19)
                || hash.params.get_decimal("m") != Some(19456)
                || hash.params.get_decimal("t") != Some(2)
                || hash.params.get_decimal("p") != Some(1)
                || hash.salt.is_none()
                || hash.hash.map(|value| value.len()) != Some(32)
            {
                return Err("管理員憑證格式無效".into());
            }
        }
        (None, Some(token)) if token_shape(token) => {}
        _ => return Err("管理員註冊狀態損壞；帳號未重設".into()),
    }
    Ok(state)
}

pub fn initialize_store(data: &Path, default_config: &str) -> Result<(), String> {
    let config = canonical(default_config)?;
    let parsed = crate::parse_config(&config)?;
    private_directory(data)?;
    let _guard = lock(data)?;
    if data.join("state.json").exists() {
        durable(data)?;
        return Ok(());
    }
    // Any prior contents, including the durable marker, prevents silent re-enrollment.
    for item in fs::read_dir(data).map_err(io_error)? {
        if item.map_err(io_error)?.file_name() != ".lock" {
            return Err("持久資料缺失或損壞；拒絕重設管理員".into());
        }
    }
    atomic(&data.join("initialized"), b"RouterTop state schema 1\n")?;
    save_json(
        &data.join("state.json"),
        &Durable {
            schema: 1,
            revision: 1,
            config,
            admin_hash: None,
            enrollment_token: Some(token()?),
            auth_epoch: 0,
            wireguard_keys: reconcile_keys(&parsed, &BTreeMap::new())?,
        },
    )
}
pub fn stored_config(data: &Path) -> Result<String, String> {
    let _guard = lock(data)?;
    Ok(durable(data)?.config)
}
pub fn bootstrap_token(data: &Path) -> Result<String, String> {
    let _guard = lock(data)?;
    durable(data)?
        .enrollment_token
        .ok_or_else(|| "管理員已完成註冊".into())
}

fn private_key_bytes(encoded: &str) -> Result<[u8; 32], String> {
    let bytes = STANDARD.decode(encoded).map_err(|_| "WireGuard 私鑰損壞")?;
    let bytes: [u8; 32] = bytes.try_into().map_err(|_| "WireGuard 私鑰長度無效")?;
    if STANDARD.encode(bytes) != encoded || bytes[0] & 7 != 0 || bytes[31] & 0xc0 != 0x40 {
        return Err("WireGuard 私鑰格式無效".into());
    }
    Ok(bytes)
}

fn public_key(encoded: &str) -> Result<String, String> {
    let secret = StaticSecret::from(private_key_bytes(encoded)?);
    Ok(STANDARD.encode(PublicKey::from(&secret).as_bytes()))
}

fn reconcile_keys(
    config: &crate::Config,
    previous: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>, String> {
    let mut keys = BTreeMap::new();
    for tunnel in &config.wireguard {
        let private = if let Some(existing) = previous.get(&tunnel.interface) {
            existing.clone()
        } else {
            let mut bytes = [0u8; 32];
            OsRng.try_fill_bytes(&mut bytes).map_err(io_error)?;
            bytes[0] &= 248;
            bytes[31] = (bytes[31] & 127) | 64;
            STANDARD.encode(bytes)
        };
        let own_public = public_key(&private)?;
        if tunnel
            .peers
            .iter()
            .any(|peer| peer.public_key == own_public)
        {
            return Err("WireGuard peer 不可使用自己的公鑰".into());
        }
        keys.insert(tunnel.interface.clone(), private);
    }
    Ok(keys)
}

/// Root CLI only: secret files are separate from the public active config.
/// Callers enforce local-root access; the directory and files are private.
pub fn write_wireguard_configs(data: &Path, output: &Path) -> Result<usize, String> {
    use std::fmt::Write as _;
    let _guard = lock(data)?;
    let state = durable(data)?;
    let config = crate::parse_config(&state.config)?;
    private_directory(output)?;
    for tunnel in &config.wireguard {
        let private = state
            .wireguard_keys
            .get(&tunnel.interface)
            .ok_or("WireGuard 金鑰缺失")?;
        let mut text = format!(
            "[Interface]\nPrivateKey = {private}\nListenPort = {}\n",
            tunnel.listen_port
        );
        for peer in &tunnel.peers {
            writeln!(
                text,
                "\n[Peer]\nPublicKey = {}\nAllowedIPs = {}\nPersistentKeepalive = {}",
                peer.public_key,
                peer.allowed_ips.join(", "),
                peer.persistent_keepalive
            )
            .map_err(io_error)?;
            if let Some(endpoint) = &peer.endpoint {
                writeln!(text, "Endpoint = {endpoint}").map_err(io_error)?;
            }
        }
        atomic(
            &output.join(format!("{}.conf", tunnel.interface)),
            text.as_bytes(),
        )?;
    }
    Ok(config.wireguard.len())
}

fn response(status: u16, body: Value) -> Response {
    Response {
        status,
        headers: vec![
            (
                "Content-Type".into(),
                "application/json; charset=utf-8".into(),
            ),
            ("Cache-Control".into(), "no-store".into()),
            ("X-Content-Type-Options".into(), "nosniff".into()),
        ],
        body: body.to_string(),
    }
}
fn cookie(response: &mut Response, token: &str) {
    response.headers.push((
        "Set-Cookie".into(),
        format!(
            "{COOKIE}={token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
            if token.is_empty() { 0 } else { SESSION_SECONDS }
        ),
    ));
}
fn password_ok(password: &str) -> bool {
    (12..=128).contains(&password.len()) && !password.bytes().any(|byte| byte.is_ascii_control())
}
fn password_hash(password: &str) -> Result<String, String> {
    let mut bytes = [0u8; 16];
    OsRng.try_fill_bytes(&mut bytes).map_err(io_error)?;
    let salt = SaltString::encode_b64(&bytes).map_err(io_error)?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(io_error)
}
fn verify(password: &str, hash: &str) -> bool {
    if !password_ok(password) {
        return false;
    }
    PasswordHash::new(hash)
        .map(|h| {
            Argon2::default()
                .verify_password(password.as_bytes(), &h)
                .is_ok()
        })
        .unwrap_or(false)
}

/// Physical-console enrollment shares the exact durable Web administrator.
/// The caller must already have physical console access; no HTTP route exposes
/// this enrollment method. Existing accounts can never be reset through it.
pub fn console_setup_required(data: &Path) -> Result<bool, String> {
    let _guard = lock(data)?;
    Ok(durable(data)?.admin_hash.is_none())
}

pub fn console_setup(data: &Path, password: &str, confirmation: &str) -> Result<(), String> {
    if !password_ok(password) || password != confirmation {
        return Err(
            "Passwords must match, contain 12 to 128 bytes, and exclude control characters.".into(),
        );
    }
    let _guard = lock(data)?;
    let mut state = durable(data)?;
    if state.admin_hash.is_some() {
        return Err("Administrator already enrolled; log in with the existing password.".into());
    }
    state.admin_hash = Some(password_hash(password)?);
    state.enrollment_token = None;
    state.auth_epoch = state
        .auth_epoch
        .checked_add(1)
        .ok_or("Credential epoch exhausted")?;
    save_json(&data.join("state.json"), &state)
}

#[derive(Debug, PartialEq, Eq)]
pub enum ConsoleAuth {
    Accepted,
    Rejected,
    Throttled,
}

/// A separate root-owned runtime directory isolates console throttling from
/// CGI sessions. Holding both locks serializes attempts across all local TTYs
/// and checks the current persisted hash on every attempt.
pub fn console_authenticate(
    data: &Path,
    runtime: &Path,
    password: &str,
    now: u64,
) -> Result<ConsoleAuth, String> {
    private_directory(runtime)?;
    let _console_guard = lock(runtime)?;
    let _data_guard = lock(data)?;
    let state = durable(data)?;
    let hash = state
        .admin_hash
        .as_deref()
        .ok_or("Administrator setup is required")?;
    let attempts = runtime.join("attempts.json");
    let mut rate: Volatile = if attempts.exists() {
        read_json(&attempts)?
    } else {
        Volatile::default()
    };
    if rate.failures > 5 || !rate.sessions.is_empty() {
        return Err("Console throttle state is invalid".into());
    }
    if throttle(&mut rate, now).is_err() {
        return Ok(ConsoleAuth::Throttled);
    }
    let accepted = verify(password, hash);
    if accepted {
        rate.failures = 0;
        rate.window_start = now;
    } else {
        rate.failures += 1;
    }
    // A failed write never authorizes a shell, even for a correct password.
    save_json(&attempts, &rate)?;
    Ok(if accepted {
        ConsoleAuth::Accepted
    } else {
        ConsoleAuth::Rejected
    })
}
fn request_length(request: &Request) -> ApiResult<()> {
    let declared = match &request.content_length {
        None if request.method == "GET" => 0,
        Some(value) if !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()) => {
            value.parse::<usize>().map_err(|_| (413, "要求內容太大"))?
        }
        _ => return Err((400, "Content-Length 無效")),
    };
    if declared > MAX_BODY || request.body.len() > MAX_BODY {
        return Err((413, "要求內容太大"));
    }
    if declared != request.body.len() {
        return Err((400, "要求內容長度不符"));
    }
    Ok(())
}
fn validate_request(request: &Request) -> ApiResult<()> {
    if !request.https {
        return Err((403, "管理介面僅接受 HTTPS"));
    }
    if request.host.is_empty()
        || request.host.len() > 255
        || !request
            .host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b".-:[]".contains(&c))
    {
        return Err((400, "Host 無效"));
    }
    request_length(request)?;
    match request.method.as_str() {
        "GET" if request.body.is_empty() => Ok(()),
        "POST" => {
            if request.origin.as_deref() != Some(format!("https://{}", request.host).as_str()) {
                return Err((403, "來源驗證失敗"));
            }
            let content_type = request.content_type.as_deref().unwrap_or("");
            if content_type != "application/json"
                && content_type != "application/json; charset=utf-8"
            {
                return Err((400, "需要 application/json"));
            }
            Ok(())
        }
        _ => Err((400, "不支援此 HTTP 方法")),
    }
}
fn parse<T: for<'a> Deserialize<'a>>(request: &Request) -> ApiResult<T> {
    serde_json::from_slice(&request.body).map_err(|_| (400, "JSON 格式或欄位無效"))
}
fn session_token(request: &Request) -> Option<&str> {
    let mut found = None;
    for item in request.cookie.as_deref()?.split(';') {
        let Some((name, value)) = item.trim().split_once('=') else {
            continue;
        };
        if name == COOKIE {
            if found.is_some() || !token_shape(value) {
                return None;
            }
            found = Some(value);
        }
    }
    found
}
fn pending(paths: &Paths, config: &str) -> bool {
    fs::read_to_string(&paths.active)
        .ok()
        .and_then(|text| canonical(&text).ok())
        .as_deref()
        != Some(config)
}
fn store_runtime(paths: &Paths, state: &Volatile) -> ApiResult<()> {
    save_json(&paths.runtime.join("sessions.json"), state)
        .map_err(|_| (500, "暫存管理資料無法寫入"))
}
fn throttle(state: &mut Volatile, now: u64) -> ApiResult<()> {
    if now < state.window_start || now.saturating_sub(state.window_start) >= 300 {
        state.window_start = now;
        state.failures = 0;
    }
    if state.failures >= 5 {
        return Err((429, "登入嘗試過多，請五分鐘後再試"));
    }
    Ok(())
}
fn new_session(state: &mut Volatile, now: u64, auth_epoch: u64) -> ApiResult<(String, String)> {
    if state.sessions.len() >= 64 {
        state.sessions.remove(0);
    }
    let session = Session {
        token: token().map_err(|_| (500, "亂數來源失敗"))?,
        csrf: token().map_err(|_| (500, "亂數來源失敗"))?,
        issued: now,
        expires: now.saturating_add(SESSION_SECONDS),
        auth_epoch,
    };
    let result = (session.token.clone(), session.csrf.clone());
    state.sessions.push(session);
    Ok(result)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Setup {
    token: String,
    password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    username: String,
    password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SaveConfig {
    config: crate::Config,
    revision: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangePassword {
    current_password: String,
    new_password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

pub fn handle_request(paths: &Paths, request: &Request, now: u64) -> Response {
    match dispatch(paths, request, now) {
        Ok(response) => response,
        Err((status, error)) => response(status, json!({"error":error})),
    }
}
fn dispatch(paths: &Paths, request: &Request, now: u64) -> ApiResult<Response> {
    validate_request(request)?;
    let _guard = lock(&paths.data).map_err(|_| (500, "持久儲存無法使用"))?;
    let mut data = durable(&paths.data).map_err(|_| (500, "持久資料損壞或缺失；請由主控台復原"))?;
    private_directory(&paths.runtime).map_err(|_| (500, "暫存管理資料無法建立"))?;
    let runtime_file = paths.runtime.join("sessions.json");
    let mut runtime: Volatile = if runtime_file.exists() {
        read_json(&runtime_file).map_err(|_| (500, "暫存管理資料損壞"))?
    } else {
        Volatile::default()
    };
    if runtime.sessions.len() > 64 || runtime.failures > 5 {
        return Err((500, "暫存管理資料格式無效"));
    }
    runtime.sessions.retain(|s| {
        now >= s.issued
            && now < s.expires
            && token_shape(&s.token)
            && token_shape(&s.csrf)
            && s.auth_epoch == data.auth_epoch
    });
    let current = session_token(request).and_then(|token| {
        runtime
            .sessions
            .iter()
            .position(|s| equal_secret(token, &s.token))
    });
    if request.method == "GET" && request.path == "/session" {
        return Ok(response(
            200,
            match current {
                Some(index) => {
                    json!({"setup_required":false,"authenticated":true,"csrf_token":runtime.sessions[index].csrf})
                }
                None => json!({"setup_required":data.admin_hash.is_none(),"authenticated":false}),
            },
        ));
    }
    if request.method == "POST" && (request.path == "/setup" || request.path == "/login") {
        throttle(&mut runtime, now)?;
        let valid = if request.path == "/setup" {
            if data.admin_hash.is_some() {
                return Err((409, "管理員已完成註冊"));
            }
            let setup: Setup = parse(request)?;
            if !password_ok(&setup.password) {
                return Err((400, "密碼長度必須是 12 到 128 位元組，且不可包含控制字元"));
            }
            let valid = data
                .enrollment_token
                .as_deref()
                .map(|expected| equal_secret(expected, &setup.token))
                .unwrap_or(false);
            if valid {
                data.admin_hash =
                    Some(password_hash(&setup.password).map_err(|_| (500, "密碼雜湊失敗"))?);
                data.enrollment_token = None;
                data.auth_epoch = data
                    .auth_epoch
                    .checked_add(1)
                    .ok_or((500, "憑證版本已達上限"))?;
                save_json(&paths.data.join("state.json"), &data)
                    .map_err(|_| (500, "管理員資料無法儲存"))?;
            }
            valid
        } else {
            let login: Login = parse(request)?;
            login.username == "admin"
                && data
                    .admin_hash
                    .as_deref()
                    .map(|hash| verify(&login.password, hash))
                    .unwrap_or(false)
        };
        if !valid {
            runtime.failures += 1;
            store_runtime(paths, &runtime)?;
            return Err((401, "帳號、密碼或註冊權杖不正確"));
        }
        // Do not reset the global throttle on success; otherwise an attacker with
        // one valid credential could continuously clear another client's budget.
        let (token, csrf) = new_session(&mut runtime, now, data.auth_epoch)?;
        store_runtime(paths, &runtime)?;
        let mut reply = response(
            200,
            json!({"setup_required":false,"authenticated":true,"csrf_token":csrf}),
        );
        cookie(&mut reply, &token);
        return Ok(reply);
    }
    let current = current.ok_or((401, "請先登入"))?;
    if request.method == "POST"
        && !request
            .csrf
            .as_deref()
            .map(|csrf| equal_secret(csrf, &runtime.sessions[current].csrf))
            .unwrap_or(false)
    {
        return Err((403, "CSRF 驗證失敗"));
    }
    let mut reply = match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/wireguard/keys") => {
            let keys: Result<BTreeMap<_, _>, _> = data
                .wireguard_keys
                .iter()
                .map(|(name, private)| public_key(private).map(|public| (name, public)))
                .collect();
            response(
                200,
                json!({"public_keys":keys.map_err(|_| (500,"WireGuard 金鑰無效"))?}),
            )
        }
        ("GET", "/config") => {
            let mut config =
                crate::parse_config(&data.config).map_err(|_| (500, "設定資料無效"))?;
            let password_set = config
                .wan
                .pppoe
                .as_ref()
                .is_some_and(|p| !p.password.is_empty());
            if let Some(ppp) = &mut config.wan.pppoe {
                ppp.password.clear();
            }
            response(
                200,
                json!({"config":config,"wan_password_set":password_set,"revision":data.revision,"pending_reboot":pending(paths,&data.config)}),
            )
        }
        ("POST", "/config") => {
            let mut change: SaveConfig = parse(request)?;
            let previous = crate::parse_config(&data.config).map_err(|_| (500, "設定資料無效"))?;
            if change.config.wan.mode == crate::WanProtocol::Dhcp {
                change.config.wan.pppoe = None;
            } else if let Some(ppp) = &mut change.config.wan.pppoe {
                if ppp.password.is_empty() {
                    if let Some(old) = previous.wan.pppoe.as_ref().filter(|old| {
                        previous.wan.mode == crate::WanProtocol::Pppoe
                            && old.username == ppp.username
                    }) {
                        ppp.password.clone_from(&old.password);
                    }
                }
            }
            if let Err(error) = crate::validate(&change.config) {
                return Ok(response(400, json!({"error":error})));
            }
            if change.revision != data.revision {
                return Err((409, "設定已由其他操作更新，請重新載入"));
            }
            data.wireguard_keys = reconcile_keys(&change.config, &data.wireguard_keys)
                .map_err(|_| (400, "WireGuard 金鑰或 peer 設定無效"))?;
            data.config = toml::to_string(&change.config).map_err(|_| (500, "設定編碼失敗"))?;
            data.revision = data
                .revision
                .checked_add(1)
                .ok_or((500, "設定版本已達上限"))?;
            save_json(&paths.data.join("state.json"), &data).map_err(|_| (500, "設定無法儲存"))?;
            response(
                200,
                json!({"revision":data.revision,"pending_reboot":pending(paths,&data.config)}),
            )
        }
        ("GET", "/status") => {
            let uptime = fs::read_to_string("/proc/uptime")
                .ok()
                .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
                .filter(|v| v.is_finite() && *v >= 0.0)
                .ok_or((500, "無法讀取系統運作時間"))? as u64;
            let memory =
                fs::read_to_string("/proc/meminfo").map_err(|_| (500, "無法讀取系統記憶體"))?;
            let field = |name: &str| {
                memory.lines().find_map(|line| {
                    line.strip_prefix(name)?
                        .split_whitespace()
                        .next()?
                        .parse::<u64>()
                        .ok()
                })
            };
            let total = field("MemTotal:").ok_or((500, "無法讀取記憶體總量"))?;
            let available = field("MemAvailable:").ok_or((500, "無法讀取可用記憶體"))?;
            let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
                .map_err(|_| (500, "無法讀取系統主機名稱"))?;
            response(
                200,
                json!({"hostname":hostname.trim(),"uptime_seconds":uptime,"memory_total_kib":total,"memory_available_kib":available,"persistent":true,"pending_reboot":pending(paths,&data.config),"version":env!("CARGO_PKG_VERSION"),"console_auth_required":true,"console_password_shared":true,"ipv6_dynamic":crate::pd::read_status(),"wan":crate::pppoe::read_status(&crate::parse_config(&data.config).map_err(|_|(500,"設定資料無效"))?)}),
            )
        }
        ("POST", "/logout") => {
            let _: Empty = parse(request)?;
            runtime.sessions.remove(current);
            store_runtime(paths, &runtime)?;
            response(200, json!({"authenticated":false}))
        }
        ("POST", "/password") => {
            let change: ChangePassword = parse(request)?;
            if !password_ok(&change.new_password) {
                return Err((400, "密碼長度必須是 12 到 128 位元組，且不可包含控制字元"));
            }
            throttle(&mut runtime, now)?;
            if !data
                .admin_hash
                .as_deref()
                .map(|hash| verify(&change.current_password, hash))
                .unwrap_or(false)
            {
                runtime.failures += 1;
                store_runtime(paths, &runtime)?;
                return Err((401, "目前密碼不正確"));
            }
            data.admin_hash =
                Some(password_hash(&change.new_password).map_err(|_| (500, "密碼雜湊失敗"))?);
            // Credential and epoch are one durable transaction. Old sessions are
            // rejected even if clearing their volatile file subsequently fails.
            data.auth_epoch = data
                .auth_epoch
                .checked_add(1)
                .ok_or((500, "憑證版本已達上限"))?;
            save_json(&paths.data.join("state.json"), &data).map_err(|_| (500, "密碼無法儲存"))?;
            runtime.sessions.clear();
            store_runtime(paths, &runtime)?;
            response(200, json!({"authenticated":false}))
        }
        ("POST", "/reboot") => {
            let _: Empty = parse(request)?;
            runtime.sessions.clear();
            store_runtime(paths, &runtime)?;
            atomic(&paths.runtime.join("reboot.request"), b"reboot\n")
                .map_err(|_| (500, "重新啟動要求無法寫入"))?;
            response(200, json!({"reboot_requested":true}))
        }
        _ => return Err((400, "未知的管理 API")),
    };
    if request.method == "POST"
        && matches!(request.path.as_str(), "/logout" | "/password" | "/reboot")
    {
        cookie(&mut reply, "");
    }
    Ok(reply)
}

pub fn run_cgi() -> Result<(), String> {
    let get = |name: &str| std::env::var(name).ok();
    let mut request = Request {
        method: get("REQUEST_METHOD").unwrap_or_default(),
        path: get("PATH_INFO").unwrap_or_default(),
        host: get("HTTP_HOST").unwrap_or_default(),
        origin: get("HTTP_ORIGIN"),
        content_type: get("CONTENT_TYPE"),
        content_length: get("CONTENT_LENGTH"),
        cookie: get("HTTP_COOKIE"),
        csrf: get("HTTP_X_CSRF_TOKEN"),
        body: Vec::new(),
        https: get("HTTPS").as_deref() == Some("on"),
    };
    let declared = request
        .content_length
        .as_deref()
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<usize>().ok());
    let early = if declared.unwrap_or(0) > MAX_BODY {
        Some(response(413, json!({"error":"要求內容太大"})))
    } else {
        None
    };
    let reply = if let Some(reply) = early {
        reply
    } else {
        // Read one byte beyond the declaration to reject both truncated and extra bodies.
        let limit = declared.unwrap_or(0).saturating_add(1).min(MAX_BODY + 1);
        std::io::stdin()
            .take(limit as u64)
            .read_to_end(&mut request.body)
            .map_err(io_error)?;
        let paths = Paths {
            data: PathBuf::from(
                get("ROUTERTOP_DATA_DIR").unwrap_or_else(|| "/data/routertop".into()),
            ),
            runtime: PathBuf::from(
                get("ROUTERTOP_RUNTIME_DIR").unwrap_or_else(|| "/run/routertop/web".into()),
            ),
            active: PathBuf::from(
                get("ROUTERTOP_ACTIVE_CONFIG")
                    .unwrap_or_else(|| "/etc/routertop/routertop.toml".into()),
            ),
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io_error)?
            .as_secs();
        handle_request(&paths, &request, now)
    };
    let mut stdout = std::io::stdout().lock();
    write!(stdout, "Status: {}\r\n", reply.status).map_err(io_error)?;
    for (key, value) in reply.headers {
        write!(stdout, "{key}: {value}\r\n").map_err(io_error)?;
    }
    write!(
        stdout,
        "Content-Length: {}\r\n\r\n{}",
        reply.body.len(),
        reply.body
    )
    .map_err(io_error)?;
    stdout.flush().map_err(io_error)
}

#[cfg(test)]
mod atomicity_tests {
    use super::*;

    #[test]
    fn durable_password_epoch_revokes_sessions_when_runtime_rename_fails() {
        let root = std::env::temp_dir().join(format!("routertop-epoch-{}", token().unwrap()));
        let paths = Paths {
            data: root.join("data"),
            runtime: root.join("run"),
            active: root.join("active.toml"),
        };
        initialize_store(&paths.data, include_str!("../../../configs/routertop.toml")).unwrap();
        let request = |path: &str, body: Value| {
            let bytes = body.to_string().into_bytes();
            Request {
                method: "POST".into(),
                path: path.into(),
                host: "router.test".into(),
                origin: Some("https://router.test".into()),
                content_type: Some("application/json".into()),
                content_length: Some(bytes.len().to_string()),
                cookie: None,
                csrf: None,
                body: bytes,
                https: true,
            }
        };
        let setup = request(
            "/setup",
            json!({"token":bootstrap_token(&paths.data).unwrap(), "password":"old correct password"}),
        );
        let setup = handle_request(&paths, &setup, 1000);
        assert_eq!(setup.status, 200);
        let cookie = setup
            .headers
            .iter()
            .find(|(key, _)| key == "Set-Cookie")
            .unwrap()
            .1
            .split(';')
            .next()
            .unwrap()
            .to_string();
        let csrf: Value = serde_json::from_str(&setup.body).unwrap();
        let mut change = request(
            "/password",
            json!({"current_password":"old correct password", "new_password":"new correct password"}),
        );
        change.cookie = Some(cookie.clone());
        change.csrf = Some(csrf["csrf_token"].as_str().unwrap().into());
        let old_runtime = fs::read(paths.runtime.join("sessions.json")).unwrap();
        FAIL_RUNTIME_RENAME.with(|flag| flag.set(true));
        let changed = handle_request(&paths, &change, 1001);
        FAIL_RUNTIME_RENAME.with(|flag| flag.set(false));
        assert_eq!(changed.status, 500);
        assert_eq!(
            fs::read(paths.runtime.join("sessions.json")).unwrap(),
            old_runtime
        );
        let data = durable(&paths.data).unwrap();
        assert!(verify(
            "new correct password",
            data.admin_hash.as_deref().unwrap()
        ));
        assert_eq!(data.auth_epoch, 2);
        let mut get = request("/config", json!({}));
        get.method = "GET".into();
        get.body.clear();
        get.content_length = Some("0".into());
        get.cookie = Some(cookie);
        assert_eq!(handle_request(&paths, &get, 1002).status, 401);
        fs::remove_dir_all(root).unwrap();
    }
}
