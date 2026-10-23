# 0.2 management contract

Scope: writable persistent ext4 data volume, first-use administrator enrollment, HTTPS login/session protection, compact Traditional Chinese Web UI, real restart/browser/negative-access tests. Preserve old 0.1 artifacts. No production release or host networking modifications.

Ownership: core worker owns new src/web.rs (and its submodules), tests/web.rs; UI worker owns web/index.html, web/app.js, web/style.css; integrator owns lib/config changes, CLI wiring, manifests, image, lab and docs. Authors use existing separate worktrees. Reviewer checks concrete candidate once.

Storage: explicit kernel routertop.datadev=/dev/vda1 (or unique label ROUTERTOP_DATA fallback), ext4 mounted /data rw,nosuid,nodev,noexec. No automatic disk formatting. /data/routertop is persistent state owned by unprivileged routertop UID 1000; /run/routertop/web is volatile sessions/control, same UID. /data/tls contains TLS material root only. No volume -> management unavailable, basic router still boots, no claim of persistence. Corrupt/missing durable state must not silently reset existing administrator.

Rust module API: web::initialize_store(data:&Path, default_config:&str)->Result<(),String>; web::stored_config(data:&Path)->Result<String,String>; web::bootstrap_token(data:&Path)->Result<String,String>; web::run_cgi()->Result<(),String>. Main wires storage-init DATA CONFIG, stored-config DATA, bootstrap-token [default /data/routertop], and cgi dispatch from argv0 ending routertop.cgi. CGI env ROUTERTOP_DATA_DIR default /data/routertop, ROUTERTOP_RUNTIME_DIR default /run/routertop/web, ROUTERTOP_ACTIVE_CONFIG default /etc/routertop/routertop.toml. Methods and headers strictly validated; no shell execution. HTTPS-only Cookie HttpOnly;Secure;SameSite=Strict;Path=/. Session expiry + logout/reboot invalidation + CSRF X-CSRF-Token + strict Origin equals https://HTTP_HOST on mutating requests. JSON <=32KiB; password 12..128 bytes; admin only; Argon2id; crypto random tokens; shared-process file lock; bounded global login throttle. Atomic write+file fsync+rename+parent fsync for persistent config and credential state; optimistic revision on configuration saves. No plaintext password persistence.

API URL /cgi-bin/routertop.cgi with PATH_INFO suffix:
GET /session -> {setup_required,authenticated,csrf_token?};
POST /setup {token,password} -> authenticated session + csrf_token;
POST /login {username:"admin",password} -> authenticated session + csrf_token;
POST /logout {} -> revoke cookie;
GET /status -> {hostname,uptime_seconds,memory_total_kib,memory_available_kib,persistent:true,pending_reboot,version};
GET /config -> {config:<Config>,revision:<u64>,pending_reboot};
POST /config {config:<Config>,revision:<u64>} -> {revision,pending_reboot:true};
POST /password {current_password,new_password} -> invalidate all sessions (login again);
POST /reboot {} -> write fixed reboot.request to runtime dir, root supervisor handles only this action.
Errors JSON {error:<user-facing string>}, status 400/401/403/409/413/429/500; sensitive responses no-store. First setup token retrieved at physical console, never embedded in HTML or unauthenticated API. Token invalidated on first successful setup. Configuration applies at reboot; UI explicitly distinguishes saved/pending from active and confirms reboot.

Config current fields: hostname; wan.interface; lan.interface/address; dhcp.start/end/lease_hours; dns.upstream; firewall.ssh_port (optional); routes[] {destination,gateway}. Integrator adds firewall.https_port optional, default sample443. UI edits core fields, preserves unknown supported fields such as static routes. No frontend framework/CDN/tracker. TLS via lighttpd+mod_openssl, unprivileged CGI, bind LAN IP only, LAN firewall HTTPS permit. Existing physical local recovery console remains physical-trust scoped.

Acceptance: unit/concurrency/negative HTTP tests; TLS server with real requests; browser setup/login/save/logout/password change; poweroff/reboot same data disk retains account/settings/cert; sessions invalid after reboot; diskless/corrupt state behavior; networking regression; same-size comparison. Unexecuted areas explicitly NOT_RUN.
