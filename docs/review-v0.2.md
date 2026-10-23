# RouterTop 0.2 independent scoped review

Date: 2026-10-24 (Asia/Taipei). Task: management-0.2-review. Reviewer actor: `/root/review`, independent from implementation actors `/root`, `/root/core`, `/root/image`. Next owner: `/root` (integration and VM acceptance).

Verdict: **PASS for the scoped static review and targeted fix verification. No open demonstrated blocker in the reviewed candidate.** This is not a runtime, production-security, or full-product approval.

Input: `docs/management-contract.md`; new authentication/persistence/management code and image integration. Repository has no HEAD yet: `git rev-parse --verify HEAD` returned exit 1. Base/head commit SHA: N/A (initial uncommitted repository); candidate bound by SHA256 below. Review ownership was read-only; only this new report was authorized for writing. No VM serial, host networking, runtime mutations, or reviewed source edits were performed by reviewer.

## Findings and targeted verification

| ID | Status | Trigger and impact | Verified resolution |
|---|---|---|---|
| R02-01 | RESOLVED | `scripts/boot-qemu.ps1` supplied `-no-reboot`; authenticated reboot would terminate QEMU instead of restarting with its data disk. | The launcher no longer supplies `-no-reboot`. |
| R02-02 | RESOLVED | `web/index.html` setup/login forms omitted a method. If JavaScript failed or was disabled, browser-native GET submission would put named password/enrollment fields into the URL and history. | Setup, login and password forms explicitly specify `method="post"` (lines 27, 37, 95). |
| R02-03 | RESOLVED | `routertop-storage` used umask 077 when replacing the active config. Root-owned mode 0600 prevented CGI UID 1000 from reading the active config, making `pending_reboot` permanently true. | `image/overlay/usr/sbin/routertop-storage:28` applies mode 0644 to the non-secret active configuration before rename. Account/password state remains in the private store. |

Reviewed authentication behavior: no default password; console-retrieved random enrollment token is absent from unauthenticated session responses and static UI; successful enrollment removes it. Credentials use Argon2id. Mutating requests require matching HTTPS Origin; authenticated mutations additionally require session CSRF. Cookies are Secure, HttpOnly and SameSite=Strict. One file lock serializes durable state, throttle and session decisions across CGI processes. Config revision rejects concurrent stale writes.

Reviewed persistence behavior: durable config and account state share one atomic write/file-fsync/rename/parent-fsync bundle. Corrupt or missing initialized state is rejected rather than silently re-enrolled. The final password-change delta writes a new credential and auth_epoch atomically; session matching requires the current epoch. Failure to replace the volatile sessions file after the durable password change therefore cannot preserve an old authenticated session. Source and the new portable/Windows fault-injection tests were inspected; reviewer did not rerun them.

Reviewed privilege boundaries: HTTPS listens on the configured LAN address; lighttpd drops to routertop user/group for CGI. TLS storage is private to root. Log parent directory is root-owned, with only precreated log files writable by UID 1000. The root supervisor observes a fixed reboot request path and executes a fixed reboot action; no request-controlled command is evaluated. Data volume mounting is explicit or uses the unique deliberate label, and the image does not autoformat a disk. Diskless mode does not enable management. No broader review of unrelated 0.1 features was conducted.

## Evidence and limits

- **PASS (reviewer executed):** PowerShell `Get-Content`, scoped `rg`, `git diff --no-index`, and `Get-FileHash` inspection in `E:\routertop`. Final targeted read/hash command exit 0. Diffs and exact source control flow support the findings above.
- **PASS (author-reported, not independently rerun):** core worker reported 14 Windows integration tests, portable password-epoch fault injection, real Windows runtime-rename failure, cross-process/cross-thread revision races and clippy. Integrator reported final 24 Windows tests plus fmt/clippy. These attestations do not substitute for recorded Linux/runtime acceptance.
- **NOT_RUN by reviewer:** Linux CGI/TLS server, browser enrollment/login/save/logout/password change, same-disk reboot retention, certificate retention, UID 1000 active-config readability, pending=false after reboot, diskless/corrupt-state boot, networking regression, and CI.
- Integrator should bind runtime evidence to the final built artifact and explicitly verify the active snapshot is readable by UID 1000 and pending_reboot becomes false after reboot. This report does not claim those checks passed.

## Reviewed candidate SHA256

| Path | SHA256 |
|---|---|
| `crates/routertop/src/web.rs` | `BC4F3FF594524E9668710E7DE4E57F8F98BA69A92ECA61A4CD11F00FE6B40113` |
| `crates/routertop/tests/web.rs` | `CB731A296129E2DDC99D22A155B49A5A7439B685AF89629A88DD24F3F7C1DFC6` |
| `crates/routertop/src/main.rs` | `3421B1463752C6DC33D76252E7B3FC2C5945B1734E49088020CA7A6E8826DD0E` |
| `web/index.html` | `958D37843643DBAF74BC52AB613794236D9B6DCE3CEF5802B520474156116602` |
| `web/app.js` | `29A6C5D1A65812F566AA38921F3DAA5871A94F0B6C18CB1421DC34FACBCB94E2` |
| `image/overlay/usr/sbin/routertop-storage` | `123C6415B837CA1C0015D84583891312D9B570AA0F9D168CD2EA207F523720FC` |
| `image/overlay/usr/sbin/routertop-management` | `D8183AAAE536193F4265B33D134CA0741B63A680C553E5ABCB794680D0212D45` |
| `image/overlay/usr/sbin/routertop-web-supervisor` | `A19903ED54F1DAF3DADBAAD7F83417BB3BF26FE07E5470541CB9901D1223E00E` |
| `scripts/boot-qemu.ps1` | `0AA110C6355BDCE5BDC49EBBB5631956E3214FB302D0C67F3413FBDD2ED17821` |

External publication/deployment: N/A; none requested or performed by reviewer. Remaining runtime acceptance owner: `/root`.
