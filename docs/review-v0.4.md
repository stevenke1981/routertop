# RouterTop 0.4 independent scoped review

Task: `routertop-v0.4-review`; reviewer actor `/root/review`; next owner `/root` (integrator). Reviewed on 2026-10-24 against base/head commit `7af518d6f2138b0a0dd27c64066dbd7e3f954306` plus the uncommitted 0.4 candidate. Reviewer is not an author of product changes. Only this report is reviewer-owned.

Acceptance source: `docs/network-v0.4-contract.md` (SHA256 `354937761CF73D46B1AAD4C5909A75302E6CBD71D8AA99FD82C92AE6C2F88B5C`). Scope: IPv6 validation/rendering, full-tunnel routing and kill switch, console authentication/failure paths, shared durable ownership, Web integration, and boot integration. No unrelated whole-project review; no VM, external writes, or publication.

## Finding

**R04-01 — P2, RESOLVED: Web accepted passwords that the new console cannot enter.**

`crates/routertop/src/web.rs:379-380` accepts any password of 12–128 bytes. Both HTTP enrollment and password change use that validator (`web.rs:661`, `web.rs:787`). In contrast, `crates/routertop/src/console.rs:67-70` terminates input at newline and rejects all ASCII control bytes. A valid Web password containing a tab therefore cannot authenticate through the mandatory console prompt, even though the underlying shared hash matches. Terminal canonical processing also consumes certain other control characters. This violates the shared usable password contract and can deny local recovery to an existing account; it is not an authentication bypass.

Evidence is the deterministic mismatch in the original two input paths, not a claimed TTY execution. The integrator fixed `web.rs:380` to reject ASCII control bytes; the shared validator covers HTTP setup, password change, and console enrollment. `web/app.js:91` rejects the same range. `tests/web.rs` adds TAB/DEL rejection to `strict_content_length_content_type_and_password_boundaries`. A focused independent source recheck confirms the fix. Integrator reports 21 focused Windows tests PASS; reviewer did not rerun them. Pre-existing passwords containing controls must be changed through Web; documentation of that migration limitation remains the integrator's delivery responsibility.

```json
{"findings":[{"id":"R04-01","priority":"P2","status":"RESOLVED","file":"crates/routertop/src/console.rs","line":69,"related":"crates/routertop/src/web.rs:380","kind":"shared-password-input-compatibility","evidence":"shared validator and UI reject ASCII controls; regression assertions inspected","runtime_reproduction":"NOT_RUN"}]}
```

## Scoped checks and boundaries

- PASS (static): IPv6 strings are parsed/canonicalized before interpolation; LAN/VLAN /64 and WG prefix/MTU constraints, overlap checks, full-tunnel cardinality/default-route restrictions, and firewall address-family matching have explicit rejection paths.
- PASS (static): full-tunnel main-table nondefault lookup precedes the separate default table; WG transport marks are assigned before link-up; all configured WG sockets receive the reserved mark. Direct-WAN forward drops precede established/custom accepts. IPv4-only full mode blocks IPv6 forwarding. WAN output ends in a drop after the narrow transport/DHCP/ND exceptions. NAT66 is explicit.
- PASS (static): ND input is hop-limit constrained; LAN router solicitation and own-address DNS/echo permissions are rendered separately. RA defaults are suppressed for isolated/V4-only-full IPv6 subnets. Packet behavior remains NOT_RUN by this reviewer.
- PASS (static): console refuses non-Linux/non-TTY/non-root invocation, consults current persisted credentials on each attempt, writes throttle state before returning Accepted, and has no shell branch on absent/corrupt state or failed authentication. Both init TTY entries point to the console wrapper, not a bare shell.
- PASS (static): atomic durable replacements retain the existing file owner, falling back to the parent owner for new files; boot initializes and recursively assigns persisted state to UID/GID 1000 before console startup. Console runtime is separate and root-owned. Actual UID1000/TTY behavior remains NOT_RUN by this reviewer.
- PASS (static): IPv6, WG full-tunnel/NAT66, and firewall family fields travel through populate/editor/save paths; credential forms use POST. This is not browser rendering, keyboard, or mobile proof.
- PASS (static): boot/apply failure paths disable IPv4 and IPv6 forwarding. Known Linux `chown` compile issue is already changed to `std::os::unix::fs::chown`; no duplicate finding raised.
- PASS: read-only PowerShell source/diff inspection and `git diff --check` completed with exit code 0 (line-ending warnings only). Odin `project_analysis` explicitly bound to `ws_7eccb743b075c34e255f096273a38d0dd35fc1bd370bd2b8` confirmed `E:\routertop`; its structural analysis reports tests/semantic inspections NOT_RUN and is not build evidence.
- NOT_RUN by reviewer: Cargo tests/clippy, Alpine build, namespace/real packet forwarding, WG handshake and deletion kill-switch behavior, IPv6 RA/ND traffic, actual TTY controls, browser CRUD/reboot/UI, BIOS/UEFI/RAM, artifact size and hosted CI. Integrator owns these independent acceptance results.

Review disposition: **PASS for this scoped static review after the focused R04-01 fix recheck; no open evidenced finding.** Runtime acceptance is NOT_RUN here, not approved by static inspection. Integrator follow-up: the shared-password migration limitation is now documented in README, architecture and image instructions. No broad review was repeated.

## Reviewed source snapshot (SHA256)

| Path | SHA256 |
| --- | --- |
| `crates/routertop/src/ipv6.rs` | `EB4548A1A9B02D5A09576816B9CF0E5877498FA368C1E18CCEE7EFFA405D9CF4` |
| `crates/routertop/src/network.rs` | `E1D939EF35931260E1085D4D0BE4BAFBA52AD40D3AEB83AC631FC924C68CF49C` |
| `crates/routertop/src/lib.rs` | `CD131638C5198E5957508BF0596A5C72DD0A128774A74A7F19047A53D39B7F93` |
| `crates/routertop/src/main.rs` | `7185728D64ED96A4139D2A15A33C43F2FED93DB0BF5944AF65FC586EE30EA7CB` |
| `crates/routertop/src/console.rs` | `6791DB9F3591A8B22D3606BF8B00B855CE278DCFC8F786CB3F95911EA3F72866` |
| `crates/routertop/src/web.rs` (focused fix recheck) | `52FDD8A5DDF0532F689C6D3CC459BCFD2AC011E81ABF39CA7CA70272FBEF5A1A` |
| `crates/routertop/tests/web.rs` (focused fix recheck) | `F40DC3A44F32AB158B9D487A4F64E344FD998D3B509CAC4CE1F6D6A161AB212F` |
| `web/app.js` (focused fix recheck) | `66093B2BF38EBB037BDE388CF6F16C79D611DFFF6E5C4EF3E025A60C58C2B7CD` |
| `web/index.html` | `1E4F9B52718B82CFE8C7B4E50A050BEEB3C840E42110771E8D49134106389D15` |
| `web/style.css` | `35FCD600FF45B44BA9B809ED80DCD4445E1557A128F4BB4727E1AADB7F42234F` |
| `image/overlay/etc/inittab` | `15EC397BC9EF7D1BDD7A08F319C1893A444B8140BEBB1189CE72BB67D6611EAC` |
| `image/overlay/usr/sbin/routertop-boot` | `FED777F75885C28111D1E8F10904F27D0087C3C2E323A468B6B894F0C2BD32C7` |
| `image/overlay/usr/sbin/routertop-console` | `2BE22802536840A2872FB765F26116EA4DF4AD50A8471B1A1CC38836D4D890ED` |
