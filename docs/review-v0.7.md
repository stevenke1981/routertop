# RouterTop 0.7 independent scoped review

Reviewer instance: `/root/wan_review`, independent of the authors. Base: `a698bdce2952c99da9e4ff0f7515df138afe7630`. Candidate is uncommitted source identified below by normalized-LF SHA256, not a fictitious tested commit. One scoped pass, followed by focused closure of the concrete finding and separately requested, narrowly scoped reverse-path-filter and DHCPv6 client lifecycle runtime fix closures. Production sources were read-only to this reviewer; only this document was written in the review worktree.

## Result

**PASS — one P1 finding resolved; zero open confirmed findings.** This is a code review and focused compiler-output check, not Linux packet, image boot, production ISP or CI acceptance. Those layers are owned by the integrator/test agent.

Scope: static/dual-WAN validation, dedicated device-bound probe routing and terminal unreachable routes, client versus supervisor default-route ownership, hysteresis/failback/both-down behavior, finite forwarding authorization, primary-only IPv6/PD withdrawal and reactivation, dual PPP lifecycle/credential privacy, Web secret preservation and CLI export privilege selection.

## Finding and focused closure

**P1 — explicit firewall interface rules were silently expanded onto the other uplink.** Initial `lib.rs` dual-WAN expansion duplicated every nftables line containing the primary device. A configured input rule `id=primary-only-admin`, `in_interface=eth0`, TCP destination port 8443, action accept rendered both an eth0 accept and an eth2 accept with the same rule ID. Enabling backup therefore broadened an explicitly primary-only exposure.

Evidence: a temporary config based on the normal default, plus DHCP backup `eth2`, valid failover targets and the single rule above, was rendered with the author's debug executable. Initial render exit 0 produced two matching accept lines. No network or production configuration was changed by this reproduction.

The author now excludes the exact generated custom-input/custom-forward rule lines from automatic backup policy expansion. Generated NAT, forwarding policy and full-tunnel backup guards remain eligible. Focused rerender exit 0 produces exactly one matching rule, scoped to `eth0`. New regression `explicit_interface_firewall_rules_are_never_broadened_to_another_uplink` checks primary-only input accept and backup-only forward drop each appear once.

Reviewer reran `cargo test --locked --test wan` in `.worktrees/wan-core`: **8 passed, 0 failed, exit 0**. This is the focused closure; no repeated full-project review was performed.

## Additional scoped checks and boundaries

- Config validation rejects health targets throughout configured LAN/VLAN/WireGuard subnets and known static WAN router addresses. An actual CLI check of target `10.20.0.1` with configured VLAN `10.20.0.1/24` returned nonzero and the explicit local LAN/VLAN/WireGuard target diagnostic. Dynamic ownership checks inspect both logical uplinks before probing.
- CLI credential export selects the root guard when **any** configured uplink uses PPPoE, including DHCP/static primary plus PPPoE backup. The guard is Linux-specific by the existing contract; Windows execution does not prove Linux non-root denial. A Windows negative-check assumption was discarded after reading `require_local_root`. Non-root Linux execution remains an explicit runtime acceptance responsibility.
- Web GET clears both PPP password fields and returns independent presence flags. Blank saves preserve only unchanged mode/account/interface within the same slot; neither slot borrows the other's secret. Private PPP peer options use protected directories and files, with no credential arguments or rendered public-secret material.
- Actual route/kernel behavior, failure timings, PPP discovery/authentication, IPv6-prefix withdrawal, real browser persistence/reboot and exact artifact/remote/hosted-CI identity are **NOT_RUN by this reviewer** and must not be inferred from this review.

## Requested reverse-path-filter follow-up

The integrator's actual Linux packet experiment found that inherited strict `rp_filter=1` rejected probe replies before a main default route existed. Changing only the router namespace reverse-path setting restored the bound probe, primary selection and real LAN HTTP. This runtime evidence was reported by the integrator, not executed by this reviewer.

The production fix is limited to dual mode: rendered sysctl sets `all.rp_filter=0`, `default.rp_filter=0` and both existing physical WAN interface settings to zero. Linux combines all/per-interface policy; clearing only `all` would leave the existing interface's strict value active. Future ppp0/ppp1 inherit the default zero after creation; nonexistent PPP keys are intentionally not written before dialing. Slash-separated per-interface keys retain literal dots in interface names. Existing source/interface nftables policy remains installed; single-WAN rendering does not change rp_filter.

Focused source inspection confirms both boot and CLI boot-apply load the rendered sysctl **before** starting WAN clients, so new PPP interfaces receive the intended inherited value. Reviewer ran only the affected regression:

`cargo test --locked --test wan dual_probe_reverse_path_policy_covers_existing_underlays_and_future_ppp_only_in_dual_mode`

**PASS: 1 passed, 0 failed, 8 filtered out; exit 0.** No repeated whole-project review. Actual final Linux matrix with the production-rendered sysctl, without manual overrides, remains the test owner's gate.

## Requested r4 DHCPv6 client lifecycle follow-up

The test owner reported a causal Alpine dhcpcd 10.5.2 experiment: with an empty private `/run`, `dhcpcd -6 -x` starts a default-config daemon instead of merely stopping a client, then blocks until the external timeout. In mixed PPPoE-primary/DHCP-backup boot, initial backup selection reached this stop path before any primary IPv6 client existed. The unintended master then prevented the later dedicated client configuration from taking effect. This is a runtime P1 found by packet testing, not an additional whole-project review finding.

Focused r4 closure inspects only the replacement client lifecycle and its call sites in `wan.rs` / `pppoe.rs`:

- Stop reads `/run/dhcpcd/pid`; absent or stale process identity returns without launching **any** command. The unsafe `dhcpcd -x` invocation is removed from the production stop paths.
- A live PID must exceed 1, differ from the caller, resolve to executable basename `dhcpcd`, and have a readable network-namespace identity equal to the current router. Errors do not count as a namespace match. This verifies executable and namespace; it does not claim to verify the process's `-f` command-line argument.
- Verified stop sends bounded TERM through the BusyBox kill applet, then waits at most 100 × 20 ms for exit. Start uses an eight-second command timeout and a two-second readiness wait. Failures propagate to the existing fail-closed WAN path; primary reconciliation retries startup rather than trying it only on an active-role transition.
- Both start and stop take the same `pd/client.lock`. Dual-WAN startup rechecks the primary role **after** acquiring that lock, so a queued PPP IPv6CP hook cannot restart a client after backup selection completed. The legacy single-PPP caller uses the same stop safety fix without applying the dual-only role requirement.
- IPv6 withdrawal is attempted even if stopping the client reports failure, and existing nft/PD active-role gates remain the forwarding boundary.

Reviewer ran exactly the affected regression:

`cargo test --locked --lib stopping_absent_or_stale_ipv6_client_never_runs_a_command`

**PASS: 1 passed, 0 failed, 11 filtered out; exit 0.** The absent/stale cases inject signal closures that panic if called, proving those paths do not issue a command. This is code/test closure only. The final r4 real-kernel mixed-protocol matrix, fresh image/browser lifecycle, reboot and hosted CI remain separate integrator/test-owner gates, and are **NOT_RUN by this reviewer**.

## Reviewed input hashes

Normalized LF source bytes; lib.rs and tests/wan.rs identify the reverse-path-filter closure, wan.rs and pppoe.rs identify the r4 client lifecycle closure, and remaining hashes identify the original scoped pass:

```json
{
  "crates/routertop/src/lib.rs": "4f00c1d5ffe912f9fca9090a0ceab7fe71179ad897de624128a1315471d18329",
  "crates/routertop/src/main.rs": "31410c7a56035699dd9a151af7b569a5a97c6ef0b8b7d41044a5682b0923a490",
  "crates/routertop/src/network.rs": "1a5b1d59231537810cf980b4dd13cd568f212b6665ed3c15ef25973a91c81865",
  "crates/routertop/src/pd.rs": "1017e5525cdb7171fd1857e1558da0d506e890dc9bf53af876ffd9d8b215dd04",
  "crates/routertop/src/pppoe.rs": "c2228394c0be11f4767496bd52218436d802ed5fca15114912c5fff1c6c2eacd",
  "crates/routertop/src/wan.rs": "719dba328a0429599c401cb37471726d3545a183c4f598334e2f4bb8e24e829b",
  "crates/routertop/tests/wan.rs": "8e8c6d0167907ee65b5c03326b6290f7895cda18cf0ee711485e60791a760c0a",
  "crates/routertop/src/web.rs": "a957aa708a13221fbd406d9230e7673917d8108f02f93f8d4089b05f096a8ead",
  "web/app.js": "5f9830238c663b1df1af00f7d800b49cb570082aaf0c85abf3a0a575c1ba1ffc",
  "web/index.html": "da0b40ba2a643a7e9ddd36dfb15ea1fc3303b330ff20e3c081705f04a81c7c12"
}
```

Any later production changes require the integrator to decide whether affected focused validation is needed. No authoring, commit, push, deployment or permissions/provider changes were performed by this reviewer.
