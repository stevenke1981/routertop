# RouterTop 0.8 scoped independent review

Result: **PASS for the static scope below; runtime acceptance is NOT_RUN by this reviewer.** No unresolved actionable finding remains in the reviewed candidate. This is one independent pass with focused closure of V08-R1 and the later, actual-ISO V08-R2 regression, not a full-project review or an approval of the image, public release, or CI.

Task `v08_review`, actor `/root/v08_review`, receiver `/root`. Author instances are `/root/v08_core` and `/root/v08_web`; the reviewer did not modify their production files. Reviewer write scope is this document in `.worktrees/v08-review`, branch `codex/v08-review`. This role restriction is not an OS read-only sandbox. Base and current worktree HEAD are `fcc8c02b742ffeac4531423f78be82cd098c4966`; candidate changes are uncommitted and are identified by the source hashes below. No commit, push, or external publication was performed by this reviewer.

Inputs: root `docs/plan-v0.8.md` and frozen `docs/network-v0.8-contract.md`; core R2 candidate in `.worktrees/v08-core`; Web candidate in `.worktrees/v08-web`. Relevant acceptance IDs are AC1, AC3 and AC6; AC2/AC4/AC5 require other owners' evidence.

## Finding and focused closure

**V08-R1, P1 — serialize and epoch-check monitor error cleanup. CLOSED.** The first inspected monitor captured an origin epoch but performed its error cleanup without the PD state lock or a current-epoch comparison. An old reconciliation could fail, a concurrent selection could install the replacement generation, and the old error branch could then clear replacement authorization/DNS/RA, deprecate replacement delegated addresses, and publish old-generation status. This conclusion follows the actual `monitor → reconcile_once` and `provider::select` lock/mutation paths; it is not a claim of a reproduced Linux packet failure.

The author added the PD lock around error cleanup, compares `provider::read(dir).ok()` with the captured origin whenever active/standby is enabled, and clears `auto_sources` along with the other authorization sets. The enabled-policy comparison also covers a missing/failed initial epoch read: an unknown old origin cannot clear a subsequently installed valid epoch. Focused source inspection confirmed these changes in final `pd.rs`, LF-normalized SHA256 `8181c16c340be058fb3bfcf234520afbe78e5948e7ac71979dcf71a66a762d78`. No second broad review was started.

**V08-R2 — actual-ISO CGI cannot read the private provider epoch. Static closure PASS; replacement runtime validation remains separately owned.** On 2026-10-25 the root owner requested a focused check of only the R3 `wan.rs` change. The preserved actual-appliance browser report `.cache/v08/browser-attempt1/browser-v08-report.json` is **FAIL**, after seven recorded PASS checks, at `initial backup-only boot with backup IPv6/PD`. The non-secret ISP snapshot `.cache/v08/isp-browser-attempt1-status.json` records backup DHCPv6 reply 29 / renew 28. Root reported that CGI UID 1000 attempted the private 0600 `provider.json` read, producing null WAN readiness despite the acquired delegation. These old runtime results are preserved, not relabeled as a pass.

The R3 privileged WAN step now reads the private epoch and publishes only `ipv6_generation` after the epoch provider/logical interface matches the selected provider/device. The CGI path `read_status → ipv6_status → ipv6_status_at → ipv6_status_from_public` uses the public WAN snapshot plus freshness-filtered public PD status and performs no private epoch read. Its readiness condition requires selected WAN connected state, physical and logical device agreement with configuration, a present numeric generation equal to the PD generation, bound PD state/phase, and matching PD provider/logical interface. Missing, corrupt or older-than-ten-second PD status becomes null through the existing `status_at` filter; mismatched snapshots return false/null. The projection adds no boot identity, incarnation, token, DUID or credentials; private file permissions and readers were not widened.

Focused inspection also read the two added unit tests: they cover all four DHCP/PPPoE combinations for both selected slots and reject generation/provider/device/state/phase mismatches, absent generation and null PD. Their execution results were reported by core/root and were not rerun by this reviewer. Exact inspected R3 root `crates/routertop/src/wan.rs` LF-normalized SHA256 is `2b9652e3efd20d68b68fdbf91c55301b57d545f7de9093673f48acd57db0944c`; fingerprint collection and `git diff --check -- crates/routertop/src/wan.rs` each exited **0**. This closes the permission/public-projection defect at source level only. Actual UID 1000 regression execution and the replacement ISO/browser run remain **NOT_RUN by this reviewer**, with test/root owners responsible for their evidence. No other production scope was reopened.

## Static conclusions and limits

| Invariant inspected | Static result and evidence |
|---|---|
| Provider origin and ABA rejection | PASS: immutable per-generation client hook captures boot/generation/slot/interface/incarnation; PD event and successful reconciliation compare captured epoch under the PD lock. PPP hooks capture pppd PID/start identity at origin; per-slot owner/session checks reject an older owner's down event. |
| Lifecycle lock ordering | PASS: WAN step/event serialization precedes selection; selection invalidates under PD lock and releases it before waiting for verified client stop/start. Client and state lock attempts and process waits are bounded. No bare `dhcpcd -x` appears in the lifecycle. |
| Withdrawal before activation | PASS: selection records inactive epoch and empties authorization/DNS/RA before stopping the client; retains status/owned-address inventory until address/default withdrawal; initializes and starts replacement only afterward. Selection preserves unrelated management/WireGuard interfaces. |
| Standby isolation | PASS: only selected logical interface gets a client config and `auto_wan` authorization. Both PPP links negotiate IPv6CP, with automatic pppd IPv6 defaults disabled. Kernel RA/autoconf remains disabled; stale DHCPv6/RA/DNS hook ownership is checked. Actual packets/routes/DNS are NOT_RUN here. |
| Both-WAN firewall and retired sources | PASS: generated IPv6 policy expands to both logical WANs; user rules are rendered separately and excluded from later generic backup expansion. Provider/PD guards precede conntrack and custom forwarding accepts; delegated LAN/VLAN source sets retire old sources. Router output has current-interface/current-source gates; WireGuard full-tunnel drops remain in the expanded generated policy. Actual nft/conntrack packet behavior is NOT_RUN here. |
| Persistent slot identities | PASS: primary retains the old identity path; backup uses sibling `backup-duid`. Identities have private permissions, are validated, and corruption refuses regeneration. Runtime epochs/leases initialize closed. Actual reboot/cold boot persistence is NOT_RUN here. |
| Web opt-in preservation | PASS: model defaults to primary-only; backend preserves an existing opt-in when a legacy client omits the new field, while explicit opt-out remains available. UI serializes opt-in only with dual WAN + automatic mode + PD and displays provider/phase. Existing per-slot password preservation remains called after policy handling. Browser, save/reboot and credential runtime checks are NOT_RUN here. |
| One monitor/client | PASS for inspected launch path: one boot invocation of `routertop-ipv6-start` launches one monitor; verified same-netns dhcpcd identity/lifecycle checks serialize one client. Duplicate arbitrary manual monitor invocations are not prevented by a lifetime monitor lock; no normal-path duplicate was established. Actual process-count acceptance belongs to the Linux lab. |

## Checks and evidence

Platform: Windows / PowerShell. Read-only source, diff and call-path inspection completed. `git diff --check` in each author worktree exited **0**, with line-ending notices only. `git rev-parse HEAD` in each author worktree exited **0** and returned the base SHA above. Source fingerprint collection using .NET SHA256 over UTF-8 text with CRLF normalized to LF exited **0**. These are static checks, not compiler or test execution.

Reviewer compilation, unit tests, live Linux packets, final image/browser checks, cold boot, performance, public remote verification and hosted CI: **NOT_RUN**. Root/core/Web/network owners retain their separate checks and logs; this document does not upgrade their status. Reviewer Odin inventory call aborted before dispatch and supplied no navigation or diagnostic evidence; root's separate Odin work must be cited independently. No model, reasoning setting, provider, MCP configuration or permission was changed by this reviewer.

## Reviewed content fingerprints

SHA256 is LF-normalized UTF-8 content, permitting comparison with Linux copies. Core rows are the frozen R2 candidate after V08-R1 closure, except `wan.rs`, which is updated to the focused R3 closure above. Web rows identify the original inspected source snapshot; later Web formatting/integration changes are outside this focused R3 check.

| Owner | Repository-relative file | SHA256 |
|---|---|---|
| core | `crates/routertop/src/provider.rs` | `b356bcdf3150a8e3fdd765ea312de1c2327bb2cdeeb0280610e63c4e2d6d1d98` |
| core R3 | `crates/routertop/src/wan.rs` | `2b9652e3efd20d68b68fdbf91c55301b57d545f7de9093673f48acd57db0944c` |
| core | `crates/routertop/src/pd.rs` | `8181c16c340be058fb3bfcf234520afbe78e5948e7ac71979dcf71a66a762d78` |
| core | `crates/routertop/src/ipv6.rs` | `c2df414ad3e862c90a565e51ade14e55a6a6367c6b2abab03214a58ad444bd4b` |
| core | `crates/routertop/src/lib.rs` | `dc9f0b22f3bc79f9296bb41882a95dc1a9bd969b0325b4cad90cce8117766b7b` |
| core | `crates/routertop/src/main.rs` | `0b231b6a655057da82fd1ed9e38865ab3e1e5ceef1080bb32f2196bb1d145ca9` |
| core | `crates/routertop/tests/provider.rs` | `1ce966b20fe924b1cb7bf6d8f93862a049b2f9238e53ba942aaff45c5ab2ef46` |
| core | `crates/routertop/tests/ipv6.rs` | `96877c202258c15bc938ece11b83a3b738e8f4d4a152cdc88922b6b6ff000c29` |
| core | `image/overlay/usr/sbin/routertop-ppp-ip-down` | `8acc22606c484137dbe3a09d007e2a2d03fa4ac79388098d15620826a4568797` |
| core | `image/overlay/usr/sbin/routertop-ppp-ip-up` | `6b68cbc0d0e8071b340e968c85bf3cb57c46b725a9ee733062acbff3fbce2f7e` |
| core | `image/overlay/usr/sbin/routertop-ppp-ipv6-down` | `e6701ddd1e28aa359a44ac801eefcb7efa6c72b7a505d5fcac1abd967de900e4` |
| core | `image/overlay/usr/sbin/routertop-ppp-ipv6-up` | `8fd1d43ef8fcf95ada6ed07863464378ab22a0524e801b901e85b214b04b977b` |
| web | `crates/routertop/src/web.rs` | `995cb990ecf5102f550af92615d4dd65847ffa991f9fc532760fce89f87bc79d` |
| web | `crates/routertop/tests/web.rs` | `2d7939de0c6e7b843c727d8b2d78c7f699af9932938637c8a7a3800436715067` |
| web | `web/app.js` | `a184abe76ff31ffd622b9518ba447264d27dfc6a198f11e89573e8d5a7fda356` |
| web | `web/index.html` | `17081091a4851fffa4a979f4172e2aef0702f859b584707228db43bce6034889` |

Handoff findings payload (embedded to honor the single-document write scope):

```json
{
  "task_id": "v08_review",
  "revision": "R3-V08-R2-focused-closure",
  "actor_instance": "/root/v08_review",
  "receiver_instance": "/root",
  "base_sha": "fcc8c02b742ffeac4531423f78be82cd098c4966",
  "head_sha": "uncommitted-content-bound-by-table",
  "result": "PASS",
  "scope": "static provider-generation/lifecycle/policy and Web opt-in preservation",
  "acceptance_ids": ["AC1", "AC3", "AC6"],
  "open_findings": [],
  "closed_findings": ["V08-R1", "V08-R2-static-closure"],
  "runtime_result": "NOT_RUN",
  "external_side_effects": {"performed": false},
  "next_action": "Root verifies integrated source hashes and retains separate Linux/image/browser/remote evidence."
}
```
