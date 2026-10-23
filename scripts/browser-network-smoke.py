#!/usr/bin/env python3
"""Real Chrome UI acceptance for VLAN/WireGuard/firewall on a fresh local lab VM.

Mutates only the explicitly addressed loopback VM, enrolls an administrator and
reboots it. Credentials remain in memory; no HAR, trace, browser profile or raw
serial transcript is saved. Actual packet/handshake tests are separate.
"""
from __future__ import annotations

import argparse
import base64
import copy
import importlib.util
import json
import re
import secrets
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


spec = importlib.util.spec_from_file_location("routertop_browser_smoke", Path(__file__).with_name("browser-smoke.py"))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
API = lab.API
check = lab.check
# Public-only fixtures, not stored/generated private keys or real peers.
PEER_PUBLIC = base64.b64encode(bytes(range(1, 33))).decode("ascii")
TEMP_PUBLIC = base64.b64encode(bytes(range(33, 65))).decode("ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="https://127.0.0.1:19443")
    parser.add_argument("--serial-port", type=int, default=19410)
    parser.add_argument("--output", type=Path, default=Path("evidence/v03/browser"))
    parser.add_argument("--chrome", required=True)
    parser.add_argument("--reboot-timeout", type=int, default=180)
    parser.add_argument("--headed", action="store_true")
    args = parser.parse_args()
    args.url = args.url.rstrip("/")
    parsed = urllib.parse.urlsplit(args.url)
    check(parsed.scheme == "https" and parsed.hostname in {"127.0.0.1", "localhost"}, "Only loopback HTTPS test VMs are allowed")
    check(not parsed.path and not parsed.query and not parsed.fragment, "Supply a bare origin URL")
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"result": "RUNNING", "url": args.url, "started_utc": datetime.now(timezone.utc).isoformat(),
              "checks": [], "screenshots": [], "packet_handshake_testing": "NOT_RUN by UI harness"}
    sensitive: list[str] = []
    stage = "fresh lab enrollment"
    started = time.monotonic()

    def secret(value: str) -> str:
        sensitive.append(value)
        return value

    def sanitize(error: object) -> str:
        value = str(error)
        for item in sorted(sensitive, key=len, reverse=True):
            value = value.replace(item, "[REDACTED_SECRET]")
        return re.sub(r"\b[0-9a-fA-F]{64}\b", "[REDACTED_TOKEN]", value)

    def passed(name: str, **details) -> None:
        report["checks"].append({"name": name, "result": "PASS", **details})
        print("PASS " + name, flush=True)

    def no_private_fields(data) -> None:
        if isinstance(data, dict):
            check(not {"private_key", "private_keys", "wireguard_keys"}.intersection(data), "Private-key field exposed in API response")
            for value in data.values():
                no_private_fields(value)
        elif isinstance(data, list):
            for value in data:
                no_private_fields(value)

    try:
        check(lab.public_session(args.url).get("setup_required") is True, "Fresh VM required; existing administrator will not be reset")
        fingerprint = lab.certificate_fingerprint(args.url)
        password = secret("Rt03-" + secrets.token_urlsafe(24))
        token = secret(lab.enrollment_token(args.serial_port))
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=args.chrome, headless=not args.headed)
            context = browser.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 1000}, locale="zh-TW")
            context.set_default_timeout(60000)
            page = context.new_page()
            runtime_errors: list[str] = []
            page.on("pageerror", lambda error: runtime_errors.append(sanitize(error)))

            def post_response(path):
                return page.expect_response(lambda response: response.url == args.url + API + path and response.request.method == "POST", timeout=65000)

            def get(path):
                response = context.request.get(args.url + API + path, timeout=30000)
                check(response.status == 200, f"GET {path}: HTTP {response.status}")
                data = response.json()
                no_private_fields(data)
                return data

            def navigate(panel):
                page.locator(f'.nav-item[data-panel="{panel}"]').click()
                expect(page.locator(f"#panel-{panel}")).to_be_visible()

            def fill(name, value):
                page.locator("#edit-" + name).fill(str(value))

            def select(name, value):
                page.locator("#edit-" + name).select_option(value)

            def apply_editor():
                page.locator("#editor-apply").click()
                expect(page.locator("#editor-dialog")).not_to_be_visible()

            def save(panel):
                with post_response("/config") as pending:
                    page.locator(f"#panel-{panel} .advanced-save").click()
                check(pending.value.status == 200, f"{panel} save failed: HTTP {pending.value.status}")
                expect(page.locator(f"#panel-{panel} .advanced-save")).to_be_enabled()
                expect(page.locator("#global-error")).to_be_hidden()
                return get("/config")

            def delete(locator):
                page.once("dialog", lambda dialog: dialog.accept())
                locator.click()

            def capture(name):
                check(page.locator("#app-screen").is_visible(), "Only authenticated non-credential pages may be captured")
                page.screenshot(path=str(args.output / name), full_page=True)
                report["screenshots"].append(name)

            def add_vlan(interface, tag, address, dhcp=False):
                page.locator("#add-vlans").click()
                fill("interface", interface); select("parent", "eth1"); fill("id", tag); fill("address", address)
                page.locator("#edit-internet").uncheck()
                if dhcp:
                    page.locator("#edit-dhcp-enabled").check()
                    fill("dhcp-start", "192.168.20.100"); fill("dhcp-end", "192.168.20.150"); fill("lease-hours", 12)
                apply_editor()

            def add_wg(interface, address, port):
                page.locator("#add-wireguard").click()
                fill("interface", interface); fill("address", address); fill("listen-port", port); fill("mtu", 1420)
                page.locator("#edit-internet").uncheck(); apply_editor()

            def add_peer(key, allowed):
                page.get_by_role("button", name="新增 wg0 對等端", exact=True).click()
                fill("public-key", key); fill("allowed-ips", allowed); fill("keepalive", 0); apply_editor()

            def add_rule(rule_id, action, protocol, comment):
                page.locator("#add-firewall").click()
                fill("id", rule_id); select("chain", "forward"); select("action", action); select("protocol", protocol)
                select("in-interface", "vlan20"); select("out-interface", "eth1")
                fill("source", "192.168.20.0/24"); fill("destination", "192.168.88.0/24"); fill("comment", comment)
                apply_editor()

            page.goto(args.url, wait_until="domcontentloaded")
            expect(page.locator("#setup-panel")).to_be_visible()
            page.locator("#setup-token").fill(token)
            page.locator("#setup-password").fill(password); page.locator("#setup-confirm").fill(password)
            with post_response("/setup") as pending:
                page.locator("#setup-form button[type=submit]").click()
            check(pending.value.status == 200, "UI enrollment failed")
            expect(page.locator("#network-fields")).to_be_enabled()
            initial = get("/config")
            check(initial["config"]["lan"]["interface"] == "eth1" and initial["config"]["lan"]["address"] == "192.168.88.1/24", "Harness expects the standard isolated lab LAN")
            check(not initial["config"].get("vlans") and not initial["config"].get("wireguard") and not initial["config"]["firewall"].get("rules"), "Harness requires fresh advanced configuration")
            passed("fresh_ui_enrollment")

            stage = "VLAN create edit delete"
            navigate("vlans")
            add_vlan("vlan20", 20, "192.168.20.1/24", dhcp=True)
            created = save("vlans")
            check(created["config"]["vlans"][0] == {"interface": "vlan20", "parent": "eth1", "id": 20, "address": "192.168.20.1/24", "dhcp": {"start": "192.168.20.100", "end": "192.168.20.150", "lease_hours": 12}, "internet": False}, "VLAN fields differ from UI input")
            page.get_by_role("button", name="編輯 VLAN vlan20", exact=True).click()
            fill("lease-hours", 24); apply_editor()
            check(save("vlans")["config"]["vlans"][0]["dhcp"]["lease_hours"] == 24, "VLAN edit was not persisted")
            add_vlan("vlan30", 30, "192.168.30.1/24")
            check(len(save("vlans")["config"]["vlans"]) == 2, "Second VLAN was not persisted")
            delete(page.get_by_role("button", name="刪除 VLAN vlan30", exact=True))
            check(len(save("vlans")["config"]["vlans"]) == 1, "VLAN deletion was not persisted")
            capture("vlan-desktop.png")
            passed("vlan_ui_create_edit_delete_persistence")

            stage = "WireGuard interface keys and peers"
            navigate("wireguard")
            add_wg("wg0", "10.44.0.1/24", 51820)
            wg_saved = save("wireguard")
            check(wg_saved["config"]["wireguard"][0]["peers"] == [], "New WireGuard interface unexpectedly has peers")
            keys = get("/wireguard/keys")["public_keys"]
            public_key = keys["wg0"]
            check(len(base64.b64decode(public_key, validate=True)) == 32, "Public-key API did not return a 32-byte key")
            expect(page.get_by_role("textbox", name="wg0 本機公鑰", exact=True)).to_have_value(public_key)
            page.get_by_role("button", name="編輯 VPN wg0", exact=True).click()
            fill("mtu", 1400); apply_editor()
            check(save("wireguard")["config"]["wireguard"][0]["mtu"] == 1400, "WireGuard interface edit failed")
            page.get_by_role("button", name="編輯 VPN wg0", exact=True).click()
            fill("mtu", 1420); apply_editor(); save("wireguard")
            add_peer(PEER_PUBLIC, "10.44.0.2/32")
            check(len(save("wireguard")["config"]["wireguard"][0]["peers"]) == 1, "Peer creation failed")
            page.get_by_role("button", name="編輯 wg0 對等端 1", exact=True).click()
            fill("keepalive", 25); apply_editor()
            check(save("wireguard")["config"]["wireguard"][0]["peers"][0]["persistent_keepalive"] == 25, "Peer edit failed")
            add_peer(TEMP_PUBLIC, "10.44.0.3/32"); save("wireguard")
            delete(page.get_by_role("button", name="刪除 wg0 對等端 2", exact=True))
            check(len(save("wireguard")["config"]["wireguard"][0]["peers"]) == 1, "Peer deletion failed")
            add_wg("wg1", "10.45.0.1/24", 51821); save("wireguard")
            check("wg1" in get("/wireguard/keys")["public_keys"], "Second interface key not created")
            delete(page.get_by_role("button", name="刪除 VPN wg1", exact=True)); save("wireguard")
            remaining_keys = get("/wireguard/keys")["public_keys"]
            check("wg1" not in remaining_keys and remaining_keys["wg0"] == public_key, "Key deletion/stability mismatch")
            capture("wireguard-desktop.png")
            passed("wireguard_interface_peer_crud_and_public_key_stability")

            stage = "ordered firewall CRUD"
            navigate("firewall")
            add_rule("allow-vlan20-icmp", "accept", "icmp", "allow isolated test ICMP")
            add_rule("drop-vlan20", "drop", "any", "drop remaining test traffic")
            check([rule["id"] for rule in save("firewall")["config"]["firewall"]["rules"]] == ["allow-vlan20-icmp", "drop-vlan20"], "Initial firewall order differs")
            page.get_by_role("button", name="下移規則 allow-vlan20-icmp", exact=True).click()
            check([rule["id"] for rule in save("firewall")["config"]["firewall"]["rules"]] == ["drop-vlan20", "allow-vlan20-icmp"], "Rule move down failed")
            page.get_by_role("button", name="停用規則 drop-vlan20", exact=True).click()
            check(save("firewall")["config"]["firewall"]["rules"][0]["enabled"] is False, "Disable rule failed")
            page.get_by_role("button", name="編輯規則 drop-vlan20", exact=True).click()
            fill("comment", "ordered drop test"); apply_editor()
            check(save("firewall")["config"]["firewall"]["rules"][0]["comment"] == "ordered drop test", "Rule edit failed")
            page.get_by_role("button", name="啟用規則 drop-vlan20", exact=True).click()
            page.get_by_role("button", name="上移規則 allow-vlan20-icmp", exact=True).click()
            restored = save("firewall")["config"]["firewall"]["rules"]
            check(restored[0]["id"] == "allow-vlan20-icmp" and restored[1]["enabled"] is True, "Rule enable/reorder failed")
            add_rule("temporary-rule", "reject", "tcp", "temporary CRUD rule"); save("firewall")
            delete(page.get_by_role("button", name="刪除規則 temporary-rule", exact=True))
            final = save("firewall")
            check(len(final["config"]["firewall"]["rules"]) == 2, "Rule deletion failed")
            unchanged = copy.deepcopy(final["config"])
            unchanged.pop("vlans", None); unchanged.pop("wireguard", None); unchanged["firewall"].pop("rules", None)
            baseline = copy.deepcopy(initial["config"])
            baseline.pop("vlans", None); baseline.pop("wireguard", None); baseline["firewall"].pop("rules", None)
            check(unchanged == baseline, "Advanced UI changed unrelated base configuration")
            check(final["pending_reboot"] is True, "Advanced saves should be pending reboot")
            capture("firewall-desktop.png")
            page.set_viewport_size({"width": 390, "height": 844})
            capture("firewall-mobile.png")
            check(page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "Mobile advanced UI overflows horizontally")
            page.set_viewport_size({"width": 1440, "height": 1000})
            passed("firewall_typed_crud_order_enable_disable_and_base_preservation")
            passed("advanced_mobile_responsive")

            stage = "reload saved advanced configuration"
            page.locator("#panel-firewall .advanced-reload").click()
            expect(page.locator("#panel-firewall .advanced-save")).to_be_enabled()
            check(get("/config") == final, "Read-only reload changed stored config")
            expect(page.locator('#firewall-list [data-rule-id="allow-vlan20-icmp"]')).to_be_visible()
            passed("advanced_reload_retains_config")

            stage = "real reboot and persistence"
            old_cookies = context.cookies()
            for cookie in old_cookies:
                secret(cookie["value"])
            page.once("dialog", lambda dialog: dialog.accept())
            with post_response("/reboot") as pending:
                page.locator("#pending-banner .reboot-button").click()
            check(pending.value.status == 200, "Confirmed reboot request failed")
            down = False
            returned = False
            deadline = time.monotonic() + args.reboot_timeout
            while time.monotonic() < deadline:
                try:
                    session = lab.public_session(args.url, timeout=2)
                    if down:
                        check(not session["setup_required"] and not session["authenticated"], "Persistent administrator/session state incorrect after reboot")
                        returned = True
                        break
                except (OSError, ValueError):
                    down = True
                time.sleep(1)
            check(down and returned, "Did not observe actual HTTPS down/up reboot cycle")
            old = playwright.request.new_context(ignore_https_errors=True, storage_state={"cookies": old_cookies, "origins": []})
            try:
                check(old.get(args.url + API + "/status").status == 401, "Pre-reboot session survived reboot")
            finally:
                old.dispose()
            check(lab.certificate_fingerprint(args.url) == fingerprint, "TLS certificate changed on reboot")
            page.goto(args.url, wait_until="domcontentloaded")
            expect(page.locator("#login-panel")).to_be_visible()
            page.locator("#login-password").fill(password)
            with post_response("/login") as pending:
                page.locator("#login-form button[type=submit]").click()
            check(pending.value.status == 200, "Original administrator credential failed after reboot")
            expect(page.locator("#network-fields")).to_be_enabled()
            persisted = get("/config")
            check(persisted["config"] == final["config"] and persisted["revision"] == final["revision"], "Advanced settings did not persist exactly")
            check(persisted["pending_reboot"] is False, "Advanced settings still pending after reboot")
            check(get("/wireguard/keys")["public_keys"]["wg0"] == public_key, "WireGuard key changed after reboot")
            check(get("/status")["persistent"] is True, "Persistent data volume unavailable after reboot")
            expect(page.locator("#pending-banner")).to_be_hidden()
            navigate("wireguard")
            expect(page.get_by_role("textbox", name="wg0 本機公鑰", exact=True)).to_have_value(public_key)
            capture("wireguard-after-reboot.png")
            check(not runtime_errors, "Browser JavaScript errors: " + "; ".join(runtime_errors))
            passed("reboot_preserves_advanced_config_public_key_certificate_and_original_admin", revision=final["revision"])
            passed("private_key_fields_absent_and_no_browser_runtime_errors")
            report["result"] = "PASS"
            context.close(); browser.close()
    except Exception as error:
        report.update(result="FAIL", failed_stage=stage, error=sanitize(error))
        print("FAIL " + stage + ": " + sanitize(error), file=sys.stderr, flush=True)
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 2)
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        (args.output / "browser-network-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
