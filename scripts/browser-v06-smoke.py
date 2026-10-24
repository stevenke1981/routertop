#!/usr/bin/env python3
"""Real Chrome PPPoE WAN/IPv6-PD and persistent credential acceptance.

--fixture uses the real HTML/JS with isolated API fixtures, not a router.
Without --fixture, requires a fresh disposable loopback HTTPS appliance and
enrolls through its console token gate. Passwords and tokens stay in memory.
No traces, HAR, cookies, raw console output or client identity are saved.
"""
from __future__ import annotations

import argparse
import copy
import importlib.util
import ipaddress
import json
import re
import secrets
import subprocess
import sys
import time
import tomllib
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


spec = importlib.util.spec_from_file_location("routertop_v04", Path(__file__).with_name("browser-v04-smoke.py"))
previous = importlib.util.module_from_spec(spec)
spec.loader.exec_module(previous)
lab = previous.lab
API = lab.API
check = lab.check


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="https://127.0.0.1:19443")
    parser.add_argument("--serial-port", type=int, default=19410)
    parser.add_argument("--chrome", required=True)
    parser.add_argument("--output", type=Path, default=Path("evidence/v06/browser"))
    parser.add_argument("--fixture", action="store_true", help="Real browser, local HTML and API fixtures; no VM access")
    parser.add_argument("--skip-reboot", action="store_true")
    parser.add_argument("--require-lease", action="store_true", help="After real reboot, require WAN address and delegated LAN/VLAN /64s")
    parser.add_argument("--reboot-timeout", type=int, default=180)
    parser.add_argument("--lease-timeout", type=int, default=120)
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--pppoe-credentials", type=Path, help="Private lab JSON file with username/password; never written to report")
    parser.add_argument("--lifecycle-hook", type=Path, help="Trusted local Python module exposing run_checks(api_get, console_port, password, outputdir)")
    parser.add_argument("--uefi-launcher", type=Path, help="Task-specific PowerShell launcher for authenticated poweroff and UEFI cold boot")
    args = parser.parse_args()
    args.url = args.url.rstrip("/")
    parsed = urllib.parse.urlsplit(args.url)
    check(parsed.scheme == "https" and parsed.hostname in {"127.0.0.1", "localhost"}, "Only loopback HTTPS lab origins are accepted")
    check(not parsed.path and not parsed.query and not parsed.fragment and not parsed.username, "Supply an origin URL")
    check(not args.require_lease or (not args.fixture and not args.skip_reboot), "--require-lease needs a real reboot test")
    check(not (args.lifecycle_hook or args.uefi_launcher) or (not args.fixture and not args.skip_reboot), "Lifecycle/cold-boot options require the real reboot path")
    for option, suffix in ((args.lifecycle_hook, ".py"), (args.uefi_launcher, ".ps1")):
        if option:
            check(option.resolve(strict=True).is_file() and option.suffix.lower() == suffix, "Invalid lifecycle hook or launcher path")
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"result": "RUNNING", "mode": "browser_with_api_fixture" if args.fixture else "real_appliance",
              "started_utc": datetime.now(timezone.utc).isoformat(), "checks": [], "screenshots": [], "visual_audits": [],
              "packet_forwarding": "NOT_RUN by browser harness", "cold_boot_and_duid": "NOT_RUN by browser harness"}
    sensitive = []
    started = time.monotonic()
    stage = "initialization"

    def secret(value):
        sensitive.append(value)
        return value

    def sanitized(value):
        result = str(value)
        for item in sorted(sensitive, key=len, reverse=True):
            result = result.replace(item, "[REDACTED_SECRET]")
        return re.sub(r"\b[0-9a-fA-F]{64}\b", "[REDACTED_TOKEN]", result)

    def passed(name):
        report["checks"].append({"name": name, "result": "PASS"})
        print("PASS " + name, flush=True)

    try:
        if not args.fixture:
            check(lab.public_session(args.url).get("setup_required") is True, "Fresh VM required; existing administrators will not be reset")
        token = secret(secrets.token_hex(32) if args.fixture else previous.fresh_console_token(args.serial_port))
        password = secret("Rt06-" + secrets.token_urlsafe(24))
        if args.fixture:
            pppoe = {"username": "routertop-fixture", "password": secret(secrets.token_urlsafe(24))}
        else:
            check(args.pppoe_credentials is not None, "Real PPPoE acceptance requires --pppoe-credentials")
            credential_bytes = args.pppoe_credentials.resolve(strict=True).read_bytes()
            check(len(credential_bytes) <= 2048, "Lab credential file is too large")
            pppoe = json.loads(credential_bytes)
            check(set(pppoe) == {"username", "password"} and all(isinstance(v, str) and 1 <= len(v) <= 128 and all(32 <= ord(c) < 127 for c in v) for v in pppoe.values()), "Invalid lab credential shape")
            secret(pppoe["username"]); secret(pppoe["password"])
            del credential_bytes
        certificate = None if args.fixture else lab.certificate_fingerprint(args.url)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=args.chrome, headless=not args.headed)
            context = browser.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 1080}, locale="zh-TW")
            context.set_default_timeout(60000)
            page = context.new_page()
            runtime_errors = []
            page.on("pageerror", lambda error: runtime_errors.append(sanitized(error)))
            fixture = None
            if args.fixture:
                root = Path(__file__).resolve().parents[1]
                config = tomllib.loads((root / "configs/routertop.toml").read_text(encoding="utf-8"))
                config.update(ipv6=None, vlans=[], wireguard=[], routes=[])
                config["firewall"].update(ssh_port=None, rules=[])
                config["wan"].update(mode="dhcp", pppoe=None)
                fixture = {"pppoe_password": None, "wan": {"mode": "dhcp", "state": "disabled"}, "config": config, "revision": 1, "pending_reboot": False, "authenticated": False, "dynamic": None, "saves": 0, "next_status": 200}
                csrf = secret(secrets.token_hex(32))

                def route(request):
                    path = urllib.parse.urlsplit(request.request.url).path
                    if not path.startswith(API):
                        filename = "index.html" if path == "/" else path.lstrip("/")
                        check(filename in {"index.html", "app.js", "style.css"}, "Unexpected fixture resource")
                        request.fulfill(path=str(root / "web" / filename))
                        return
                    endpoint = path[len(API):]
                    body = request.request.post_data_json if request.request.method == "POST" else None
                    if endpoint == "/session":
                        data = {"setup_required": not fixture["authenticated"], "authenticated": fixture["authenticated"], "csrf_token": csrf}
                    elif endpoint == "/setup":
                        check(body["token"] == token and body["password"] == password, "Unexpected fixture enrollment")
                        fixture["authenticated"] = True
                        data = {"setup_required": False, "authenticated": True, "csrf_token": csrf}
                    elif endpoint == "/status":
                        data = {"hostname": "routertop", "version": "fixture", "persistent": True, "uptime_seconds": 300,
                                "memory_total_kib": 262144, "memory_available_kib": 196608, "pending_reboot": fixture["pending_reboot"],
                                "console_auth_required": True, "console_password_shared": True, "ipv6_dynamic": fixture["dynamic"], "wan": fixture["wan"]}
                    elif endpoint == "/config":
                        if body is not None:
                            fixture["saves"] += 1
                            check(request.request.headers.get("x-csrf-token") == csrf, "UI omitted CSRF header")
                            status = fixture.pop("next_status", 200)
                            if status != 200:
                                request.fulfill(status=status, json={"error": "Fixture save failure"})
                                return
                            check(body["revision"] == fixture["revision"], "UI submitted stale revision")
                            incoming = copy.deepcopy(body["config"])
                            credentials = incoming["wan"].get("pppoe")
                            if incoming["wan"].get("mode") == "pppoe":
                                previous_account = (fixture["config"]["wan"].get("pppoe") or {}).get("username")
                                if not credentials["password"] and (not fixture["pppoe_password"] or credentials["username"] != previous_account):
                                    request.fulfill(status=400, json={"error": "變更帳號需要撥號密碼"})
                                    return
                                fixture["pppoe_password"] = credentials["password"] or fixture["pppoe_password"]
                                credentials["password"] = ""
                            else:
                                fixture["pppoe_password"] = None
                            fixture.update(config=incoming, revision=fixture["revision"] + 1, pending_reboot=True)
                        data = {key: fixture[key] for key in ("config", "revision", "pending_reboot")}
                        data["wan_password_set"] = fixture["pppoe_password"] is not None
                    elif endpoint == "/wireguard/keys":
                        data = {"public_keys": {}}
                    else:
                        request.fulfill(status=404, json={"error": "Unexpected fixture API"})
                        return
                    request.fulfill(json=data)

                page.route(args.url + "/**", route)

            def get(path):
                # Browser fetch shares the authenticated context and works in fixture mode.
                result = page.evaluate("""async path => { const response = await fetch(path, {cache:'no-store',credentials:'same-origin'}); return {status:response.status,data:await response.json()}; }""", API + path)
                check(result["status"] == 200, f"GET {path} failed")
                check(not re.search(r'"(?:private_key|private_keys|wireguard_keys)"\s*:', json.dumps(result["data"])), "Private-key field in API response")
                check(pppoe["password"] not in json.dumps(result["data"]), "PPPoE password leaked in API response")
                if path == "/config" and result["data"]["config"]["wan"].get("pppoe"):
                    check(result["data"]["config"]["wan"]["pppoe"]["password"] == "", "PPPoE password field must be blank")
                return result["data"]

            def post_response(path):
                return page.expect_response(lambda response: response.url == args.url + API + path and response.request.method == "POST", timeout=65000)

            def navigate(panel):
                page.locator(f'.navigation [data-panel="{panel}"]').click()
                expect(page.locator("#panel-" + panel)).to_be_visible()

            def save(expected=200, panel="network"):
                button = "#save-config" if panel == "network" else "#panel-ipv6 .advanced-save"
                with post_response("/config") as pending:
                    page.locator(button).click()
                check(pending.value.status == expected, "Unexpected save response status")
                expect(page.locator(button)).to_be_enabled()
                if expected == 200:
                    expect(page.locator("#global-error")).to_be_hidden()
                else:
                    expect(page.locator("#global-error")).to_be_visible()
                return get("/config")

            def visual(name):
                page.evaluate("window.scrollTo(0,0)")
                audit = page.evaluate(previous.VISUAL_AUDIT)
                report["visual_audits"].append({"name": name, **audit})
                check(audit["color_scheme"] == "light", "Light appearance changed")
                check(not audit["contrast_failures"] and not audit["target_failures"] and not audit["horizontal_overflow"], "Visual accessibility check failed: " + json.dumps(audit))
                check(not page.locator("#setup-token").input_value(), "Refusing screenshot with populated token field")
                filename = name + ".png"
                check(not page.locator("#pppoe-password").input_value(), "Refusing screenshot with populated PPPoE password")
                page.screenshot(path=str(args.output / filename), full_page=True,
                                mask=[page.locator("#pppoe-username")], mask_color="#e9e9ee")
                report["screenshots"].append(filename)

            def require_dynamic_lease():
                deadline = time.monotonic() + args.lease_timeout
                while time.monotonic() < deadline:
                    live = get("/status")
                    dynamic = live.get("ipv6_dynamic")
                    wan = live.get("wan") or {}
                    assignments = {item["interface"]: item for item in (dynamic or {}).get("delegated", [])}
                    if wan.get("state") == "connected" and wan.get("ipv4_address") and wan.get("ipv6_ready") and dynamic and dynamic["state"] == "bound" and {"eth1", "vlan20"}.issubset(assignments):
                        prefixes = [ipaddress.IPv6Network(assignments[name]["prefix"], strict=False) for name in ("eth1", "vlan20")]
                        check(all(prefix.prefixlen == 64 for prefix in prefixes) and prefixes[0] != prefixes[1], "Delegated LAN/VLAN prefixes invalid or duplicate")
                        navigate("ipv6")
                        page.locator("#ipv6-refresh").click()
                        expect(page.locator("#ipv6-runtime-mode")).to_have_text("已取得動態 IPv6")
                        return {"state": "bound", "pppoe_state": "connected", "ipv4_present": True, "ipv6_ready": True, "wan_address_count": len(dynamic.get("wan_addresses", [])), "delegated_interfaces": ["eth1", "vlan20"], "unique_prefix_length": 64}
                    time.sleep(2)
                raise AssertionError("Dynamic WAN and both delegated /64 subnets were not acquired")

            def login_after_boot(expected_config):
                check(lab.certificate_fingerprint(args.url) == certificate, "TLS identity changed")
                page.goto(args.url, wait_until="domcontentloaded")
                expect(page.locator("#login-panel")).to_be_visible()
                page.locator("#login-password").fill(password)
                with post_response("/login") as pending:
                    page.locator("#login-form button[type=submit]").click()
                check(pending.value.status == 200, "Original admin credential rejected after boot")
                expect(page.locator("#network-fields")).to_be_enabled()
                persisted = get("/config")
                check(persisted["config"] == expected_config["config"] and persisted["revision"] == expected_config["revision"] and not persisted["pending_reboot"], "PD config/revision did not persist and apply")
                check(persisted.get("wan_password_set") and persisted["config"]["wan"]["pppoe"]["password"] == "", "PPPoE credential retention or write-only response failed")
                navigate("network")
                expect(page.locator("#pppoe-password")).to_have_value("")
                expect(page.locator("#pppoe-password-help")).to_contain_text("已儲存")

            stage = "fresh enrollment"
            page.goto(args.url, wait_until="domcontentloaded")
            expect(page.locator("#setup-panel")).to_be_visible()
            page.locator("#setup-token").fill(token)
            page.locator("#setup-password").fill(password)
            page.locator("#setup-confirm").fill(password)
            with post_response("/setup") as pending:
                page.locator("#setup-form button[type=submit]").click()
            check(pending.value.status == 200, "Enrollment failed")
            expect(page.locator("#network-fields")).to_be_enabled()
            initial = get("/config")
            check(initial["config"]["lan"]["interface"] == "eth1", "Expected isolated eth1 management LAN")
            check(not initial["config"].get("vlans") and not initial["config"].get("wireguard"), "Fresh lab configuration required")
            passed("fresh_enrollment_and_config_load")

            stage = "PPPoE mode, credentials and MTU validation"
            navigate("network")
            expect(page.locator("#wan-mode")).to_have_value("dhcp")
            expect(page.locator("#pppoe-fields")).to_be_hidden()
            expect(page.locator("#pppoe-username")).to_be_disabled()
            page.locator("#wan-mode").select_option("pppoe")
            expect(page.locator("#pppoe-fields")).to_be_visible()
            page.locator("#pppoe-username").fill(pppoe["username"])
            check(page.locator("#pppoe-password").evaluate("e => e.required"), "New account must require a password")
            page.locator("#pppoe-password").fill(pppoe["password"])
            page.locator("#pppoe-mtu").fill("1279")
            check(not page.locator("#network-form").evaluate("f => f.checkValidity()"), "MTU below IPv6 minimum accepted")
            page.locator("#pppoe-mtu").fill("1493")
            check(not page.locator("#network-form").evaluate("f => f.checkValidity()"), "MTU above PPPoE maximum accepted")
            page.locator("#pppoe-mtu").fill("1492")
            first = save()
            check(first.get("wan_password_set") and first["config"]["wan"]["mode"] == "pppoe", "PPPoE save incomplete")
            check(first["config"]["wan"]["pppoe"] == {"username": pppoe["username"], "password": "", "mtu": 1492}, "Credential returned or PPPoE options changed")
            expect(page.locator("#pppoe-password")).to_have_value("")
            expect(page.locator("#pppoe-password-help")).to_contain_text("已儲存")
            retained = save()
            check(retained.get("wan_password_set"), "Blank save removed existing password")
            page.locator("#pppoe-username").fill("changed-account")
            check(page.locator("#pppoe-password").evaluate("e => e.required"), "Changed username accepted without a new password")
            page.once("dialog", lambda dialog: dialog.accept())
            page.locator("#reload-config").click()
            expect(page.locator("#pppoe-username")).to_have_value(pppoe["username"])
            expect(page.locator("#pppoe-password")).to_have_value("")
            page.locator("#wan-mode").select_option("dhcp")
            expect(page.locator("#pppoe-fields")).to_be_hidden()
            removed = save()
            check(not removed.get("wan_password_set") and removed["config"]["wan"].get("pppoe") is None, "Disabling PPPoE retained credential")
            page.locator("#wan-mode").select_option("pppoe")
            check(page.locator("#pppoe-password").evaluate("e => e.required"), "Re-enabling removed credential accepted a blank password")
            page.locator("#pppoe-password").fill(pppoe["password"])
            retained = save()
            passed("pppoe_mode_mtu_bounds_write_only_password_blank_preservation_and_account_change_validation")

            stage = "PPPoE and delegated IPv6 settings"
            navigate("vlans")
            page.locator("#add-vlans").click()
            for name, value in {"interface": "vlan20", "id": "20", "address": "192.168.20.1/24"}.items():
                page.locator("#edit-" + name).fill(value)
            page.locator("#edit-parent").select_option("eth1")
            page.locator("#editor-apply").click()
            expect(page.locator("#editor-dialog")).not_to_be_visible()
            navigate("ipv6")
            page.locator("#ipv6-enabled").check()
            page.locator("#ipv6-wan-mode").select_option("auto")
            page.locator("#ipv6-pd-enabled").check()
            page.locator("#ipv6-pd-prefix-length").fill("56")
            page.locator("#ipv6-pd-lan-subnet").fill("0")
            page.locator("#add-ipv6-vlan").click()
            page.locator("#edit-interface").select_option("vlan20")
            page.locator("#edit-subnet-id").fill("1")
            for key in ("Tab", "Shift+Tab"):
                for _ in range(12):
                    page.keyboard.press(key)
                    check(page.evaluate("document.querySelector('#editor-dialog').contains(document.activeElement) && document.hasFocus()"), "PD editor lost keyboard focus")
            page.locator("#editor-apply").click()
            expect(page.locator("#editor-dialog")).not_to_be_visible()
            desired = save(panel="ipv6")
            check(desired["config"]["wan"] == retained["config"]["wan"] and desired.get("wan_password_set"), "Saving IPv6 changed PPPoE options or lost credential")
            v6 = desired["config"]["ipv6"]
            check(v6["wan_mode"] == "auto" and v6["lan_address"] == "" and v6["pd"] == {"prefix_length": 56, "lan_subnet_id": 0, "vlans": [{"interface": "vlan20", "subnet_id": 1}]}, "PPPoE PD configuration incorrect")
            for field in ("lan", "dhcp", "dns", "firewall", "routes", "wireguard"):
                check(desired["config"][field] == initial["config"][field], "Unrelated config changed: " + field)
            check(desired["pending_reboot"], "Saved PPPoE config was not marked pending")
            passed("pppoe_ipv6_pd_save_preserves_other_settings_and_credential")

            stage = "reload and status separation"
            page.reload(wait_until="domcontentloaded")
            expect(page.locator("#network-fields")).to_be_enabled()
            navigate("network")
            check(get("/config") == desired, "Saved settings changed after reload")
            expect(page.locator("#wan-mode")).to_have_value("pppoe")
            expect(page.locator("#pppoe-password")).to_have_value("")
            if fixture is not None:
                for live_state, label in (("dialing", "正在撥號"), ("connected", "已連線"), ("reconnecting", "連線中斷，正在重撥")):
                    fixture["wan"] = {"mode": "pppoe", "state": live_state, "ipv4_address": "198.18.0.2" if live_state == "connected" else None, "ipv6_ready": live_state == "connected"}
                    page.locator("#wan-refresh").click()
                    expect(page.locator("#wan-runtime-state")).to_have_text(label)
                fixture["wan"]["state"] = "<img src=x onerror=alert(1)>"
                page.locator("#wan-refresh").click()
                expect(page.locator("#wan-runtime-state")).to_have_text("無法確認連線狀態")
                check(page.locator("#wan-runtime img").count() == 0, "WAN status interpreted as HTML")
                fixture["wan"].update(state="connected", ipv4_address="198.18.0.2", ipv6_ready=True)
                page.locator("#wan-refresh").click()
                expect(page.locator("#wan-runtime-state")).to_have_text("已連線")
                fixture["next_status"] = 409
                save(409)
                check(get("/config") == desired, "Failed save changed fixture settings")
                page.locator("#reload-config").click()
                expect(page.locator("#global-error")).to_be_hidden()
                passed("fixture_pppoe_states_safe_text_conflict_and_password_clear")
            visual("pppoe-desktop")
            page.set_viewport_size({"width": 390, "height": 844})
            visual("pppoe-mobile")
            page.set_viewport_size({"width": 1440, "height": 1080})
            navigate("ipv6")
            visual("pppoe-ipv6-pd-desktop")
            passed("saved_modes_credential_flag_and_light_responsive_ui")

            if not args.fixture and not args.skip_reboot:
                stage = "actual reboot and persistent configuration"
                cookies = copy.deepcopy(context.cookies())
                for cookie in cookies:
                    secret(cookie["value"])
                page.once("dialog", lambda dialog: dialog.accept())
                with post_response("/reboot") as pending:
                    page.locator("#pending-banner .reboot-button").click()
                check(pending.value.status == 200, "Reboot rejected")
                down = up = False
                deadline = time.monotonic() + args.reboot_timeout
                while time.monotonic() < deadline:
                    try:
                        session = lab.public_session(args.url, timeout=2)
                        if down:
                            check(not session["setup_required"], "Administrator lost on reboot")
                            up = True
                            break
                    except (OSError, ValueError):
                        down = True
                    time.sleep(1)
                check(down and up, "Complete HTTPS reboot cycle not observed")
                stale = playwright.request.new_context(ignore_https_errors=True, storage_state={"cookies": cookies, "origins": []})
                try:
                    check(stale.get(args.url + API + "/status").status == 401, "Old session survived reboot")
                finally:
                    stale.dispose()
                login_after_boot(desired)
                passed("actual_reboot_preserves_config_revision_credentials_certificate_and_expires_session")
                if args.require_lease:
                    stage = "actual dynamic WAN and delegated subnets"
                    report["lease_observation"] = require_dynamic_lease()
                    passed("actual_pppoe_ipv4_ipv6_and_distinct_delegated_lan_vlan_subnets")
                navigate("network")
                visual("pppoe-after-reboot")
                if args.lifecycle_hook:
                    stage = "upstream lifecycle hook"
                    hook_spec = importlib.util.spec_from_file_location("routertop_pd_lifecycle", args.lifecycle_hook.resolve())
                    hook = importlib.util.module_from_spec(hook_spec)
                    hook_spec.loader.exec_module(hook)
                    outcome = hook.run_checks(get, args.serial_port, password, args.output)
                    check(isinstance(outcome, dict), "Lifecycle hook must return a sanitized report object")
                    # The trusted hook owns detailed packet assertions and secret-free reporting.
                    report["lifecycle_checks"] = json.loads(sanitized(json.dumps(outcome)))
                    check(outcome.get("result") == "PASS", "Lifecycle hook did not pass")
                    passed("upstream_lifecycle_hook")
                if args.uefi_launcher:
                    stage = "UEFI cold boot and DHCPv6 identity persistence"
                    terminal_spec = importlib.util.spec_from_file_location("routertop_pd_console", Path(__file__).with_name("console-v04-smoke.py"))
                    console_module = importlib.util.module_from_spec(terminal_spec)
                    terminal_spec.loader.exec_module(console_module)
                    terminal = None
                    authenticated = False
                    cold_started = False
                    cold_off = False

                    def connect_console():
                        connection = console_module.Terminal(args.serial_port)
                        try:
                            connection.send("\n")
                            connection.until("Password: ", timeout=45)
                            connection.login(password)
                            return connection
                        except Exception:
                            connection.close()
                            raise

                    def identity_hash(connection):
                        output = connection.shell("sha256sum /data/routertop-dhcpcd/duid")
                        match = re.search(r"(?m)^([0-9a-f]{64})\s+/data/routertop-dhcpcd/duid", output)
                        check(match is not None, "Persistent DHCPv6 identity digest not available")
                        return secret(match.group(1))

                    def pppoe_credential_hash(connection):
                        output = connection.shell("test -f /run/routertop/pppoe/peer && test $(stat -c %a /run/routertop/pppoe/peer) = 600 && sha256sum /run/routertop/pppoe/peer")
                        match = re.search(r"(?m)^([0-9a-f]{64})\s+/run/routertop/pppoe/peer", output)
                        check(match is not None, "Private PPPoE runtime credential file or permissions invalid")
                        return secret(match.group(1))

                    def wait_down():
                        deadline = time.monotonic() + 45
                        while time.monotonic() < deadline:
                            try:
                                lab.public_session(args.url, timeout=2)
                            except (OSError, ValueError):
                                return
                            time.sleep(1)
                        raise AssertionError("HTTPS remained available after poweroff")

                    try:
                        terminal = connect_console()
                        authenticated = True
                        identity_before = identity_hash(terminal)
                        pppoe_before = pppoe_credential_hash(terminal)
                        terminal.poweroff()
                        terminal.close(); terminal = None; authenticated = False
                        wait_down()
                        launched = subprocess.run(["powershell.exe", "-NoProfile", "-File", str(args.uefi_launcher.resolve()), "-Uefi", "-SerialPort", str(args.serial_port), "-ManagementPort", str(parsed.port or 443)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=75, check=False)
                        check(launched.returncode == 0, "Task-specific UEFI launcher failed")
                        cold_started = True
                        deadline = time.monotonic() + 20
                        while True:
                            try:
                                terminal = console_module.Terminal(args.serial_port)
                                break
                            except OSError:
                                check(time.monotonic() < deadline, "UEFI serial listener did not start")
                                time.sleep(0.5)
                        terminal.until("Password: ", timeout=args.reboot_timeout)
                        terminal.close(); terminal = None
                        deadline = time.monotonic() + args.reboot_timeout
                        while True:
                            try:
                                session = lab.public_session(args.url, timeout=2)
                                check(not session["setup_required"] and not session["authenticated"], "Cold boot lost administrator or anonymous session invalid")
                                break
                            except (OSError, ValueError):
                                check(time.monotonic() < deadline, "HTTPS did not return after cold boot")
                                time.sleep(1)
                        login_after_boot(desired)
                        if args.require_lease:
                            report["cold_boot_lease_observation"] = require_dynamic_lease()
                        terminal = connect_console()
                        authenticated = True
                        terminal.shell("test -d /sys/firmware/efi")
                        check(identity_hash(terminal) == identity_before, "DHCPv6 client identity changed across cold boot")
                        check(pppoe_credential_hash(terminal) == pppoe_before, "Private PPPoE credential/options changed across cold boot")
                        report["cold_boot_and_duid"] = {"result": "PASS", "firmware": "UEFI", "identity_preserved": True, "pppoe_credential_preserved": True, "private_credential_permissions": "0600"}
                        navigate("network")
                        visual("pppoe-after-uefi-cold-boot")
                        passed("uefi_cold_boot_preserves_settings_admin_certificate_pppoe_credential_and_dhcpv6_identity")
                        terminal.poweroff()
                        cold_off = True
                        terminal.close(); terminal = None; authenticated = False
                        wait_down()
                        passed("final_authenticated_poweroff_and_https_down")
                    finally:
                        if terminal is not None:
                            if authenticated:
                                try:
                                    terminal.poweroff()
                                    cold_off = True
                                    report["cleanup"] = "authenticated poweroff completed"
                                except Exception as error:
                                    report["cleanup_error"] = type(error).__name__
                            terminal.close(); terminal = None
                        if cold_started and not cold_off:
                            try:
                                cleanup = connect_console()
                                try:
                                    cleanup.poweroff()
                                    report["cleanup"] = "authenticated poweroff completed"
                                finally:
                                    cleanup.close()
                            except Exception as error:
                                report["cleanup_error"] = type(error).__name__
            else:
                report["actual_reboot"] = "NOT_RUN: fixture mode" if args.fixture else "NOT_RUN: --skip-reboot"
            check(not runtime_errors, "Browser runtime errors: " + "; ".join(runtime_errors))
            passed("no_browser_runtime_errors_or_returned_credentials")
            report["result"] = "PASS"
            context.close()
            browser.close()
    except Exception as error:
        report.update(result="FAIL", failed_stage=stage, error=sanitized(error))
        print("FAIL " + stage + ": " + sanitized(error), file=sys.stderr, flush=True)
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 2)
        (args.output / "browser-v06-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
