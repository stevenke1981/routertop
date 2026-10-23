#!/usr/bin/env python3
"""Destructive-to-the-lab-only real UI acceptance for a fresh RouterTop VM.

Enrolls a new administrator, edits hostname, changes password and reboots the
specified VM. Credentials remain in memory. No trace, HAR, storage-state file or
raw serial output is saved. Run only against the task's disposable test VM.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import secrets
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


API = "/cgi-bin/routertop.cgi"


def check(condition: bool, description: str) -> None:
    if not condition:
        raise AssertionError(description)


def certificate_fingerprint(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    tls = ssl._create_unverified_context()  # Deliberate self-signed lab TLS.
    with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10) as raw:
        with tls.wrap_socket(raw, server_hostname=parsed.hostname) as secure:
            return hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest()


def public_session(url: str, timeout: float = 4) -> dict:
    request = urllib.request.Request(url + API + "/session", headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, context=ssl._create_unverified_context(), timeout=timeout) as response:
        return json.load(response)


def enrollment_token(port: int) -> str:
    """Read the console token privately; disable terminal echo around the read."""
    begin = "RTBEGIN_" + secrets.token_hex(8)
    end = "RTEND_" + secrets.token_hex(8)
    with socket.create_connection(("127.0.0.1", port), timeout=10) as serial:
        serial.settimeout(0.5)
        serial.sendall(b"\n")  # Opens BusyBox askfirst recovery console if needed.
        drain_until = time.monotonic() + 2
        while time.monotonic() < drain_until:
            try:
                if not serial.recv(65536):
                    raise ConnectionError("VM console disconnected before token retrieval")
            except socket.timeout:
                pass
        serial.sendall(b"stty -echo\n")
        time.sleep(0.3)
        try:
            while True:
                if not serial.recv(65536):
                    raise ConnectionError("VM console disconnected before token retrieval")
        except socket.timeout:
            pass
        command = f"printf '\\n{begin}\\n'; routertop bootstrap-token; printf '\\n{end}\\n'\n"
        serial.sendall(command.encode("ascii"))
        captured = bytearray()
        try:
            deadline = time.monotonic() + 30
            while time.monotonic() < deadline:
                try:
                    part = serial.recv(65536)
                    if not part:
                        break
                    captured.extend(part)
                    if end.encode() in captured:
                        break
                except socket.timeout:
                    continue
            decoded = captured.decode("utf-8", errors="replace")
            segment = decoded.split(begin, 1)[-1].split(end, 1)[0]
            tokens = re.findall(r"(?m)^\s*([0-9a-fA-F]{64})\s*$", segment)
            check(len(tokens) == 1, "Could not privately retrieve a unique enrollment token from the VM console")
            return tokens[0]
        finally:
            captured.clear()
            serial.sendall(b"stty echo\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="https://127.0.0.1:19443")
    parser.add_argument("--serial-port", type=int, default=19410)
    parser.add_argument("--output", type=Path, default=Path("evidence/v02"))
    parser.add_argument("--chrome", required=True, help="Absolute installed Chrome executable path")
    parser.add_argument("--reboot-timeout", type=int, default=180)
    parser.add_argument("--headed", action="store_true", help="Explicitly show the test browser window")
    args = parser.parse_args()
    args.url = args.url.rstrip("/")
    parsed = urllib.parse.urlsplit(args.url)
    check(parsed.scheme == "https" and parsed.hostname in {"127.0.0.1", "localhost"}, "This harness is limited to a local HTTPS lab VM")
    check(parsed.path in {"", "/"} and not parsed.query and not parsed.fragment, "Use the origin URL without a path or query")
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"started_utc": datetime.now(timezone.utc).isoformat(), "url": args.url,
              "browser": "installed Chrome / Playwright", "result": "RUNNING", "checks": [], "screenshots": []}
    sensitive: list[str] = []
    stage = "initialization"
    browser = None
    context = None
    started = time.monotonic()

    def passed(name: str, **details) -> None:
        report["checks"].append({"name": name, "result": "PASS", **details})
        print("PASS " + name, flush=True)

    def remember(value: str) -> str:
        sensitive.append(value)
        return value

    def sanitized(value: object) -> str:
        result = str(value)
        for secret in sorted(sensitive, key=len, reverse=True):
            if secret:
                result = result.replace(secret, "[REDACTED_SECRET]")
        # Cookies, CSRF and enrollment tokens are always 32 random bytes in hex.
        return re.sub(r"\b[0-9a-fA-F]{64}\b", "[REDACTED_HEX_TOKEN]", result)

    try:
        stage = "fresh VM and certificate"
        initial_session = public_session(args.url)
        check(initial_session.get("setup_required") is True, "Fresh VM enrollment is required; refusing to reset an existing administrator")
        fingerprint_before = certificate_fingerprint(args.url)
        report["certificate_sha256_before"] = fingerprint_before
        token = remember(enrollment_token(args.serial_port))
        password = remember("RtLab-" + secrets.token_urlsafe(24))
        new_password = remember("RtNew-" + secrets.token_urlsafe(24))
        wrong_password = remember("RtWrong-" + secrets.token_urlsafe(24))
        passed("fresh_enrollment_and_console_token")

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=args.chrome, headless=not args.headed,
                                                 args=["--disable-features=PasswordManagerOnboarding"])
            context = browser.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 1000}, locale="zh-TW")
            context.set_default_timeout(60000)
            page = context.new_page()
            page_errors: list[str] = []
            page.on("pageerror", lambda error: page_errors.append(sanitized(error)))

            def response_for(path: str):
                return page.expect_response(lambda response: response.url == args.url + API + path and response.request.method == "POST", timeout=65000)

            def api_get(path: str) -> dict:
                response = context.request.get(args.url + API + path, timeout=30000)
                check(response.status == 200, f"GET {path} returned HTTP {response.status}")
                return response.json()

            def csrf() -> str:
                value = api_get("/session").get("csrf_token", "")
                check(bool(value), "Authenticated session did not provide CSRF token")
                return remember(value)

            def cookie_snapshot() -> list[dict]:
                cookies = context.cookies()
                for cookie in cookies:
                    remember(cookie["value"])
                return copy.deepcopy(cookies)

            def old_cookie_denied(cookies: list[dict], label: str) -> None:
                old = playwright.request.new_context(ignore_https_errors=True, storage_state={"cookies": cookies, "origins": []})
                try:
                    response = old.get(args.url + API + "/status", timeout=30000)
                    check(response.status == 401, f"{label}: prior cookie returned HTTP {response.status}")
                finally:
                    old.dispose()
                passed(label)

            def screenshot(name: str) -> None:
                check(page.locator("#app-screen").is_visible(), "Only authenticated non-secret dashboard screenshots are permitted")
                file = args.output / name
                page.screenshot(path=str(file), full_page=True)
                report["screenshots"].append(name)

            def login_with(secret: str) -> float:
                expect(page.locator("#login-panel")).to_be_visible()
                page.locator("#login-password").fill(secret)
                begin_login = time.monotonic()
                with response_for("/login") as pending:
                    page.locator("#login-form button[type=submit]").click()
                check(pending.value.status == 200, f"Valid UI login returned HTTP {pending.value.status}")
                expect(page.locator("#app-screen")).to_be_visible()
                expect(page.locator("#network-fields")).to_be_enabled()
                return round(time.monotonic() - begin_login, 3)

            stage = "first-use UI enrollment"
            page.goto(args.url, wait_until="domcontentloaded", timeout=60000)
            expect(page.locator("#setup-panel")).to_be_visible()
            page.locator("#setup-token").fill(token)
            page.locator("#setup-password").fill(password)
            page.locator("#setup-confirm").fill(password)
            with response_for("/setup") as pending:
                page.locator("#setup-form button[type=submit]").click()
            check(pending.value.status == 200, f"UI setup returned HTTP {pending.value.status}")
            expect(page.locator("#app-screen")).to_be_visible()
            expect(page.locator("#network-fields")).to_be_enabled()
            initial_status = api_get("/status")
            initial_config = api_get("/config")
            original_hostname = initial_status["hostname"]
            check(initial_status.get("persistent") is True, "Router storage is not persistent")
            check(initial_status.get("pending_reboot") is False, "Fresh VM unexpectedly has pending configuration")
            expect(page.locator("#persistence-value")).to_have_text("持久儲存")
            expect(page.locator("#pending-banner")).to_be_hidden()
            cookies = cookie_snapshot()
            check(bool(cookies), "No authenticated browser cookie")
            check(all(c.get("secure") and c.get("httpOnly") and c.get("sameSite") == "Strict" for c in cookies), "Session cookie security attributes missing")
            screenshot("desktop-overview.png")
            passed("ui_enrollment_persistent_status_and_secure_cookie", active_hostname=original_hostname)

            stage = "save hostname and pending reboot UI"
            page.locator('.nav-item[data-panel="network"]').click()
            page.locator("#hostname").fill("routertop-persist-test")
            with response_for("/config") as pending:
                page.locator("#save-config").click()
            check(pending.value.status == 200, f"Configuration save returned HTTP {pending.value.status}")
            expect(page.locator("#pending-banner")).to_be_visible()
            saved = api_get("/config")
            check(saved["config"]["hostname"] == "routertop-persist-test", "Hostname was not durably saved")
            check(saved["pending_reboot"] is True, "Saved configuration was not marked pending")
            expected_config = copy.deepcopy(initial_config["config"])
            expected_config["hostname"] = "routertop-persist-test"
            check(saved["config"] == expected_config, "UI discarded or altered unrelated config fields")
            check(api_get("/status")["hostname"] == original_hostname, "Saved hostname incorrectly appeared active before reboot")
            screenshot("desktop-network-pending.png")
            page.locator('.nav-item[data-panel="overview"]').click()
            expect(page.locator("#active-hostname")).to_have_text(original_hostname)
            page.set_viewport_size({"width": 390, "height": 844})
            screenshot("mobile-overview.png")
            check(page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "Mobile viewport has horizontal overflow")
            page.set_viewport_size({"width": 1440, "height": 1000})
            passed("ui_save_preserves_fields_and_distinguishes_pending_from_active", saved_revision=saved["revision"])
            passed("responsive_mobile_no_horizontal_overflow")

            stage = "UI logout and incorrect password"
            before_logout = cookie_snapshot()
            with response_for("/logout") as pending:
                page.locator("#logout-button").click()
            check(pending.value.status == 200, "Logout failed")
            expect(page.locator("#login-panel")).to_be_visible()
            check(page.locator("#setup-token").input_value() == "", "Enrollment token retained after logout")
            old_cookie_denied(before_logout, "logout_revokes_old_cookie")
            page.locator("#login-password").fill(wrong_password)
            with response_for("/login") as pending:
                page.locator("#login-form button[type=submit]").click()
            check(pending.value.status == 401, "Wrong password did not return HTTP 401")
            expect(page.locator("#auth-error")).to_be_visible()
            expect(page.locator("#login-panel")).to_be_visible()
            login_seconds = login_with(password)
            passed("ui_wrong_password_rejected_then_valid_login", login_seconds=login_seconds)

            stage = "UI password change"
            before_password_change = cookie_snapshot()
            page.locator('.nav-item[data-panel="security"]').click()
            page.locator("#current-password").fill(password)
            page.locator("#new-password").fill(new_password)
            page.locator("#confirm-password").fill(new_password)
            with response_for("/password") as pending:
                page.locator("#password-form button[type=submit]").click()
            check(pending.value.status == 200, "Password update failed")
            expect(page.locator("#login-panel")).to_be_visible()
            old_cookie_denied(before_password_change, "password_change_revokes_old_cookie")
            login_with(new_password)
            passed("ui_password_change_and_new_password_login")

            stage = "API negative access tests"
            anonymous = playwright.request.new_context(ignore_https_errors=True)
            try:
                check(anonymous.get(args.url + API + "/status").status == 401, "Anonymous status was not denied")
            finally:
                anonymous.dispose()
            current = api_get("/config")
            csrf_token = csrf()
            request_body = {"config": current["config"], "revision": current["revision"]}
            negative_headers = {"Origin": args.url, "Content-Type": "application/json"}
            response = context.request.post(args.url + API + "/config", headers=negative_headers, data=request_body)
            check(response.status == 403, f"Missing CSRF returned HTTP {response.status}")
            headers = {**negative_headers, "X-CSRF-Token": csrf_token}
            response = context.request.post(args.url + API + "/config", headers={**headers, "Origin": "https://invalid.example"}, data=request_body)
            check(response.status == 403, f"Wrong Origin returned HTTP {response.status}")
            response = context.request.post(args.url + API + "/config", headers=headers,
                                            data={**request_body, "revision": current["revision"] - 1})
            check(response.status == 409, f"Stale revision returned HTTP {response.status}")
            invalid = copy.deepcopy(request_body)
            invalid["config"]["hostname"] = "invalid hostname; unsafe"
            response = context.request.post(args.url + API + "/config", headers=headers, data=invalid)
            check(response.status == 400, f"Invalid config returned HTTP {response.status}")
            check(api_get("/config") == current, "Denied writes changed persistent configuration")
            passed("api_unauthenticated_csrf_origin_revision_invalid_config_denials")

            stage = "UI confirmed reboot"
            before_reboot = cookie_snapshot()
            page.once("dialog", lambda dialog: dialog.accept())
            reboot_started = time.monotonic()
            with response_for("/reboot") as pending:
                page.locator("#pending-banner .reboot-button").click()
            check(pending.value.status == 200, "UI reboot request failed")
            saw_down = False
            reboot_session = None
            deadline = time.monotonic() + args.reboot_timeout
            while time.monotonic() < deadline:
                try:
                    reboot_session = public_session(args.url, timeout=2)
                    if saw_down:
                        break
                except (OSError, urllib.error.URLError, ValueError):
                    saw_down = True
                time.sleep(1)
            check(saw_down, "No actual HTTPS downtime observed after reboot request")
            check(reboot_session is not None and time.monotonic() < deadline, "Router did not return after reboot deadline")
            check(reboot_session.get("setup_required") is False, "Administrator enrollment was lost across reboot")
            check(reboot_session.get("authenticated") is False, "Anonymous session became authenticated after reboot")
            fingerprint_after = certificate_fingerprint(args.url)
            report["certificate_sha256_after"] = fingerprint_after
            check(fingerprint_before == fingerprint_after, "TLS certificate changed across reboot")
            old_cookie_denied(before_reboot, "reboot_revokes_old_cookie")
            page.goto(args.url, wait_until="domcontentloaded", timeout=60000)
            login_with(new_password)
            final_status = api_get("/status")
            final_config = api_get("/config")
            check(final_status.get("persistent") is True, "Persistent storage missing after reboot")
            check(final_status["hostname"] == "routertop-persist-test", "Saved hostname did not become active")
            check(final_status.get("pending_reboot") is False, "Settings still pending after reboot")
            check(final_config["config"] == saved["config"] and final_config["revision"] == saved["revision"], "Saved configuration/revision did not persist exactly")
            expect(page.locator("#active-hostname")).to_have_text("routertop-persist-test")
            expect(page.locator("#pending-banner")).to_be_hidden()
            screenshot("desktop-after-reboot.png")
            passed("actual_reboot_preserves_admin_config_revision_certificate", reboot_seconds=round(time.monotonic() - reboot_started, 2))
            check(not page_errors, "Browser JavaScript runtime errors: " + "; ".join(page_errors))
            passed("browser_javascript_no_runtime_errors")
            report["result"] = "PASS"
            context.close()
            browser.close()
            context = browser = None
    except Exception as error:
        report["result"] = "FAIL"
        report["failed_stage"] = stage
        report["error"] = sanitized(error)
        print("FAIL " + stage + ": " + sanitized(error), file=sys.stderr, flush=True)
    finally:
        # Closing can itself fail after Playwright unwinds; do not mask evidence.
        for resource in (context, browser):
            if resource is not None:
                try:
                    resource.close()
                except Exception:
                    pass
        report["elapsed_seconds"] = round(time.monotonic() - started, 2)
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        # No request/response bodies, cookies, passwords or console transcript.
        (args.output / "browser-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
