#!/usr/bin/env python3
"""Real Chrome 0.4 UI, accessibility and persistence acceptance on a fresh VM.

Only loopback HTTPS targets are accepted. Creates an in-memory administrator,
configures IPv6 and dual-stack full-tunnel WireGuard, then reboots the lab VM.
No passwords, tokens, private keys, cookies, HAR or console transcript are saved.
Packet forwarding, VPN handshake and console password tests remain separate.
"""
from __future__ import annotations

import argparse
import base64
import copy
import importlib.util
import ipaddress
import json
import re
import secrets
import socket
import subprocess
import sys
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

from playwright.sync_api import expect, sync_playwright


spec = importlib.util.spec_from_file_location("routertop_browser_base", Path(__file__).with_name("browser-smoke.py"))
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)
API = lab.API
check = lab.check
PUBLIC_FIXTURE = base64.b64encode(bytes(range(1, 33))).decode("ascii")


def fresh_console_token(port: int) -> str:
    """Use the 0.4 create/token gate, never assume an unauthenticated shell."""
    with socket.create_connection(("127.0.0.1", port), timeout=10) as console:
        console.settimeout(0.5)
        console.sendall(b"\n")
        captured = bytearray()
        requested = False
        deadline = time.monotonic() + 30
        try:
            while time.monotonic() < deadline:
                try:
                    part = console.recv(65536)
                    if not part:
                        break
                    captured.extend(part)
                    if not requested and b"Setup choice" in captured:
                        console.sendall(b"token\n")
                        requested = True
                        captured.clear()
                    elif requested:
                        match = re.search(rb"Web enrollment token:\s*([0-9a-fA-F]{64})", captured)
                        if match:
                            return match.group(1).decode("ascii")
                except socket.timeout:
                    continue
            raise RuntimeError("Fresh console did not return an enrollment token through the create/token gate")
        finally:
            captured.clear()


VISUAL_AUDIT = r"""() => {
  const rgba = value => { const nums = value.match(/[\d.]+/g)?.map(Number); return nums ? [nums[0],nums[1],nums[2],nums[3] ?? 1] : [0,0,0,0]; };
  const luminance = c => c.slice(0,3).map(x => x/255).map(x => x <= .04045 ? x/12.92 : ((x+.055)/1.055)**2.4).reduce((sum,x,i) => sum + x*[.2126,.7152,.0722][i],0);
  const contrast = (a,b) => { const x=luminance(a),y=luminance(b); return (Math.max(x,y)+.05)/(Math.min(x,y)+.05); };
  const background = element => { for(let node=element;node;node=node.parentElement){const color=rgba(getComputedStyle(node).backgroundColor);if(color[3] >= .99)return color;}return [255,255,255,1]; };
  const visible = element => {const r=element.getBoundingClientRect(),s=getComputedStyle(element);return r.width>0 && r.height>0 && s.visibility==='visible' && s.opacity!=='0' && !element.closest('[hidden],[aria-hidden="true"]');};
  const label = element => element.id ? '#'+element.id : element.tagName.toLowerCase()+'.'+Array.from(element.classList).join('.');
  const failures=[], pairs=new Map();
  for(const element of document.querySelectorAll('body *')){
    if(!visible(element) || element.matches(':disabled') || element.closest('fieldset:disabled'))continue;
    if(!Array.from(element.childNodes).some(n=>n.nodeType===Node.TEXT_NODE && n.textContent.trim()))continue;
    const s=getComputedStyle(element),fg=rgba(s.color),bg=background(element);
    const key=fg.slice(0,3).join(',')+'/'+bg.slice(0,3).join(',');
    const ratio=contrast(fg,bg), threshold=parseFloat(s.fontSize)>=24 || (parseFloat(s.fontSize)>=18.66 && Number(s.fontWeight)>=700) ? 3 : 4.5;
    if(!pairs.has(key))pairs.set(key,{foreground:s.color,background:`rgb(${bg.slice(0,3).join(', ')})`,ratio:Number(ratio.toFixed(3))});
    if(ratio<threshold)failures.push({element:label(element),ratio:Number(ratio.toFixed(3)),threshold});
  }
  const undersized=[];
  for(const element of document.querySelectorAll('button,a,input,select,textarea')){
    if(!visible(element) || element.matches(':disabled'))continue;
    const r=element.getBoundingClientRect();if(r.bottom<=0)continue;
    if(r.width<24 || r.height<24)undersized.push({element:label(element),width:r.width,height:r.height});
  }
  return {color_scheme:getComputedStyle(document.documentElement).colorScheme,font_family:getComputedStyle(document.body).fontFamily,
    contrast_pairs:[...pairs.values()],contrast_failures:failures,target_failures:undersized,
    horizontal_overflow:document.documentElement.scrollWidth>window.innerWidth};
}"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="https://127.0.0.1:19443")
    parser.add_argument("--serial-port", type=int, default=19410)
    parser.add_argument("--chrome", required=True)
    parser.add_argument("--output", type=Path, default=Path("evidence/v04/browser"))
    parser.add_argument("--reboot-timeout", type=int, default=180)
    parser.add_argument("--headed", action="store_true")
    parser.add_argument("--uefi-launcher", type=Path, help="Optional task-specific PowerShell launcher for authenticated poweroff and UEFI cold-boot acceptance")
    args = parser.parse_args()
    args.url = args.url.rstrip("/")
    parsed = urllib.parse.urlsplit(args.url)
    check(parsed.scheme == "https" and parsed.hostname in {"127.0.0.1", "localhost"}, "Only the loopback HTTPS lab VM is authorized")
    check(not parsed.path and not parsed.query and not parsed.fragment, "Supply an origin URL")
    if args.uefi_launcher:
        args.uefi_launcher = args.uefi_launcher.resolve(strict=True)
        check(args.uefi_launcher.is_file() and args.uefi_launcher.suffix.lower() == ".ps1", "UEFI launcher must be an existing PowerShell script")
    args.output.mkdir(parents=True, exist_ok=True)
    report = {"result": "RUNNING", "url": args.url, "started_utc": datetime.now(timezone.utc).isoformat(),
              "checks": [], "screenshots": [], "visual_audits": [], "packet_handshake_tests": "NOT_RUN by UI harness", "screen_reader_test": "NOT_RUN"}
    sensitive = []
    stage = "fresh enrollment"
    started = time.monotonic()

    def secret(value):
        sensitive.append(value)
        return value

    def sanitize(value):
        text = str(value)
        for item in sorted(sensitive, key=len, reverse=True):
            text = text.replace(item, "[REDACTED_SECRET]")
        return re.sub(r"\b[0-9a-fA-F]{64}\b", "[REDACTED_TOKEN]", text)

    def passed(name, **details):
        report["checks"].append({"name": name, "result": "PASS", **details})
        print("PASS " + name, flush=True)

    try:
        check(lab.public_session(args.url).get("setup_required") is True, "Fresh VM required; will not reset an existing administrator")
        certificate = lab.certificate_fingerprint(args.url)
        token = secret(fresh_console_token(args.serial_port))
        password = secret("Rt04-" + secrets.token_urlsafe(24))
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=args.chrome, headless=not args.headed)
            context = browser.new_context(ignore_https_errors=True, viewport={"width": 1440, "height": 1080}, locale="zh-TW")
            context.set_default_timeout(60000)
            page = context.new_page()
            runtime_errors = []
            page.on("pageerror", lambda error: runtime_errors.append(sanitize(error)))

            def get(path):
                response = context.request.get(args.url + API + path, timeout=30000)
                check(response.status == 200, f"GET {path} returned HTTP {response.status}")
                data = response.json()
                check(not re.search(r'"(?:private_key|private_keys|wireguard_keys)"\s*:', json.dumps(data)), "Private-key field leaked in API data")
                return data

            def post_response(path):
                return page.expect_response(lambda response: response.url == args.url + API + path and response.request.method == "POST", timeout=65000)

            def navigate(name):
                page.locator(f'.nav-item[data-panel="{name}"]').click()
                expect(page.locator(f"#panel-{name}")).to_be_visible()

            def fill(name, value):
                page.locator("#edit-" + name).fill(str(value))

            def apply_editor():
                page.locator("#editor-apply").click()
                expect(page.locator("#editor-dialog")).not_to_be_visible()

            def save(panel, expected_status=200):
                with post_response("/config") as pending:
                    page.locator(f"#panel-{panel} .advanced-save").click()
                check(pending.value.status == expected_status, f"Config save expected HTTP {expected_status}, got {pending.value.status}")
                expect(page.locator(f"#panel-{panel} .advanced-save")).to_be_enabled()
                if expected_status == 200:
                    expect(page.locator("#global-error")).to_be_hidden()
                else:
                    expect(page.locator("#global-error")).to_be_visible()
                return get("/config")

            def visual(name, screenshot=True):
                # Full-page captures otherwise place sticky/fixed elements at
                # the previous scroll offset, producing a misleading layout.
                page.evaluate("window.scrollTo(0, 0)")
                audit = page.evaluate(VISUAL_AUDIT)
                audit["name"] = name
                report["visual_audits"].append(audit)
                check(audit["color_scheme"] == "light", "UI did not use the requested light color scheme")
                check(not audit["contrast_failures"], "Rendered text contrast failed: " + json.dumps(audit["contrast_failures"]))
                check(not audit["target_failures"], "Control target is smaller than 24px: " + json.dumps(audit["target_failures"]))
                check(not audit["horizontal_overflow"], "Horizontal overflow on " + name)
                if screenshot:
                    check(not page.locator("#setup-token").input_value(), "Refusing screenshot while enrollment token remains in input")
                    filename = name + ".png"
                    page.screenshot(path=str(args.output / filename), full_page=True)
                    report["screenshots"].append(filename)

            page.goto(args.url, wait_until="domcontentloaded")
            expect(page.locator("#setup-panel")).to_be_visible()
            visual("setup-light")
            page.keyboard.press("Tab")
            expect(page.locator(".skip-link")).to_be_focused()
            focus = page.locator(".skip-link").evaluate("el => ({style:getComputedStyle(el).outlineStyle,width:parseFloat(getComputedStyle(el).outlineWidth)})")
            check(focus["style"] != "none" and focus["width"] >= 3, "Keyboard focus outline missing")
            page.keyboard.press("Enter")
            expect(page.locator("#auth-main")).to_be_focused()
            page.locator("#setup-token").fill(token)
            page.locator("#setup-password").fill(password)
            page.locator("#setup-confirm").fill(password)
            with post_response("/setup") as pending:
                page.locator("#setup-form button[type=submit]").click()
            check(pending.value.status == 200, "UI enrollment failed")
            expect(page.locator("#network-fields")).to_be_enabled()
            initial = get("/config")
            check(initial["config"]["lan"] == {"interface": "eth1", "address": "192.168.88.1/24"}, "Expected standard lab management LAN")
            check(not initial["config"].get("vlans") and not initial["config"].get("wireguard"), "Expected fresh advanced configuration")
            status = get("/status")
            check(status.get("console_auth_required") is True and status.get("console_password_shared") is True, "Console authentication/shared credential flags missing")
            visual("overview-light")
            passed("new_console_token_gate_and_web_enrollment")
            passed("keyboard_skip_link_and_visible_focus")

            stage = "light panels and keyboard dialog"
            page.locator(".skip-link").focus(); page.keyboard.press("Enter")
            expect(page.locator("#main")).to_be_focused()
            navigate("wireguard")
            opener = page.locator("#add-wireguard")
            opener.focus(); page.keyboard.press("Enter")
            expect(page.locator("#editor-dialog")).to_be_visible()
            for _ in range(18):
                page.keyboard.press("Tab")
                check(page.evaluate("document.getElementById('editor-dialog').contains(document.activeElement)"), "Dialog allowed keyboard focus to escape")
            visual("wireguard-editor-light")
            page.keyboard.press("Escape")
            expect(page.locator("#editor-dialog")).not_to_be_visible()
            expect(opener).to_be_focused()
            passed("native_dialog_keyboard_containment_escape_and_return")

            stage = "VLAN and full-tunnel draft"
            navigate("vlans"); page.locator("#add-vlans").click()
            fill("interface", "vlan20"); page.locator("#edit-parent").select_option("eth1")
            fill("id", 20); fill("address", "192.168.20.1/24")
            page.locator("#edit-dhcp-enabled").check()
            fill("dhcp-start", "192.168.20.100"); fill("dhcp-end", "192.168.20.150"); fill("lease-hours", 12)
            apply_editor()
            navigate("wireguard"); page.locator("#add-wireguard").click()
            fill("interface", "wg0"); fill("address", "10.44.0.1/24"); fill("address-v6", "fd44::1/64")
            fill("listen-port", 51820); fill("mtu", 1420)
            page.locator("#edit-full-tunnel").check(); page.locator("#edit-nat66").check()
            expect(page.locator("#edit-internet")).to_be_disabled()
            check(not page.locator("#edit-internet").is_checked(), "Full tunnel did not disable direct WAN forwarding")
            apply_editor()
            page.get_by_role("button", name="新增 wg0 對等端", exact=True).click()
            fill("public-key", PUBLIC_FIXTURE); fill("allowed-ips", "0.0.0.0/0\n::/0")
            fill("endpoint", "10.0.2.2:51820"); fill("keepalive", 25); apply_editor()

            stage = "IPv6 static WAN LAN VLAN and DNS"
            navigate("ipv6"); page.locator("#ipv6-enabled").check()
            page.locator("#ipv6-wan-address").fill("fd10:1::2/64")
            page.locator("#ipv6-wan-gateway").fill("fd10:1::1")
            page.locator("#ipv6-lan-address").fill("fd20:88::1/64")
            page.locator("#ipv6-dns").fill("")
            page.locator("#add-ipv6-vlan").click()
            page.locator("#edit-interface").select_option("vlan20"); fill("address", "fd20:20::1/64"); apply_editor()
            first_saved = save("ipv6")
            expected_ipv6 = {"wan_address": "fd10:1::2/64", "wan_gateway": "fd10:1::1", "lan_address": "fd20:88::1/64", "vlans": [{"interface": "vlan20", "address": "fd20:20::1/64"}], "dns_upstream": []}
            check(first_saved["config"]["ipv6"] == expected_ipv6, "IPv6 API values differ from submitted fields")
            wg = first_saved["config"]["wireguard"][0]
            check(wg["full_tunnel"] and wg["nat66"] and not wg["internet"] and wg["address_v6"] == "fd44::1/64", "Full-tunnel flags/address not persisted")
            check(wg["peers"][0]["allowed_ips"] == ["0.0.0.0/0", "::/0"], "Dual-stack defaults not persisted")
            public_key = get("/wireguard/keys")["public_keys"]["wg0"]
            visual("ipv6-desktop-light")
            passed("ipv6_static_wan_lan_vlan_and_dualstack_full_tunnel_save")

            stage = "IPv6 validation and firewall family"
            page.locator("#ipv6-lan-address").fill("fd20:88::1/48")
            denied = save("ipv6", 400)
            check(denied == first_saved, "Rejected IPv6 configuration changed durable state")
            visual("ipv6-validation-error", screenshot=False)
            page.locator("#ipv6-lan-address").fill("fd20:88::1/64"); save("ipv6")
            navigate("firewall"); page.locator("#add-firewall").click()
            fill("id", "allow-vlan20-ipv6")
            page.locator("#edit-family").select_option("ipv6")
            page.locator("#edit-chain").select_option("forward")
            page.locator("#edit-action").select_option("accept")
            page.locator("#edit-protocol").select_option("icmpv6")
            page.locator("#edit-in-interface").select_option("vlan20")
            page.locator("#edit-out-interface").select_option("eth1")
            fill("source", "fd20:20::/64"); fill("destination", "fd20:88::/64"); fill("comment", "IPv6 UI acceptance")
            apply_editor(); final = save("firewall")
            rule = final["config"]["firewall"]["rules"][0]
            check(rule["family"] == "ipv6" and rule["protocol"] == "icmpv6", "Firewall family/ICMPv6 not persisted")
            check(final["config"]["lan"] == initial["config"]["lan"], "Management LAN unexpectedly changed")
            check(final["pending_reboot"] is True, "Changes should remain pending until reboot")
            visual("firewall-desktop-light")
            passed("invalid_ipv6_rejected_without_state_change_and_ipv6_firewall_saved")

            stage = "responsive and security panels"
            for panel in ("network", "vlans", "wireguard", "security"):
                navigate(panel); visual(panel + "-desktop-light")
            expect(page.locator("#console-auth-status")).to_have_text("已啟用（必要）")
            expect(page.locator("#console-password-status")).to_have_text("與 Web admin 密碼相同")
            page.set_viewport_size({"width": 390, "height": 844})
            for panel in ("overview", "ipv6", "wireguard", "firewall", "security"):
                navigate(panel); visual(panel + "-mobile-light")
            page.set_viewport_size({"width": 1440, "height": 1080})
            passed("all_panels_light_contrast_targets_and_mobile_layout")

            stage = "reboot and persistence"
            old_cookies = copy.deepcopy(context.cookies())
            for cookie in old_cookies:
                secret(cookie["value"])
            page.once("dialog", lambda dialog: dialog.accept())
            with post_response("/reboot") as pending:
                page.locator("#pending-banner .reboot-button").click()
            check(pending.value.status == 200, "Reboot request rejected")
            down, up = False, False
            deadline = time.monotonic() + args.reboot_timeout
            while time.monotonic() < deadline:
                try:
                    session = lab.public_session(args.url, timeout=2)
                    if down:
                        check(not session["setup_required"], "Administrator was lost on reboot")
                        up = True
                        break
                except (OSError, ValueError):
                    down = True
                time.sleep(1)
            check(down and up, "No complete HTTPS down/up reboot cycle observed")
            stale = playwright.request.new_context(ignore_https_errors=True, storage_state={"cookies": old_cookies, "origins": []})
            try:
                check(stale.get(args.url + API + "/status").status == 401, "Pre-reboot session remains valid")
            finally:
                stale.dispose()
            check(lab.certificate_fingerprint(args.url) == certificate, "TLS certificate changed on reboot")
            page.goto(args.url, wait_until="domcontentloaded")
            expect(page.locator("#login-panel")).to_be_visible(); visual("login-light")
            page.locator("#login-password").fill(password)
            with post_response("/login") as pending:
                page.locator("#login-form button[type=submit]").click()
            check(pending.value.status == 200, "Original shared admin credential no longer works")
            expect(page.locator("#network-fields")).to_be_enabled()
            persisted = get("/config")
            check(persisted["config"] == final["config"] and persisted["revision"] == final["revision"], "IPv6/WireGuard/firewall config did not persist exactly")
            check(not persisted["pending_reboot"], "Rebooted configuration still pending")
            check(get("/wireguard/keys")["public_keys"]["wg0"] == public_key, "WireGuard public key changed")
            navigate("ipv6"); visual("ipv6-after-reboot-light")
            check(not runtime_errors, "Browser runtime errors: " + "; ".join(runtime_errors))
            passed("reboot_preserves_ipv6_full_tunnel_firewall_public_key_certificate_and_admin")
            passed("no_browser_runtime_errors_or_private_key_response_fields")
            if args.uefi_launcher:
                console_spec = importlib.util.spec_from_file_location("routertop_console_v04", Path(__file__).with_name("console-v04-smoke.py"))
                console_module = importlib.util.module_from_spec(console_spec)
                console_spec.loader.exec_module(console_module)
                Terminal = console_module.Terminal
                terminal = None
                terminal_authenticated = False
                cold_started = False
                cold_powered_off = False

                def wait_https_down(timeout=60):
                    deadline = time.monotonic() + timeout
                    while time.monotonic() < deadline:
                        try:
                            lab.public_session(args.url, timeout=2)
                        except (OSError, ValueError):
                            return
                        time.sleep(1)
                    raise AssertionError("HTTPS remained reachable after authenticated poweroff")

                def console_login(timeout=45):
                    connection = Terminal(args.serial_port)
                    try:
                        connection.send("\n")
                        connection.until("Password: ", timeout=timeout)
                        connection.login(password)
                        return connection
                    except Exception:
                        connection.close()
                        raise

                try:
                    stage = "authenticated poweroff before UEFI cold boot"
                    terminal = console_login()
                    terminal_authenticated = True
                    terminal.poweroff()
                    terminal.close(); terminal = None
                    terminal_authenticated = False
                    wait_https_down()
                    passed("authenticated_console_poweroff_before_uefi")

                    stage = "launch and observe UEFI cold boot"
                    # The task launcher verifies that the previous VM process
                    # has exited before starting the same durable data volume.
                    launch = subprocess.run(
                        ["powershell.exe", "-NoProfile", "-File", str(args.uefi_launcher), "-Uefi",
                         "-SerialPort", str(args.serial_port), "-ManagementPort", str(parsed.port or 443)],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=75, check=False)
                    check(launch.returncode == 0, "Task UEFI launcher failed")
                    cold_started = True
                    # QEMU waits for a serial client before starting. Keep the
                    # boot transcript only in Terminal's in-memory buffer.
                    connect_deadline = time.monotonic() + 20
                    while terminal is None:
                        try:
                            terminal = Terminal(args.serial_port)
                        except OSError:
                            check(time.monotonic() < connect_deadline, "UEFI VM serial listener did not become available")
                            time.sleep(0.5)
                    terminal.until("Password: ", timeout=args.reboot_timeout)
                    terminal.close(); terminal = None
                    deadline = time.monotonic() + args.reboot_timeout
                    while True:
                        try:
                            cold_session = lab.public_session(args.url, timeout=3)
                            break
                        except (OSError, ValueError):
                            check(time.monotonic() < deadline, "UEFI VM HTTPS did not become available")
                            time.sleep(1)
                    check(not cold_session.get("setup_required") and not cold_session.get("authenticated"), "Cold boot lost administrator or exposed an authenticated anonymous session")
                    check(lab.certificate_fingerprint(args.url) == certificate, "TLS certificate changed across UEFI cold boot")

                    stage = "UEFI original Web credential and durable state"
                    page.goto(args.url, wait_until="domcontentloaded")
                    expect(page.locator("#login-panel")).to_be_visible()
                    page.locator("#login-password").fill(password)
                    with post_response("/login") as pending:
                        page.locator("#login-form button[type=submit]").click()
                    check(pending.value.status == 200, "Original administrator credential failed after UEFI cold boot")
                    expect(page.locator("#network-fields")).to_be_enabled()
                    cold_config = get("/config")
                    check(cold_config["config"] == final["config"] and cold_config["revision"] == final["revision"], "Configuration/revision changed across UEFI cold boot")
                    check(cold_config["pending_reboot"] is False, "UEFI boot did not apply stored settings")
                    check(get("/wireguard/keys")["public_keys"]["wg0"] == public_key, "WireGuard public key changed across UEFI cold boot")
                    navigate("ipv6"); visual("ipv6-after-uefi-cold-boot-light")
                    passed("uefi_cold_boot_preserves_admin_config_revision_public_key_and_certificate")

                    stage = "authenticated UEFI network and memory observations"
                    terminal = console_login()
                    terminal_authenticated = True
                    terminal.shell("test -d /sys/firmware/efi && ip link show dev wg0 >/dev/null && ip link show dev vlan20 >/dev/null")
                    observations = {"firmware": "UEFI", "interfaces": {}, "policy_table": 51820}
                    expected_addresses = {"eth1": final["config"]["ipv6"]["lan_address"],
                                          "vlan20": final["config"]["ipv6"]["vlans"][0]["address"],
                                          "wg0": final["config"]["wireguard"][0]["address_v6"]}
                    for interface, expected_address in expected_addresses.items():
                        output = terminal.shell("ip -6 -o address show dev " + interface)
                        addresses = sorted({str(ipaddress.ip_interface(value)) for value in re.findall(r"\binet6\s+([0-9a-fA-F:]+/\d+)", output)})
                        check(str(ipaddress.ip_interface(expected_address)) in addresses, "UEFI interface lacks expected IPv6 address: " + interface)
                        observations["interfaces"][interface] = {"present": True, "ipv6_addresses": addresses}
                    routes_v4 = terminal.shell("ip -4 route show table 51820")
                    routes_v6 = terminal.shell("ip -6 route show table 51820")
                    check(re.search(r"(?m)^default dev wg0(?:\s|$)", routes_v4) is not None, "UEFI IPv4 policy table lacks the WG default route")
                    check(re.search(r"(?m)^default dev wg0(?:\s|$)", routes_v6) is not None, "UEFI IPv6 policy table lacks the WG default route")
                    observations["default_routes"] = {"ipv4": "wg0", "ipv6": "wg0"}
                    binary_output = terminal.shell("sha256sum /usr/sbin/routertop-console")
                    binary_hash = re.search(r"(?m)^([0-9a-f]{64})\s+/usr/sbin/routertop-console\s*$", binary_output)
                    check(binary_hash is not None, "Could not parse console executable SHA256")
                    observations["console_binary_sha256"] = binary_hash.group(1)
                    router_output = terminal.shell("sha256sum /usr/sbin/routertop")
                    router_hash = re.search(r"(?m)^([0-9a-f]{64})\s+/usr/sbin/routertop\s*$", router_output)
                    check(router_hash is not None, "Could not parse RouterTop binary SHA256")
                    observations["routertop_binary_sha256"] = router_hash.group(1)
                    memory_output = terminal.shell("cat /proc/meminfo")
                    for field in ("MemTotal", "MemAvailable"):
                        value = re.search(r"(?m)^" + field + r":\s+(\d+)\s+kB", memory_output)
                        check(value is not None, "Missing kernel memory field: " + field)
                        observations[field + "_kib"] = int(value.group(1))
                    check(observations["MemTotal_kib"] > 0, "Invalid UEFI memory observation")
                    report["uefi_observations"] = observations
                    passed("uefi_firmware_interfaces_ipv6_policy_routes_console_binary_and_memory")

                    stage = "authenticated UEFI final poweroff"
                    terminal.poweroff()
                    terminal.close(); terminal = None
                    terminal_authenticated = False
                    wait_https_down()
                    cold_powered_off = True
                    passed("uefi_final_authenticated_poweroff_and_https_down")
                finally:
                    if terminal is not None:
                        # Preserve authenticated-shell knowledge if an
                        # observation fails; closing it first would leave a
                        # shell waiting where a new client expects Password.
                        if terminal_authenticated:
                            try:
                                terminal.poweroff()
                                terminal.close(); terminal = None
                                wait_https_down(timeout=30)
                                cold_powered_off = True
                                report["uefi_cleanup"] = "authenticated poweroff requested; HTTPS down"
                            except Exception as cleanup_error:
                                report["uefi_cleanup_error"] = type(cleanup_error).__name__
                        if terminal is not None:
                            terminal.close(); terminal = None
                    if cold_started and not cold_powered_off:
                        report["uefi_cleanup"] = "NOT_COMPLETED"
                        try:
                            cleanup = console_login(timeout=15)
                            try:
                                cleanup.poweroff()
                            finally:
                                cleanup.close()
                            wait_https_down(timeout=30)
                            report["uefi_cleanup"] = "authenticated poweroff requested; HTTPS down"
                        except Exception as cleanup_error:
                            report["uefi_cleanup_error"] = type(cleanup_error).__name__
            else:
                report["uefi_cold_boot"] = "NOT_RUN: --uefi-launcher was not provided"
            report["result"] = "PASS"
            context.close(); browser.close()
    except Exception as error:
        report.update(result="FAIL", failed_stage=stage, error=sanitize(error))
        print("FAIL " + stage + ": " + sanitize(error), file=sys.stderr, flush=True)
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 2)
        report["finished_utc"] = datetime.now(timezone.utc).isoformat()
        (args.output / "browser-v04-report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
