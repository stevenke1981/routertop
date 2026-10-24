#!/usr/bin/env python3
"""Optional browser-v05 lifecycle hook for the isolated two-VM ISP lab.

The browser supplies an authenticated API callable and keeps the password in
memory. Both serial connections are loopback task VMs. No raw transcript,
identity, password, cookie or populated disk is retained in public reports.
"""
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import shlex
import time


def run_checks(api, console_port, password, outputdir):
    spec = importlib.util.spec_from_file_location("pd_console", Path(__file__).with_name("console-v04-smoke.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    terminal = module.Terminal(console_port)
    isp = module.Terminal(19411)
    checks = []
    initial_config = api("/config")
    state = {
        "prefix": "2001:db8:100::/56", "address": "2001:db8:5:ffff::2",
        "upstream_prefix": "2001:db8:5:ffff::/64", "dns_server": "2001:db8:5:ffff::1",
        "t1": 8, "t2": 16, "preferred_lifetime": 24, "valid_lifetime": 32,
        "ra_lifetime": 30, "ra_enabled": True, "silent": False,
    }

    def control():
        payload = shlex.quote(json.dumps(state, separators=(",", ":")))
        isp.shell(f"printf '%s' {payload} > /tmp/isp-control.json.new && mv /tmp/isp-control.json.new /tmp/isp-control.json")

    def wait_for(predicate, description, timeout=150):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = api("/status").get("ipv6_dynamic") or {}
            if predicate(status):
                return status
            time.sleep(1)
        raise AssertionError(description)

    def bound(status):
        entries = status.get("delegated", [])
        return status.get("state") == "bound" and len(entries) >= 2

    def shell_json(command):
        result = terminal.shell("printf '\\nPD_JSON_START\\n'; " + command + "; printf '\\nPD_JSON_END\\n'")
        match = re.search(r"\r*\nPD_JSON_START\r*\n(.*?)\r*\nPD_JSON_END\r*\n", result, re.S)
        if not match:
            raise AssertionError("Console JSON observation missing")
        return json.loads(match.group(1))

    def passed(name):
        checks.append({"name": name, "result": "PASS"})

    try:
        terminal.send("\n")
        terminal.until("Password: ")
        terminal.login(password)
        isp.shell('test "$(id -u)" = 0')
        digest_output = terminal.shell("sha256sum /usr/sbin/routertop")
        digest = re.search(r"(?m)^([0-9a-f]{64})\s+/usr/sbin/routertop", digest_output)
        assert digest, "Running appliance binary digest missing"
        memory_output = terminal.shell("cat /proc/meminfo")
        memory = {key: int(value) for key, value in re.findall(r"(?m)^(MemTotal|MemAvailable):\s+(\d+) kB", memory_output)}
        original = wait_for(bound, "Initial appliance delegation absent")
        original_prefixes = {entry["prefix"] for entry in original["delegated"]}
        original_addresses = {entry["address"].split("/")[0] for entry in original["delegated"]}
        assert all(ipaddress.IPv6Network(value).subnet_of(ipaddress.IPv6Network(state["prefix"])) for value in original_prefixes)
        passed("actual_iso_acquires_wan_and_distinct_lan_vlan_prefixes")

        terminal.shell("ip link set eth0 down")
        wait_for(lambda status: status.get("state") in ("waiting", "degraded") and not status.get("delegated"), "WAN link loss did not withdraw delegation policy", 35)
        passed("actual_iso_wan_link_loss_withdraws_dynamic_policy")
        terminal.shell("ip link set eth0 up")
        wait_for(bound, "WAN link reconnect did not reacquire delegation")
        passed("actual_iso_wan_link_reconnect_reacquires_lease")

        state["prefix"] = "2001:db8:200::/56"
        control()
        changed = wait_for(lambda status: bound(status) and all(ipaddress.IPv6Network(e["prefix"]).subnet_of(ipaddress.IPv6Network(state["prefix"])) for e in status["delegated"]), "Real DHCPv6 renewal did not adopt new prefix", 100)
        # Check the running kernel, not only API status, for retired addresses.
        deadline = time.monotonic() + 20
        while True:
            addresses = shell_json("ip -6 -j address show")
            actual = {a.get("local") for dev in addresses for a in dev.get("addr_info", [])}
            if not actual.intersection(original_addresses):
                break
            if time.monotonic() > deadline:
                raise AssertionError("Retired delegated router addresses remain in kernel")
            time.sleep(1)
        rules = shell_json("nft -j list table inet routertop")
        serialized = json.dumps(rules)
        assert not any(prefix.split("/")[0] in serialized for prefix in original_prefixes), "Retired prefix remains in firewall"
        assert api("/config") == initial_config, "Lease update changed saved user configuration"
        passed("actual_iso_renewal_renumbers_kernel_and_firewall_without_rewriting_config")

        state["silent"] = True
        state["ra_enabled"] = False
        control()
        wait_for(lambda status: status.get("state") in ("waiting", "degraded") and not status.get("delegated"), "Expired upstream lease retained delegated policy", 75)
        passed("actual_iso_upstream_silence_expires_delegation")
        state["silent"] = False
        state["ra_enabled"] = True
        control()
        recovered = wait_for(bound, "Upstream recovery did not restore delegation", 180)
        assert api("/config") == initial_config, "Reconnect changed persistent settings"
        passed("actual_iso_upstream_recovery_preserves_settings")
        return {"result": "PASS", "checks": checks,
                "routertop_sha256": digest.group(1), "memory_kib": memory,
                "final_prefixes": [e["prefix"] for e in recovered["delegated"]],
                "transport": "isolated QEMU socket Ethernet; real DHCPv6/RA packets"}
    finally:
        # Leave the fixture live for the subsequent real UEFI cold-boot check.
        state["silent"] = False
        state["ra_enabled"] = True
        try:
            control()
        finally:
            isp.close()
            try:
                terminal.shell("ip link set eth0 up")
                terminal.logout()
            finally:
                terminal.close()
