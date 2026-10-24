#!/usr/bin/env python3
"""Actual-ISO PPPoE/PD lifecycle hook for the isolated two-VM lab.

Called by browser-v06-smoke.py after authenticated Web save and reboot. It
controls only the explicitly assigned loopback ISP VM (serial 19411), and
logs into the appliance console with the in-memory administrator password.
No raw transcript, credentials, DUID or private-material digest is returned
or written. The browser owns report serialization and subsequent cold boot.
"""
import importlib.util
import ipaddress
import json
from pathlib import Path
import re
import shlex
import time

CONTROL = "/tmp/isp/control.json"
STATUS = "/tmp/isp/status.json"
PREFIX_B = "2001:db8:200::/56"


def run_checks(api_get, console_port, password, outputdir):
    spec = importlib.util.spec_from_file_location("pppoe_console", Path(__file__).with_name("console-v04-smoke.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    terminal = module.Terminal(console_port)
    isp = module.Terminal(19411)
    authenticated = False
    control = None
    checks = []

    def passed(name):
        checks.append({"name": name, "result": "PASS"})

    def shell_json(connection, command):
        # Sentinels occupy their own lines: an echoed command cannot be data.
        output = connection.shell("printf '\\nPPPOE_JSON_START\\n'; " + command + "; printf '\\nPPPOE_JSON_END\\n'")
        match = re.search(r"\r*\nPPPOE_JSON_START\r*\n(.*?)\r*\nPPPOE_JSON_END\r*\n", output, re.S)
        if match is None:
            raise AssertionError("Console JSON observation missing")
        return json.loads(match.group(1))

    def write_control():
        value = shlex.quote(json.dumps(control, separators=(",", ":")))
        isp.shell(f"printf '%s' {value} > {CONTROL}.new && mv {CONTROL}.new {CONTROL}")

    def wait_for(predicate, description, timeout=150):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = api_get("/status")
            if predicate(status):
                return status
            time.sleep(1)
        raise AssertionError(description)

    def bound(status):
        wan = status.get("wan") or {}
        dynamic = status.get("ipv6_dynamic") or {}
        entries = {item["interface"]: item for item in dynamic.get("delegated", [])}
        return (wan.get("state") == "connected" and wan.get("ipv4_address")
                and wan.get("ipv6_ready") is True and dynamic.get("state") == "bound"
                and {"eth1", "vlan20"}.issubset(entries))

    def saved():
        config = api_get("/config")
        assert config.get("wan_password_set") is True, "Stored PPPoE password missing"
        assert config["config"]["wan"]["pppoe"]["password"] == "", "PPPoE password returned by API"
        return config

    def digests():
        # Material and digests stay in local memory; only equality is reported.
        output = terminal.shell("test $(stat -c %a /run/routertop/pppoe/peer) = 600 && sha256sum /data/routertop-dhcpcd/duid /run/routertop/pppoe/peer")
        values = dict((name, digest) for digest, name in re.findall(
            r"(?m)^([0-9a-f]{64})\s+(/(?:data/routertop-dhcpcd/duid|run/routertop/pppoe/peer))\r?$", output))
        assert len(values) == 2, "Private credential/client identity observations missing"
        return values

    def routed_http():
        deadline = time.monotonic() + 25
        while True:
            try:
                terminal.shell("""test "$(wget -qO- -T 5 http://203.0.113.9:8080/)" = PPPOE-ISP && test "$(wget -qO- -T 5 'http://[2001:db8:99::9]:8080/')" = PPPOE-ISP""")
                return
            except AssertionError:
                if time.monotonic() >= deadline:
                    raise AssertionError("Actual PPP IPv4/IPv6 routed HTTP did not recover") from None
                time.sleep(1)

    def retired(entries):
        addresses = {item["address"].split("/")[0] for item in entries}
        prefixes = {item["prefix"].split("/")[0] for item in entries}
        deadline = time.monotonic() + 25
        while True:
            devices = shell_json(terminal, "ip -6 -j address show")
            actual = {a.get("local") for dev in devices for a in dev.get("addr_info", [])}
            rules = json.dumps(shell_json(terminal, "nft -j list table inet routertop"))
            if not actual.intersection(addresses) and not any(prefix in rules for prefix in prefixes):
                return
            if time.monotonic() >= deadline:
                raise AssertionError("Retired delegated address/prefix remains in kernel or firewall")
            time.sleep(1)

    def counts():
        status = shell_json(isp, "cat " + STATUS)
        messages = status.get("messages") or {}
        return {key: int(messages.get(key, 0)) for key in
                ("padi", "pado", "padr", "pads", "padt", "session_frames", "underlay_dhcpv4")}

    try:
        terminal.send("\n")
        terminal.until("Password: ")
        terminal.login(password)
        authenticated = True
        # The assigned ISP serial endpoint already has a root shell; no login
        # bypass or unknown host target is attempted.
        isp.shell('test "$(id -u)" = 0')
        control = shell_json(isp, "cat " + CONTROL)
        assert isinstance(control, dict) and control.get("pppoe_enabled", True), "ISP control not enabled"
        initial_config = saved()
        before = digests()
        original = wait_for(bound, "Initial actual PPPoE/IPv6/PD session absent")
        entries = original["ipv6_dynamic"]["delegated"]
        networks = [ipaddress.IPv6Network(item["prefix"]) for item in entries]
        assert len(set(networks)) == len(networks) and all(n.prefixlen == 64 for n in networks), "Delegated subnets invalid or duplicate"
        assert all(n.subnet_of(ipaddress.IPv6Network(control["prefix"])) for n in networks), "Unexpected original delegation"
        initial_counts = counts()
        assert all(initial_counts[key] > 0 for key in ("padi", "pado", "padr", "pads", "session_frames")), "Real PPPoE discovery/session frames not observed"
        routed_http()
        memory_output = terminal.shell("cat /proc/meminfo")
        memory = {key: int(value) for key, value in re.findall(r"(?m)^(MemTotal|MemAvailable):\s+(\d+) kB", memory_output)}
        passed("actual_iso_pppoe_authenticated_ipv4_ipv6_pd_and_routed_http")

        control["pppoe_enabled"] = False
        write_control()
        wait_for(lambda s: (s.get("wan") or {}).get("state") == "reconnecting"
                 and not (s.get("ipv6_dynamic") or {}).get("delegated"),
                 "Server disconnect did not withdraw PPP/PD state", 60)
        retired(entries)
        assert saved() == initial_config, "Disconnect changed saved configuration"
        passed("actual_iso_server_disconnect_withdraws_ppp_and_delegated_policy")

        control["pppoe_enabled"] = True
        write_control()
        reconnected = wait_for(bound, "PPPoE server recovery did not automatically redial", 150)
        routed_http()
        current_counts = counts()
        assert current_counts["pads"] > initial_counts["pads"], "No new PPPoE session observed after reconnect"
        assert digests() == before and saved() == initial_config, "Reconnect changed identity, credentials or user settings"
        passed("actual_iso_automatic_redial_restores_ipv4_ipv6_pd_and_preserves_private_identity")

        old_entries = reconnected["ipv6_dynamic"]["delegated"]
        assert not all(ipaddress.IPv6Network(e["prefix"]).subnet_of(ipaddress.IPv6Network(PREFIX_B)) for e in old_entries), "Prefix-change test requires initial prefix A"
        control["prefix"] = PREFIX_B
        write_control()
        changed = wait_for(lambda s: bound(s) and all(ipaddress.IPv6Network(e["prefix"]).subnet_of(ipaddress.IPv6Network(PREFIX_B))
                           for e in s["ipv6_dynamic"]["delegated"]), "Real DHCPv6 renewal did not adopt prefix B", 100)
        retired(old_entries)
        routed_http()
        assert saved() == initial_config, "Prefix update rewrote persistent configuration"
        passed("actual_iso_ppp_pd_renewal_retires_kernel_and_firewall_prefix_a")

        control["silent"] = True
        write_control()
        wait_for(lambda s: (s.get("wan") or {}).get("state") == "connected"
                 and not (s.get("ipv6_dynamic") or {}).get("delegated"),
                 "PD lease did not expire while PPP stayed connected", 75)
        retired(changed["ipv6_dynamic"]["delegated"])
        passed("actual_iso_pd_expiry_withdraws_addresses_and_policy_with_live_ppp")
        control["silent"] = False
        write_control()
        recovered = wait_for(bound, "DHCPv6 service recovery did not restore PD", 180)
        routed_http()
        assert digests() == before and saved() == initial_config, "Recovery changed private identity or user configuration"
        final_counts = counts()
        assert final_counts["underlay_dhcpv4"] == initial_counts["underlay_dhcpv4"], "IPv4 DHCP appeared on PPPoE underlay during lifecycle test"
        passed("actual_iso_pd_recovery_keeps_private_material_and_no_underlay_dhcp_fallback")
        return {"result": "PASS", "checks": checks, "memory_kib": memory,
                "private_material_preserved": True, "underlay_dhcpv4_delta": 0,
                "session_count_increased": final_counts["pads"] > initial_counts["pads"],
                "final_prefixes": [e["prefix"] for e in recovered["ipv6_dynamic"]["delegated"]],
                "transport": "isolated QEMU socket Ethernet; actual PPPoE/PPP/IPv6CP and DHCPv6 packets"}
    finally:
        # Leave the ISP live with prefix B for the browser's subsequent cold
        # boot; never retain identity hashes or raw serial output in evidence.
        if isinstance(control, dict):
            control.update(pppoe_enabled=True, silent=False, ra_enabled=False)
            try:
                write_control()
            except Exception:
                pass
        isp.close()
        try:
            if authenticated:
                terminal.logout()
        finally:
            terminal.close()
