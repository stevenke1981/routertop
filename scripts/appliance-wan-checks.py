#!/usr/bin/env python3
"""Real dual-ISP appliance lifecycle checks; called by browser-v07-smoke.py.

The disposable ISP VM must have a root shell on serial 19411. No production
interface is touched. Private data and raw console output never leave memory.
"""
from __future__ import annotations
import importlib.util
import ipaddress
import json
import re
import shlex
import time
from pathlib import Path

CONTROLS = {slot: f"/var/lib/routertop-v07-isp/{slot}/control.json" for slot in ("primary", "backup")}


def run_checks(api_get, console_port, password, outputdir):
    spec = importlib.util.spec_from_file_location("wan_console", Path(__file__).with_name("console-v04-smoke.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    router = module.Terminal(console_port)
    isp = module.Terminal(19411)
    authenticated = False
    initial_controls = {}
    checks = []

    def passed(name):
        checks.append({"name": name, "result": "PASS"})

    def shell_json(connection, command):
        output = connection.shell("printf '\\nWAN_JSON_START\\n'; " + command + "; printf '\\nWAN_JSON_END\\n'")
        match = re.search(r"\r*\nWAN_JSON_START\r*\n(.*?)\r*\nWAN_JSON_END\r*\n", output, re.S)
        assert match is not None, "Console JSON observation missing"
        return json.loads(match.group(1))

    def update(slot, **changes):
        script = "import json,os; p=" + repr(CONTROLS[slot]) + "; v=json.load(open(p)); v.update(" + repr(changes) + "); json.dump(v,open(p+'.new','w')); os.replace(p+'.new',p)"
        isp.shell("python3 -c " + shlex.quote(script))

    def wait_for(predicate, description, timeout=150):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status = api_get("/status")
            if predicate(status):
                return status
            time.sleep(1)
        raise AssertionError(description)

    def active(status, slot):
        wan = status.get("wan") or {}
        return wan.get("dual_wan") is True and wan.get("active") == slot

    def primary_ready(status):
        dynamic = status.get("ipv6_dynamic") or {}
        assignments = {v["interface"]: v for v in dynamic.get("delegated", [])}
        return active(status, "primary") and (status["wan"].get("primary") or {}).get("healthy") is True and dynamic.get("state") == "bound" and {"eth1", "vlan20"}.issubset(assignments)

    def routed_http(marker):
        deadline = time.monotonic() + 25
        while True:
            try:
                router.shell('test "$(wget -qO- -T 4 http://203.0.113.9:8080/)" = ' + shlex.quote(marker))
                return
            except AssertionError:
                if time.monotonic() >= deadline:
                    raise AssertionError("Actual WAN routed HTTP marker did not recover") from None
                time.sleep(1)

    def retired(entries):
        addresses = {v["address"].split("/")[0] for v in entries}
        prefixes = {v["prefix"].split("/")[0] for v in entries}
        deadline = time.monotonic() + 25
        while True:
            devices = shell_json(router, "ip -6 -j address show")
            current = {a.get("local") for dev in devices for a in dev.get("addr_info", [])}
            rules = json.dumps(shell_json(router, "nft -j list table inet routertop"))
            if not current.intersection(addresses) and not any(prefix in rules for prefix in prefixes):
                return
            assert time.monotonic() < deadline, "Retired primary IPv6 authorization/address remains"
            time.sleep(1)

    def private_identity():
        paths = ["/data/routertop-dhcpcd/duid", "/run/routertop/wan/pppoe-0/peer", "/run/routertop/wan/pppoe-1/peer"]
        commands = [f"test $(stat -c %a {path}) = 600" for path in paths[1:]]
        output = router.shell(" && ".join(commands) + " && sha256sum " + " ".join(paths))
        values = dict((name, digest) for digest, name in re.findall(r"(?m)^([0-9a-f]{64})\s+(/(?:data/routertop-dhcpcd/duid|run/routertop/wan/pppoe-[01]/peer))", output))
        assert set(values) == set(paths), "Private WAN credential/client identity observation missing"
        return values

    def saved():
        value = api_get("/config")
        assert value.get("wan_password_set") and value.get("wan_backup_password_set"), "Both WAN credentials must remain saved"
        assert all(value["config"][slot]["pppoe"]["password"] == "" for slot in ("wan", "wan_backup")), "WAN credential leaked"
        return value

    try:
        router.send("\n")
        router.until("Password: ")
        router.login(password)
        authenticated = True
        isp.shell('test "$(id -u)" = 0')
        for slot, path in CONTROLS.items():
            initial_controls[slot] = shell_json(isp, "cat " + shlex.quote(path))
        before_saved = saved()
        before_identity = private_identity()
        initial = wait_for(primary_ready, "Initial primary PPP/IPv6/PD missing")
        assert (initial["wan"].get("backup") or {}).get("healthy") is True, "Backup not healthy"
        entries = initial["ipv6_dynamic"]["delegated"]
        assert len({ipaddress.IPv6Network(v["prefix"]) for v in entries}) == len(entries), "Duplicate delegated prefixes"
        routed_http("WAN-primary")
        passed("actual_iso_both_ppp_links_primary_ipv4_ipv6_pd_and_distinct_egress")

        update("primary", blackhole=True)
        switched = wait_for(lambda s: active(s, "backup") and not (s.get("ipv6_dynamic") or {}).get("delegated"), "Upstream blackhole did not switch to backup/withdraw IPv6")
        assert not switched["wan"].get("ipv6_ready"), "Backup advertised primary IPv6 readiness"
        retired(entries)
        routed_http("WAN-backup")
        assert saved() == before_saved and private_identity() == before_identity, "Failover changed saved settings/identity"
        passed("actual_iso_upstream_blackhole_switches_ipv4_and_withdraws_primary_ipv6")

        update("primary", blackhole=False)
        wait_for(primary_ready, "Primary recovery did not restore primary/IPv6/PD")
        routed_http("WAN-primary")
        passed("actual_iso_primary_recovery_automatically_fails_back_and_reacquires_pd")

        update("primary", pppoe_enabled=False)
        wait_for(lambda s: active(s, "backup") and not (s.get("ipv6_dynamic") or {}).get("delegated"), "PPP peer disconnect did not select backup")
        routed_http("WAN-backup")
        passed("actual_iso_ppp_session_disconnect_uses_live_backup")
        update("primary", pppoe_enabled=True)
        wait_for(primary_ready, "PPP redial did not restore primary/IPv6/PD", 180)
        routed_http("WAN-primary")
        assert saved() == before_saved and private_identity() == before_identity, "Recovery changed saved settings/identity"
        passed("actual_iso_ppp_redial_restores_primary_and_preserves_settings_credentials_duid")
        return {"result":"PASS", "checks":checks, "private_identity_preserved":True, "ipv6_policy":"primary-only; withdrawn while backup active", "raw_console":"not retained"}
    finally:
        for slot, control in initial_controls.items():
            try:
                update(slot, blackhole=control.get("blackhole", False), pppoe_enabled=control.get("pppoe_enabled", True))
            except Exception:
                pass
        if authenticated:
            try:
                router.logout()
            except Exception:
                pass
        router.close()
        isp.close()


def verify_initial_backup_then_enable_primary(api_get, console_port, password, outputdir):
    """Exercise backup as the first active link, before any primary PD client.

    Caller provisions the primary PPP server disabled and backup enabled. This
    must not start dhcpcd's default master when no owned master exists to stop.
    The primary is then enabled and must acquire real IPv6/PD without a reboot.
    """
    spec = importlib.util.spec_from_file_location("initial_wan_console", Path(__file__).with_name("console-v04-smoke.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    router = module.Terminal(console_port)
    isp = module.Terminal(19411)
    authenticated = False
    primary_enabled = False

    def shell_json(connection, command):
        output = connection.shell("printf '\\nINITIAL_WAN_JSON_START\\n'; " + command + "; printf '\\nINITIAL_WAN_JSON_END\\n'")
        match = re.search(r"\r*\nINITIAL_WAN_JSON_START\r*\n(.*?)\r*\nINITIAL_WAN_JSON_END\r*\n", output, re.S)
        assert match is not None, "Initial WAN JSON observation missing"
        return json.loads(match.group(1))

    def enable_primary():
        script = "import json,os; p=" + repr(CONTROLS["primary"]) + "; v=json.load(open(p)); v['pppoe_enabled']=True; json.dump(v,open(p+'.new','w')); os.replace(p+'.new',p)"
        isp.shell("python3 -c " + shlex.quote(script))

    def wait_for(predicate, description, timeout=180):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            value = api_get("/status")
            if predicate(value):
                return value
            time.sleep(1)
        raise AssertionError(description)

    def primary_ready(value):
        wan = value.get("wan") or {}
        dynamic = value.get("ipv6_dynamic") or {}
        return wan.get("active") == "primary" and (wan.get("primary") or {}).get("healthy") is True and dynamic.get("state") == "bound" and {"eth1","vlan20"}.issubset({entry["interface"] for entry in dynamic.get("delegated", [])})

    try:
        router.send("\n")
        router.until("Password: ")
        router.login(password)
        authenticated = True
        isp.shell('test "$(id -u)" = 0')
        primary_control = shell_json(isp, "cat " + shlex.quote(CONTROLS["primary"]))
        backup_control = shell_json(isp, "cat " + shlex.quote(CONTROLS["backup"]))
        assert primary_control.get("pppoe_enabled") is False and backup_control.get("pppoe_enabled", True), "Initial backup test requires primary server disabled before first dial"
        before_saved = api_get("/config")
        live = wait_for(lambda value: (value.get("wan") or {}).get("active") == "backup" and ((value.get("wan") or {}).get("backup") or {}).get("healthy") is True, "Backup was not first usable WAN")
        dynamic = live.get("ipv6_dynamic") or {}
        assert dynamic.get("state") != "bound" and not dynamic.get("delegated") and not live["wan"].get("ipv6_ready"), "Initial backup retained primary IPv6/PD"
        router.shell('test "$(wget -qO- -T 5 http://203.0.113.9:8080/)" = WAN-backup')
        # Observe live processes as well as the pidfile: a wrongly started
        # default master is a failure even when PD status is still waiting.
        router.shell('test -z "$(pidof dhcpcd || true)"')
        router.shell('if [ -s /run/dhcpcd/pid ]; then p=$(cat /run/dhcpcd/pid); ! kill -0 "$p" 2>/dev/null; fi')
        devices = shell_json(router, "ip -6 -j address show")
        assert not any(address.get("scope") == "global" for device in devices if device.get("ifname") in {"eth1","vlan20"} for address in device.get("addr_info", [])), "Initial backup has stale LAN/VLAN global IPv6 addresses"
        rules = shell_json(router, "nft -j list table inet routertop")
        sets = [entry["set"] for entry in rules.get("nftables", []) if "set" in entry and (entry["set"].get("name", "").startswith(("pd_net", "pd_addr")) or entry["set"].get("name") == "auto_wan")]
        assert sets and all(not entry.get("elem") for entry in sets), "Initial backup retained dynamic IPv6 authorization"
        enable_primary()
        primary_enabled = True
        recovered = wait_for(primary_ready, "Initial backup to primary failed to start correct DHCPv6-PD client")
        router.shell('test "$(wget -qO- -T 5 http://203.0.113.9:8080/)" = WAN-primary')
        assert api_get("/config") == before_saved, "Initial WAN activation changed persistent settings"
        return {"result":"PASS", "first_active":"backup", "backup_routed_http":True, "no_live_dhcpcd_master_before_primary":True, "no_dynamic_ipv6_authorization_before_primary":True, "primary_restored_without_reboot":True, "primary_delegated_interfaces":sorted(entry["interface"] for entry in recovered["ipv6_dynamic"]["delegated"]), "settings_preserved":True}
    finally:
        if not primary_enabled:
            try:
                enable_primary()
            except Exception:
                pass
        if authenticated:
            try:
                router.logout()
            except Exception:
                pass
        router.close()
        isp.close()
