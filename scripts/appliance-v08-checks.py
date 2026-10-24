#!/usr/bin/env python3
"""Real dual-ISP appliance lifecycle checks; called by browser-v08-smoke.py.

The disposable ISP VM must have a root shell on serial 19411. No production
interface is touched. Private data and raw console output never leave memory.
"""
from __future__ import annotations
import importlib.util
import ipaddress
import json
import re
import secrets
import shlex
import time
from pathlib import Path

CONTROLS = {slot: f"/var/lib/routertop-v08-isp/{slot}/control.json" for slot in ("primary", "backup")}



def connect_isp(module):
    """Open only the owned ISP root console and prove command readiness.

    BusyBox askfirst can consume the first line after a serial reconnect.
    A failed handshake gets one bounded Ctrl-C recovery on this ISP console.
    The authenticated appliance console never uses this helper.
    """
    connection = module.Terminal(19411)
    try:
        for attempt in range(2):
            connection.send("\n" if attempt == 0 else "\x03\n")
            time.sleep(0.2)
            marker = "V08_ISP_READY_" + secrets.token_hex(8)
            connection.send("printf '\\n" + marker + ":%s\\n' \"$(id -u)\"\n")
            try:
                connection.until("\n" + marker + ":0", timeout=10)
                connection.until("\n", timeout=2)
                return connection
            except AssertionError:
                if attempt:
                    raise AssertionError("ISP root console did not acknowledge command readiness") from None
        raise AssertionError("ISP root console readiness failed")
    except Exception:
        connection.close()
        raise


def run_checks(api_get, console_port, password, outputdir):
    spec = importlib.util.spec_from_file_location("wan_console", Path(__file__).with_name("console-v04-smoke.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    router = module.Terminal(console_port)
    isp = connect_isp(module)
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

    def provider_ready(status, slot):
        dynamic = status.get("ipv6_dynamic") or {}
        assignments = {v["interface"]: v for v in dynamic.get("delegated", [])}
        return active(status, slot) and (status["wan"].get(slot) or {}).get("healthy") is True and status["wan"].get("ipv6_active") == slot and dynamic.get("provider") == slot and dynamic.get("phase") == "bound" and dynamic.get("state") == "bound" and {"eth1", "vlan20"}.issubset(assignments)

    def primary_ready(status):
        return provider_ready(status, "primary")

    def ready_prefix(status, slot, prefix):
        return provider_ready(status, slot) and all(ipaddress.IPv6Network(v["prefix"]).subnet_of(ipaddress.IPv6Network(prefix)) for v in status["ipv6_dynamic"]["delegated"])

    def routed_http(marker):
        deadline = time.monotonic() + 25
        while True:
            try:
                router.shell('test "$(wget -qO- -T 4 http://203.0.113.9:8080/)" = ' + shlex.quote(marker))
                router.shell('test "$(wget -qO- -T 4 http://[2001:db8:99::9]:8080/)" = ' + shlex.quote(marker))
                expected_dns = "203.0.113.10" if marker == "WAN-primary" else "203.0.113.20"
                answer = router.shell("nslookup -type=A pd.routertop.test 192.168.88.1")
                assert re.search(r"(?<![0-9.])" + re.escape(expected_dns) + r"(?![0-9.])", answer), "Selected provider DNS answer missing"
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
        paths = ["/data/routertop-dhcpcd/duid", "/data/routertop-dhcpcd/backup-duid", "/run/routertop/wan/pppoe-0/peer", "/run/routertop/wan/pppoe-1/peer"]
        commands = [f"test $(stat -c %a {path}) = 600" for path in paths[2:]]
        output = router.shell(" && ".join(commands) + " && sha256sum " + " ".join(paths))
        values = dict((name, digest) for digest, name in re.findall(r"(?m)^([0-9a-f]{64})\s+(/(?:data/routertop-dhcpcd/(?:duid|backup-duid)|run/routertop/wan/pppoe-[01]/peer))", output))
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
        assert before_saved["config"]["ipv6"]["provider_policy"] == "active-standby", "IPv6 failover must be explicitly enabled"
        initial = wait_for(primary_ready, "Initial primary IPv6/PD missing")
        entries = initial["ipv6_dynamic"]["delegated"]
        assert len({ipaddress.IPv6Network(v["prefix"]) for v in entries}) == len(entries), "Duplicate delegated prefixes"
        routed_http("WAN-primary")
        passed("actual_iso_primary_ipv4_ipv6_pd_egress")

        update("primary", prefix="2001:db8:200::/56")
        renewed = wait_for(lambda s: ready_prefix(s, "primary", "2001:db8:200::/56"), "Primary prefix renewal missing")
        retired(entries)
        routed_http("WAN-primary")
        passed("actual_iso_primary_prefix_renewal_retires_kernel_and_firewall")

        update("primary", blackhole=True)
        switched = wait_for(lambda s: ready_prefix(s, "backup", "2001:db8:300::/56"), "Primary blackhole did not acquire backup IPv6/PD")
        retired(renewed["ipv6_dynamic"]["delegated"])
        routed_http("WAN-backup")
        before_identity = private_identity()
        passed("actual_iso_blackhole_switches_ipv4_ipv6_and_delegated_prefix")

        update("backup", prefix="2001:db8:400::/56")
        backup_renewed = wait_for(lambda s: ready_prefix(s, "backup", "2001:db8:400::/56"), "Backup prefix renewal missing")
        retired(switched["ipv6_dynamic"]["delegated"])
        routed_http("WAN-backup")
        passed("actual_iso_backup_prefix_renewal_retires_kernel_and_firewall")

        update("primary", blackhole=False)
        recovered = wait_for(lambda s: ready_prefix(s, "primary", "2001:db8:200::/56"), "Primary recovery failed")
        retired(backup_renewed["ipv6_dynamic"]["delegated"])
        routed_http("WAN-primary")
        passed("actual_iso_primary_recovery_fails_back_with_new_pd")

        update("primary", pppoe_enabled=False)
        wait_for(lambda s: ready_prefix(s, "backup", "2001:db8:400::/56"), "PPP disconnect did not acquire backup PD")
        routed_http("WAN-backup")
        update("primary", pppoe_enabled=True)
        wait_for(lambda s: ready_prefix(s, "primary", "2001:db8:200::/56"), "PPP reconnect failed", 180)
        routed_http("WAN-primary")
        assert saved() == before_saved and private_identity() == before_identity, "Recovery changed saved settings/identity"
        passed("actual_iso_ppp_disconnect_redial_preserves_settings_credentials_both_duids")
        return {"result":"PASS", "checks":checks, "private_identity_preserved":True, "ipv6_policy":"active-standby", "ipv6_http":"actual routed HTTP through selected provider", "dns":"real local resolver query changes with selected provider", "forwarded_client_packets":"NOT_RUN by appliance hook", "raw_console":"not retained"}
    finally:
        for slot, control in initial_controls.items():
            try:
                update(slot, **{key: control[key] for key in ("blackhole", "pppoe_enabled", "prefix") if key in control})
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
    """Require backup IPv6/PD on the first boot, then recover primary without reboot."""
    spec = importlib.util.spec_from_file_location("initial_v08_console", Path(__file__).with_name("console-v04-smoke.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    router, isp = module.Terminal(console_port), connect_isp(module)
    authenticated = False

    def ready(slot):
        value = api_get("/status")
        dynamic = value.get("ipv6_dynamic") or {}
        return value.get("wan", {}).get("active") == slot and value["wan"].get("ipv6_active") == slot and dynamic.get("provider") == slot and dynamic.get("phase") == "bound" and {"eth1", "vlan20"}.issubset({v["interface"] for v in dynamic.get("delegated", [])})

    def wait(slot):
        deadline = time.monotonic() + 180
        while not ready(slot):
            assert time.monotonic() < deadline, "First-boot provider IPv6/PD missing: " + slot
            time.sleep(1)

    def enable_primary():
        code = "import json,os; p=" + repr(CONTROLS["primary"]) + "; v=json.load(open(p)); v['pppoe_enabled']=True; json.dump(v,open(p+'.new','w')); os.replace(p+'.new',p)"
        isp.shell("python3 -c " + shlex.quote(code))

    try:
        router.send("\n")
        router.until("Password: ")
        router.login(password)
        authenticated = True
        initial = api_get("/config")
        wait("backup")
        try:
            router.shell('test "$(wget -qO- -T 5 http://[2001:db8:99::9]:8080/)" = WAN-backup')
        except AssertionError:
            raise AssertionError("Initial backup IPv6 HTTP functional check failed") from None
        try:
            answer = router.shell("nslookup -type=A pd.routertop.test 192.168.88.1")
            assert "203.0.113.20" in answer
        except AssertionError:
            raise AssertionError("Initial backup DNS functional check failed (IPv6 HTTP passed)") from None
        enable_primary()
        wait("primary")
        router.shell('test "$(wget -qO- -T 5 http://[2001:db8:99::9]:8080/)" = WAN-primary')
        assert api_get("/config") == initial, "Initial provider acquisition changed saved settings"
        return {"result":"PASS", "first_active":"backup", "backup_ipv6_pd_http_dns":True, "primary_recovered_without_reboot":True, "settings_preserved":True}
    finally:
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
