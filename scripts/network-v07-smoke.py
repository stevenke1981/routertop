#!/usr/bin/env python3
"""Real static/DHCP/PPPoE active/standby WAN packets in disposable Linux namespaces.

Uses production rendering, actual udhcpc/pppd clients and production WAN supervisor.
All routes, nft rules, link failures and ISP blackholes stay in owned namespaces.
Private mount namespaces relocate the appliance runtime and executable paths only.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shlex
import signal
import sys
import threading
import time
import traceback

spec = importlib.util.spec_from_file_location("lab06", Path(__file__).with_name("network-v06-smoke.py"))
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)
Failure = old.Failure
REMOTE4 = "203.0.113.9"
MODES = ("static", "static-dhcp", "dhcp-static", "dhcp-dhcp", "dhcp-pppoe", "pppoe-dhcp", "pppoe-pppoe", "pppoe-dhcp-ipv6")


class Lab(old.Lab):
    def __init__(self, binary, scenario):
        super().__init__(binary)
        self.scenario = scenario
        self.mode = scenario
        self.with_ipv6 = scenario.endswith("-ipv6")
        self.protocols = scenario.removesuffix("-ipv6").split("-")
        self.control_paths = {}
        self.credentials = {slot: {"username": "routertop-" + slot, "password": secrets.token_urlsafe(24)}
                            for slot in ("primary", "backup")}
        self.wan_runtime = self.root_runtime / "wan"
        self.router_process = None
        self.config_bytes = None

    def control(self, slot, **changes):
        path = self.control_paths[slot]
        value = json.loads(path.read_text()) if path.exists() else {
            "prefix": "2001:db8:100::/56", "address": "2001:db8:1::2",
            "upstream_prefix": "2001:db8:1::/64", "dns_server": "2001:db8:1::1",
            "t1": 8, "t2": 16, "preferred_lifetime": 24, "valid_lifetime": 32,
            "ra_lifetime": 20, "silent": False, "ra_enabled": False,
            "pppoe_enabled": True, "assign_address": True, "blackhole": False}
        value.update(changes)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(value))
        os.replace(temporary, path)

    def fixture(self):
        for module in ("8021q", "ppp_generic", "ppp_async"):
            self.run(["modprobe", module], check=False)
        for role in ("router", "lanhub", "client", "hub0", "hub1", "primary", "backup"):
            self.namespace(role)
        for role in ("lanhub", "hub0", "hub1"):
            self.run(["ip", "link", "add", "br0", "type", "bridge"], role)
            self.run(["ip", "link", "set", "br0", "up"], role)
        self.connect("router", "lan0", "lanhub")
        self.address("router", "lan0", "192.168.88.1/24")
        self.connect("client", "eth0", "lanhub")
        self.address("client", "eth0", "192.168.88.10/24", "192.168.88.1")
        if self.with_ipv6:
            self.run(["sysctl", "-qw", "net.ipv6.conf.eth0.accept_ra=2", "net.ipv6.conf.eth0.autoconf=1"], "client")
        self.server("router", "192.168.88.1", "LOCAL-MANAGEMENT", 443)
        self.server("router", "0.0.0.0", "ROUTER-LISTENER")
        for index, protocol in enumerate(self.protocols):
            slot = ("primary", "backup")[index]
            self.connect("router", "wan" + str(index), "hub" + str(index))
            self.connect(slot, "eth0", "hub" + str(index))
            self.control_paths[slot] = self.work / (slot + "-control.json")
            self.control(slot)
            credential_file = self.secret_file(slot + "-credentials.json", json.dumps(self.credentials[slot]))
            self.start(slot, [sys.executable, Path(__file__).with_name("fixtures") / "dual-wan-isp.py",
                              "--interface", "eth0", "--mode", protocol,
                              "--runtime", self.work / (slot + "-isp"),
                              "--control-file", self.control_paths[slot],
                              "--status-file", self.work / (slot + "-status.json"),
                              "--credentials-file", credential_file,
                              "--gateway", "198.18." + str(index) + ".1",
                              "--client", "198.18." + str(index) + ".2",
                              "--marker", "WAN-" + slot], slot + "-isp.log")

    def config(self):
        text = 'hostname = "routertop-dual-wan-test"\n'
        for index, protocol in enumerate(self.protocols):
            name = ("wan", "wan_backup")[index]
            slot = ("primary", "backup")[index]
            text += "\n[" + name + "]\ninterface = \"wan" + str(index) + '\"\nmode = ' + json.dumps(protocol) + "\n"
            if protocol == "static":
                text += "[" + name + '.static_ipv4]\naddress = "198.18.' + str(index) + '.2/24"\ngateway = "198.18.' + str(index) + '.1"\n'
            elif protocol == "pppoe":
                text += "[" + name + ".pppoe]\n" + "\n".join(
                    key + " = " + json.dumps(value) for key, value in self.credentials[slot].items()) + "\nmtu = 1492\n"
        if len(self.protocols) == 2:
            text += '''
[failover]
primary_target = "203.0.113.9"
backup_target = "203.0.113.9"
interval_seconds = 2
failure_threshold = 2
recovery_threshold = 2
'''
        text += '''
[lan]
interface = "lan0"
address = "192.168.88.1/24"
[dhcp]
start = "192.168.88.100"
end = "192.168.88.150"
lease_hours = 1
[dns]
upstream = ["203.0.113.9"]
[firewall]
https_port = 443
'''
        if self.with_ipv6:
            text += '''
[ipv6]
wan_mode = "auto"
lan_address = ""
vlans = []
dns_upstream = []
dns_auto = true
[ipv6.pd]
prefix_length = 56
lan_subnet_id = 0
vlans = []
'''
        self.secret_file("routertop.toml", text)
        self.config_bytes = self.config_path.read_bytes()
        return self.config_path

    def install(self):
        config = self.config()
        output = self.work / "rendered"
        self.run([self.binary, "render", config, "--output", output])
        for path in output.iterdir():
            if path.is_file() and any(value["password"] in path.read_text() for value in self.credentials.values()):
                raise Failure("public render contains PPP credentials")
        self.run(["nft", "-c", "-f", output / "nftables.nft"], "router")
        self.run(["nft", "-f", output / "nftables.nft"], "router")
        self.run(["sysctl", "-p", output / "sysctl.conf"], "router")
        self.run(["sh", output / "network-setup.sh"], "router")
        if len(self.protocols) == 1:
            # ifup's /run state is global to the mount namespace. A previous
            # disposable WAN named wan0 must not make a fresh case look as if
            # it is already configured. Real appliance boots also get fresh RAM.
            script = ("mount --make-rprivate /; mount -t tmpfs tmpfs /run; exec ifup -i "
                      + shlex.quote(str(output / "interfaces")) + " wan0")
            self.run(["unshare", "-m", "sh", "-ec", script], "router")
            return
        self.root_runtime.mkdir(mode=0o755, exist_ok=True)
        if self.with_ipv6:
            self.run([self.binary, "ipv6-init", config, self.runtime, self.identity])
            conf = self.runtime / "dhcpcd.conf"
            conf.write_text("env ROUTERTOP_CONFIG=" + str(config) + "\n"
                            "env ROUTERTOP_PD_RUNTIME=" + str(self.runtime) + "\nnodev\n" + conf.read_text())
            dns = (output / "dnsmasq.conf").read_text().replace("/run/routertop/pd", str(self.runtime))
            dns = "\n".join("dhcp-leasefile=" + str(self.work / "leases")
                            if line.startswith("dhcp-leasefile=") else line for line in dns.splitlines()) + "\n"
            self.dns_config = self.work / "dnsmasq.conf"
            self.dns_config.write_text(dns)
            self.restart_dns()
            self.dns_thread = threading.Thread(target=self.watch_dns, daemon=True)
            self.dns_thread.start()
        database = self.work / "dhcpcd-db"
        database.mkdir(mode=0o755)
        pppdir = self.work / "ppp-system"
        pppdir.mkdir(mode=0o700)
        overlay = Path(__file__).resolve().parent.parent / "image/overlay/usr/sbin"
        mappings = [(Path(self.binary), Path("/usr/sbin/routertop"))]
        for name in ("routertop-ppp-ip-up", "routertop-ppp-ip-down", "routertop-ppp-ipv6-up", "routertop-ppp-ipv6-down", "routertop-ipv6-hook"):
            source = self.work / name
            source.write_bytes((overlay / name).read_bytes())
            source.chmod(0o700)
            mappings.append((source, Path("/usr/sbin") / name))
        # Placeholder files live only in the disposable test VM; actual mounts
        # belong to the child mount namespace and vanish when it terminates.
        for _, destination in mappings:
            destination.touch(exist_ok=True)
        script = '#!/bin/sh\nset -eu\nmount --make-rprivate /\nmount -t tmpfs tmpfs /run\nmkdir -p /run/routertop /run/dhcpcd\n'
        for source, destination in [(self.root_runtime, Path("/run/routertop")),
                                    (database, Path("/var/lib/dhcpcd")), (pppdir, Path("/etc/ppp")), *mappings]:
            script += "mount --bind " + shlex.quote(str(source)) + " " + shlex.quote(str(destination)) + "\n"
        if self.with_ipv6:
            script += shlex.quote(self.binary) + " ipv6-monitor " + shlex.quote(str(config)) + " " + shlex.quote(str(self.runtime)) + " >/dev/null 2>&1 &\n"
        script += "exec " + shlex.quote(self.binary) + " wan-run " + shlex.quote(str(config)) + " " + shlex.quote(str(self.wan_runtime)) + "\n"
        wrapper = self.secret_file("wan-start", script)
        wrapper.chmod(0o700)
        self.router_process = self.start("router", ["unshare", "-m", "sh", wrapper], "wan.log")

    def status(self):
        try:
            return json.loads((self.wan_runtime / "status.json").read_text())
        except (OSError, ValueError):
            return {}

    def selected(self, slot):
        if self.status().get("active") != slot:
            return False
        if slot == "none":
            return True
        try:
            self.http("client", REMOTE4, "WAN-" + slot)
            return True
        except Failure:
            return False

    def wait_selected(self, slot, timeout=65):
        self.wait_for(lambda: self.selected(slot), self.scenario + " selects " + slot, timeout=timeout)
        if self.config_path.read_bytes() != self.config_bytes:
            raise Failure("runtime switching rewrote saved settings")

    def ipv6_bound(self, prefix):
        network = ipaddress.IPv6Network(prefix)
        self.wait_for(lambda: self.public_status().get("delegated") and all(
            ipaddress.IPv6Address(item["address"].split("/")[0]) in network
            for item in self.public_status()["delegated"]), "primary real DHCPv6-PD")
        lan = str(ipaddress.IPv6Network((network.network_address, 64)))
        self.wait_for(lambda: self.client_address("client", "eth0", lan), "real primary prefix SLAAC")
        self.client6 = self.client_address("client", "eth0", lan)
        def ready():
            try:
                self.http("client", "2001:db8:99::9", "WAN-primary")
                return True
            except Failure:
                return False
        self.wait_for(ready, "real primary IPv6 HTTP")

    def ipv6_withdrawn(self):
        self.wait_for(lambda: self.public_status().get("delegated") == [], "primary PD withdrawn on backup")
        self.wait_for(lambda: not any(ipaddress.IPv6Address(a["local"]) in ipaddress.IPv6Network("2001:db8::/32")
                                     for a in self.addresses("router", "lan0")), "router retired PD address removal")
        self.http("client", "2001:db8:99::9", allowed=False)
        rules = self.run(["nft", "list", "set", "inet", "routertop", "primary_v6"], "router").stdout
        if '"ppp0"' in rules:
            raise Failure("primary IPv6 authorization remains on backup")

    def cut_carrier(self, index, down):
        # The first routerWAN endpoint uses p3; inspect its actual veth peer
        # index instead of relying on fixture insertion ordering.
        role = "hub" + str(index)
        peers = json.loads(self.run(["ip", "-j", "link", "show"], role).stdout)
        router = json.loads(self.run(["ip", "-j", "link", "show", "wan" + str(index)], "router").stdout)[0]
        peer = next(value["ifname"] for value in peers if value["ifindex"] == router["link_index"])
        self.run(["ip", "link", "set", peer, "down" if down else "up"], role)

    def diagnostics(self, label):
        data = {"diagnostics": label, "scenario": self.scenario, "wan": self.status(), "logs": {}}
        if self.with_ipv6:
            data["ipv6"] = self.public_status()
            path = self.work / "primary-status.json"
            if path.exists():
                data["primary_isp"] = json.loads(path.read_text())
        for filename in ("wan.log", "primary-isp.log", "backup-isp.log"):
            path = self.work / filename
            value = path.read_text(errors="replace").lower() if path.exists() else ""
            data["logs"][filename] = {"present": bool(value), "categories": [
                key for key, token in {"routing": "routing command failed", "invalid_option": "unrecognized option",
                                       "permission": "permission denied", "invalid_config": "invalid",
                                       "no_file": "no such file"}.items() if token in value]}
        data["network"] = {
            "addresses": self.run(["ip", "-j", "-4", "address", "show"], "router", check=False).stdout,
            "routes": self.run(["ip", "-4", "route", "show", "table", "all"], "router", check=False).stdout,
            "rules": self.run(["ip", "-4", "rule", "show"], "router", check=False).stdout,
        }
        print(json.dumps(data), flush=True)

    def close(self):
        # Supervisor-owned clients may outlive a terminated parent. Kill only
        # processes belonging to namespaces created by this exact invocation.
        self.stop_dns.set()
        if self.dns_thread:
            self.dns_thread.join(timeout=5)
        for name in self.namespaces.values():
            result = self.run(["ip", "netns", "pids", name], check=False)
            for value in result.stdout.split():
                try:
                    os.kill(int(value), signal.SIGTERM)
                except ProcessLookupError:
                    pass
        time.sleep(0.3)
        for name in self.namespaces.values():
            result = self.run(["ip", "netns", "pids", name], check=False)
            for value in result.stdout.split():
                try:
                    os.kill(int(value), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        super().close()


def exercise(lab):
    lab.fixture()
    if lab.with_ipv6:
        # Deterministically exercise an initially unavailable PPP primary. A
        # stop request before any IPv6 client exists must not start dhcpcd with
        # its default configuration and strand later PPP prefix acquisition.
        lab.control("primary", pppoe_enabled=False)
    lab.install()
    if len(lab.protocols) == 1:
        lab.wait_for(lambda: lab.http_ready_static(), "standalone static WAN HTTP")
        lab.passed("standalone static IPv4 WAN renders and carries actual LAN NAT HTTP")
        return
    if lab.with_ipv6:
        lab.wait_selected("backup")
        lab.http("client", "192.168.88.1", "LOCAL-MANAGEMENT", port=443)
        time.sleep(2)
        result = lab.run(["nsenter", "-m", "-t", str(lab.router_process.pid), "--", "sh", "-c",
                          "test ! -s /run/dhcpcd/pid"], "router", check=False)
        if result.returncode:
            raise Failure("initial backup selection started an unowned/default-config IPv6 client")
        lab.control("primary", pppoe_enabled=True)
        lab.passed("initially absent PPP primary boots on real DHCP backup without starting a default-config IPv6 client")
    lab.wait_selected("primary")
    lab.wait_for(lambda: lab.status().get("backup", {}).get("healthy") is True, "backup healthy")
    lab.passed(lab.scenario + ": both real uplinks acquire addresses; primary carries NAT HTTP")
    for index, protocol in enumerate(lab.protocols):
        if protocol != "pppoe":
            continue
        slot = ("primary", "backup")[index]
        peer = lab.wan_runtime / ("pppoe-" + str(index)) / "peer"
        if peer.stat().st_mode & 0o077:
            raise Failure("PPP peer credentials are not root-only")
        fixture = json.loads((lab.work / (slot + "-status.json")).read_text())
        messages = fixture.get("pppoe", {}).get("messages", {})
        if not messages.get("padi", 0) or messages.get("underlay_dhcpv4", 0):
            raise Failure("PPP underlay lacks actual discovery or leaked DHCPv4")
    if any(secret["password"] in json.dumps(lab.status()) for secret in lab.credentials.values()):
        raise Failure("public WAN status contains a PPP secret")
    detail = "; PPP peers are private with real discovery and no underlay DHCP" if "pppoe" in lab.protocols else ""
    lab.passed(lab.scenario + ": public status is secret-free" + detail)
    if lab.with_ipv6:
        lab.ipv6_bound("2001:db8:100::/56")
        identity = lab.identity.read_bytes()
        lab.passed("primary PPP IPv6CP/real DHCPv6-PD/SLAAC carry IPv6 HTTP before failover")
    lab.http("router", "127.0.0.1", "ROUTER-LISTENER")
    for index, protocol in enumerate(lab.protocols):
        slot = ("primary", "backup")[index]
        status = lab.status()[slot]
        expected_dev = "ppp" + str(index) if protocol == "pppoe" else "wan" + str(index)
        if status.get("logical_interface") != expected_dev:
            raise Failure("logical uplink does not match selected protocol")
        address = status.get("ipv4_address")
        if not address:
            raise Failure("real uplink has no acquired IPv4 address")
        lab.http(slot, address, allowed=False)
    lab.passed(lab.scenario + ": both WANs deny unsolicited access to a live router listener")
    lab.cut_carrier(0, True)
    lab.wait_selected("backup")
    if lab.with_ipv6:
        lab.ipv6_withdrawn()
        lab.passed("backup IPv4 selection withdraws primary delegated addresses and IPv6 firewall authorization")
    lab.http("client", "192.168.88.1", "LOCAL-MANAGEMENT", port=443)
    lab.passed(lab.scenario + ": actual primary carrier loss switches traffic to backup; management remains available")
    lab.cut_carrier(0, False)
    lab.wait_selected("primary")
    if lab.with_ipv6:
        lab.control("primary", prefix="2001:db8:200::/56")
        lab.ipv6_bound("2001:db8:200::/56")
        if lab.identity.read_bytes() != identity:
            raise Failure("primary recovery changed persistent DHCPv6 identity")
        lab.passed("primary return reacquires changed prefix and real IPv6 traffic with stable saved identity")
    lab.passed(lab.scenario + ": primary carrier restoration automatically restores preferred uplink")
    lab.control("primary", blackhole=True)
    lab.wait_selected("backup")
    if lab.with_ipv6:
        lab.ipv6_withdrawn()
        lab.passed("upstream IPv4 blackhole also withdraws live primary PD despite PPP IPv6CP remaining up")
    for _ in range(3):
        time.sleep(3)
        if not lab.selected("backup") or lab.status()["primary"].get("healthy") is True:
            raise Failure("failed primary probe leaked through healthy backup")
    lab.passed(lab.scenario + ": upstream blackhole with carrier up triggers failover; backup success cannot falsely recover primary")
    lab.control("backup", blackhole=True)
    lab.wait_selected("none")
    lab.http("client", REMOTE4, allowed=False)
    lab.http("client", "192.168.88.1", "LOCAL-MANAGEMENT", port=443)
    lab.passed(lab.scenario + ": both upstreams down fail closed while LAN management stays available")
    lab.control("primary", blackhole=False)
    lab.control("backup", blackhole=False)
    lab.wait_selected("primary")
    lab.passed(lab.scenario + ": upstream restoration recovers primary without rewriting saved configuration")


def http_ready_static(self):
    try:
        self.http("client", REMOTE4, "WAN-primary")
        return True
    except Failure:
        return False


Lab.http_ready_static = http_ready_static


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("routertop")
    parser.add_argument("--case", choices=MODES, action="append", dest="cases")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        print(json.dumps({"status": "FAIL", "error": "Linux root required"}))
        return 1
    os.umask(0o077)
    def interrupted(*_):
        raise Failure("interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    failed = False
    total = 0
    for scenario in args.cases or MODES:
        lab = Lab(args.routertop, scenario)
        try:
            exercise(lab)
        except Exception as error:
            if isinstance(error, Failure):
                message = str(error)
            else:
                frame = traceback.extract_tb(error.__traceback__)[-1]
                message = type(error).__name__ + " at " + frame.name + ":" + str(frame.lineno)
            lab.diagnostics(message)
            print(json.dumps({"status": "FAIL", "scenario": scenario, "error": message}), flush=True)
            failed = True
        finally:
            total += len(lab.results)
            lab.close()
        if failed:
            break
    print(json.dumps({"status": "FAIL" if failed else "PASS", "passed_cases": total,
                      "binary_sha256": hashlib.sha256(Path(args.routertop).read_bytes()).hexdigest()}), flush=True)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
