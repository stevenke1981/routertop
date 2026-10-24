#!/usr/bin/env python3
"""Real active/standby DHCPv6-PD over all DHCP/PPPoE provider pairings.

Synthetic ISPs exchange actual DHCPv4/PPP/DHCPv6/RA packets in disposable Linux
namespaces. Production rendering, WAN hysteresis, hooks and PD monitor run
unchanged; private mount namespaces relocate appliance filesystem paths only.
"""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import signal
import sys
import time
import traceback

spec = importlib.util.spec_from_file_location("lab07", Path(__file__).with_name("network-v07-smoke.py"))
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)
Failure = old.Failure
MODES = ("dhcp-dhcp", "dhcp-pppoe", "pppoe-dhcp", "pppoe-pppoe")
PREFIXES = {"primary": "2001:db8:100::/56", "backup": "2001:db8:300::/56"}
CHANGED = {"primary": "2001:db8:200::/56", "backup": "2001:db8:400::/56"}
DNS = {"primary": "2001:db8:1::1", "backup": "2001:db8:2::1"}
ANSWERS = {"primary": "203.0.113.10", "backup": "203.0.113.20"}
REMOTE6 = "2001:db8:99::9"


class Lab(old.Lab):
    def __init__(self, binary, scenario, wg_failclosed=False):
        self.wg_failclosed = wg_failclosed
        self.wg_prepared = False
        super().__init__(binary, scenario + "-ipv6")
        self.scenario = scenario
        self.mode = scenario
        self.prefixes = dict(PREFIXES)

    def run(self, args, namespace=None, **kwargs):
        if (self.wg_failclosed and len(args) == 2 and str(args[0]) == "sh"
                and str(args[1]).endswith("network-setup.sh") and not self.wg_prepared):
            self.wg_prepared = True
            state = self.work / "state"
            keys = self.work / "wireguard"
            super().run([self.binary, "storage-init", state, self.config_path])
            super().run([self.binary, "wg-configs", state, keys])
            source = Path(args[1]).read_text().replace("/run/routertop/wireguard/", str(keys) + "/")
            setup = self.work / "network-setup-relocated.sh"
            setup.write_text(source)
            args = ["sh", setup]
        return super().run(args, namespace, **kwargs)

    def fixture(self):
        super().fixture()
        if self.wg_failclosed:
            private = self.run(["wg", "genkey"]).stdout.strip()
            self.peer_public = self.run(["wg", "pubkey"], input_text=private + "\n").stdout.strip()

    def control(self, slot, **changes):
        fresh = not self.control_paths[slot].exists()
        if fresh:
            number = 1 if slot == "primary" else 2
            changes = dict(prefix=PREFIXES[slot], address=f"2001:db8:{number}::2",
                           upstream_prefix=f"2001:db8:{number}::/64", dns_server=DNS[slot],
                           ra_enabled=self.protocols[0 if slot == "primary" else 1] == "dhcp", **changes)
        super().control(slot, **changes)

    def start(self, role, args, logfile):
        args = list(args)
        if any(str(value).endswith("dual-wan-isp.py") for value in args):
            args += ["--ipv6", "--dns-answer", ANSWERS[role]]
        return super().start(role, args, logfile)

    def config(self):
        path = super().config()
        path.write_text(path.read_text().replace("[ipv6]\n", '[ipv6]\nprovider_policy = "active-standby"\n'))
        if self.wg_failclosed:
            with path.open("a") as stream:
                stream.write('\n[[wireguard]]\ninterface = "wg0"\naddress = "10.44.0.1/24"\n'
                             'address_v6 = "fd44::1/64"\nlisten_port = 51820\nmtu = 1420\n'
                             'internet = false\nfull_tunnel = true\nnat66 = true\n'
                             '[[wireguard.peers]]\npublic_key = ' + json.dumps(self.peer_public) + '\n'
                             'allowed_ips = ["0.0.0.0/0", "::/0"]\n'
                             'endpoint = "203.0.113.9:51821"\npersistent_keepalive = 1\n')
        self.config_bytes = path.read_bytes()
        return path

    def selected(self, slot):
        if self.wg_failclosed:
            return self.status().get("active") == slot
        return super().selected(slot)

    def active_clients(self):
        # dhcpcd privilege-separation proxies are children of the single manager;
        # count actual manager processes, scoped to this invocation's router netns.
        pids = self.run(["ip", "netns", "pids", self.namespaces["router"]]).stdout.split()
        managers = []
        for pid in pids:
            try:
                proc = Path("/proc") / pid
                if (proc / "exe").resolve().name == "dhcpcd" and b"[manager]" in (proc / "cmdline").read_bytes():
                    managers.append(pid)
            except (OSError, ProcessLookupError):
                pass
        return managers

    def bound(self, slot, prefix):
        network = ipaddress.IPv6Network(prefix)
        def published():
            value = self.public_status()
            delegated = value.get("delegated", [])
            return value.get("provider") == slot and bool(delegated) and all(
                ipaddress.IPv6Address(item["address"].split("/")[0]) in network for item in delegated)
        self.wait_for(published, slot + " actual selected provider PD", timeout=65)
        lan = str(ipaddress.IPv6Network((network.network_address, 64)))
        self.wait_for(lambda: self.client_address("client", "eth0", lan), slot + " actual SLAAC", timeout=40)
        self.client6 = self.client_address("client", "eth0", lan)
        def traffic():
            try:
                self.http("client", REMOTE6, "WAN-" + slot)
                return True
            except Failure:
                return False
        self.wait_for(traffic, slot + " actual IPv6 forwarded HTTP", timeout=30)
        self.wait_for(lambda: self.public_status().get("dns_servers") == [DNS[slot]], slot + " learned DNS ownership")
        def resolved():
            result = self.run(["busybox", "nslookup", "-type=A", "pd.routertop.test", "192.168.88.1"],
                              "client", check=False, timeout=10)
            return result.returncode == 0 and ANSWERS[slot] in result.stdout
        self.wait_for(resolved, slot + " actual learned IPv6 DNS query")
        index = int(slot == "backup")
        expected = ("ppp" if self.protocols[index] == "pppoe" else "wan") + str(index)
        defaults = self.run(["ip", "-j", "-6", "route", "show", "default"], "router").stdout
        routes = json.loads(defaults)
        if not routes or any(route.get("dev") != expected for route in routes):
            raise Failure("standby IPv6 default route leaked into main table")
        self.wait_for(lambda: self.status().get("ipv6_active") == slot,
                      "WAN public IPv6 active provider converges with real PD", timeout=10)
        if len(self.active_clients()) != 1:
            raise Failure("selected provider does not own exactly one actual DHCPv6 manager")
        self.http("router", REMOTE6, "WAN-" + slot)
        self.http("client", "192.168.88.1", "LOCAL-MANAGEMENT", port=443)
        if self.config_path.read_bytes() != self.config_bytes:
            raise Failure("runtime changed saved provider settings")
        return self.client6

    def origin_epoch(self):
        provider = json.loads((self.runtime / "provider.json").read_text())
        slot = provider["slot"]
        if slot == "primary":
            slot = 0
        elif slot == "backup":
            slot = 1
        return ":".join(str(value) for value in (provider["boot"], provider["generation"], slot,
                                                provider["logical_interface"], provider.get("incarnation", "")))

    def provider_view(self):
        value = self.public_status()
        # Lease timers legitimately tick or renew while a delayed hook is tested.
        # Compare ownership and addresses, not wall-clock lifetime snapshots.
        value["delegated"] = [{key: item.get(key) for key in ("address", "interface", "prefix")}
                              for item in value.get("delegated", [])]
        return value

    def stale_ppp_down(self, origin):
        if origin is None:
            return
        current = json.loads((self.wan_runtime / "ppp-owner-0.json").read_text())["incarnation"]
        if origin == current:
            raise Failure("PPP recovery did not create a fresh process incarnation")
        before = self.provider_view()
        lease = (self.wan_runtime / "lease-0.json").read_bytes()
        for event in ("ipv4-down", "ipv6-down"):
            self.run(["env", "ROUTERTOP_PPP_SESSION=" + origin, self.binary,
                      "pppoe-event", self.config_path, self.wan_runtime / "pppoe-0", event, "ppp0"], "router")
        after = self.provider_view()
        if (self.wan_runtime / "lease-0.json").read_bytes() != lease:
            raise Failure("old PPP down callback erased current IPv4 lease")
        for key in ("provider", "generation", "logical_interface", "delegated", "dns_servers"):
            if before.get(key) != after.get(key):
                raise Failure("old PPP down callback revoked live provider " + key)

    def stale_events(self, epoch, interface):
        before = self.provider_view()
        for reason in ("BOUND6", "STOP6", "EXPIRE6"):
            self.run(["env", "ROUTERTOP_PD_EPOCH=" + epoch, "interface=" + interface, "reason=" + reason,
                      "new_dhcp6_ia_pd1_prefix1=2001:db8:666::", "new_dhcp6_ia_pd1_prefix1_length=56",
                      "new_dhcp6_ia_pd1_prefix1_vltime=300", "new_dhcp6_ia_pd1_prefix1_pltime=150",
                      "new_dhcp6_name_servers=2001:db8:666::1", self.binary,
                      "ipv6-event", self.config_path, self.runtime], "router")
        after = self.provider_view()
        for key in ("provider", "generation", "logical_interface", "delegated", "dns_servers"):
            if before.get(key) != after.get(key):
                raise Failure("old A-to-B-to-A callback changed live provider " + key)

    def prefix_counter(self, slot, prefix):
        # Observe packets at the ISP, independently of return-path availability.
        self.run(["nft", "add", "rule", "inet", "routertop_test_isp", "upstream",
                  "ip6", "saddr", prefix, "counter"], slot)

    def assert_no_retired_packets(self, slot):
        rules = json.loads(self.run(["nft", "-j", "list", "chain", "inet", "routertop_test_isp", "upstream"], slot).stdout)
        counters = [expression["counter"]["packets"] for entry in rules.get("nftables", [])
                    for expression in entry.get("rule", {}).get("expr", []) if "counter" in expression]
        if not counters or any(counters):
            raise Failure("retired prefix packets reached new ISP, including established TCP flow")

    def begin_stream(self, address):
        counter = self.work / "stream-client-count"
        source = ("import socket,sys,time,pathlib; s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);"
                  "s.settimeout(3);s.bind((sys.argv[1],0));s.connect(('2001:db8:99::9',8081));"
                  "n=0\nwhile True:\n s.sendall(b'routertop-v08\\n');n+=1;pathlib.Path(sys.argv[2]).write_text(str(n));time.sleep(.2)")
        self.start("client", [sys.executable, "-c", source, address, counter], "stream-client.log")
        self.wait_for(lambda: counter.exists() and int(counter.read_text() or "0") >= 3, "actual established IPv6 TCP stream")

    def retired(self, prefix, address):
        network = ipaddress.IPv6Network(prefix)
        self.wait_for(lambda: not any(ipaddress.IPv6Address(value["local"]) in network
                                     for value in self.addresses("router", "lan0")), "retired router prefix removed")
        # Preserve real client RA state: no manual address flush or source override
        # is used for the successful flow. Explicit old-source traffic must fail.
        self.tcp_source_port += 1
        result = self.run(["curl", "--noproxy", "*", "--silent", "--fail", "--max-time", "3",
                           "--interface", address, "--local-port", str(self.tcp_source_port),
                           "http://[" + REMOTE6 + "]:8080/"], "client", check=False)
        if result.returncode == 0:
            raise Failure("retired delegated source escaped through new provider")

    def diagnostics(self, label):
        super().diagnostics(label)
        print(json.dumps({"diagnostics_v08": label, "scenario": self.scenario,
                          "ipv6": self.public_status(),
                          "ipv6_routes": self.run(["ip", "-6", "route", "show", "table", "all"], "router", check=False).stdout,
                          "provider_files": [path.name for path in self.runtime.iterdir()] if self.runtime.exists() else []}), flush=True)


def exercise(lab):
    lab.fixture()
    initial_backup_identity = None
    if lab.protocols[0] == "pppoe":
        lab.control("primary", pppoe_enabled=False)
    lab.install()
    if lab.protocols[0] == "pppoe":
        lab.wait_selected("backup")
        lab.bound("backup", PREFIXES["backup"])
        initial_backup_identity = lab.identity.with_name("backup-duid").read_bytes()
        lab.control("primary", pppoe_enabled=True)
        lab.passed(lab.scenario + ": absent PPP primary boots with actual backup PD/DNS and exactly one DHCPv6 manager")
    lab.wait_selected("primary")
    first = lab.bound("primary", PREFIXES["primary"])
    identity = lab.identity.read_bytes()
    first_epoch = lab.origin_epoch()
    first_interface = lab.public_status()["logical_interface"]
    first_ppp = json.loads((lab.wan_runtime / "ppp-owner-0.json").read_text())["incarnation"] if lab.protocols[0] == "pppoe" else None
    lab.wait_for(lambda: lab.status().get("backup", {}).get("healthy") is True, "backup health readiness")
    lab.passed(lab.scenario + ": primary real PD/SLAAC/IPv6 HTTP/DNS; standby has no IPv6 default")
    lab.begin_stream(first)
    lab.prefix_counter("backup", PREFIXES["primary"])
    lab.cut_carrier(0, True)
    lab.wait_selected("backup")
    backup = lab.bound("backup", PREFIXES["backup"])
    backup_identity = lab.identity.with_name("backup-duid").read_bytes()
    if initial_backup_identity is not None and backup_identity != initial_backup_identity:
        raise Failure("initial backup selection changed stable backup identity")
    if identity == backup_identity:
        raise Failure("providers share the same persistent DHCPv6 identity")
    lab.retired(PREFIXES["primary"], first)
    lab.assert_no_retired_packets("backup")
    lab.passed(lab.scenario + ": carrier loss selects backup real PD/DNS and blocks retired primary source")
    lab.control("primary", prefix=CHANGED["primary"])
    lab.cut_carrier(0, False)
    lab.wait_selected("primary")
    second = lab.bound("primary", CHANGED["primary"])
    lab.retired(PREFIXES["backup"], backup)
    lab.stale_events(first_epoch, first_interface)
    lab.stale_ppp_down(first_ppp)
    lab.bound("primary", CHANGED["primary"])
    if lab.identity.read_bytes() != identity:
        raise Failure("primary reconnect changed saved DHCPv6 identity")
    lab.passed(lab.scenario + ": reconnect restores changed primary prefix and DNS with stable identity")
    lab.control("backup", prefix=CHANGED["backup"])
    lab.control("primary", blackhole=True)
    lab.wait_selected("backup")
    lab.bound("backup", CHANGED["backup"])
    if lab.identity.with_name("backup-duid").read_bytes() != backup_identity:
        raise Failure("backup reconnect changed saved DHCPv6 identity")
    lab.retired(CHANGED["primary"], second)
    for _ in range(3):
        time.sleep(2)
        if lab.status().get("active") != "backup" or lab.status().get("primary", {}).get("healthy") is True:
            raise Failure("failed primary health probe escaped via backup")
    lab.passed(lab.scenario + ": carrier-up upstream blackhole switches real IPv6 prefix and learned DNS")
    lab.control("backup", blackhole=True)
    lab.wait_selected("none")
    lab.wait_for(lambda: lab.public_status().get("delegated") == [], "both-down PD withdrawal")
    lab.wait_for(lambda: lab.active_clients() == [], "both-down no stray default-config DHCPv6 manager")
    lab.http("client", REMOTE6, allowed=False)
    lab.http("router", REMOTE6, allowed=False)
    lab.http("client", "192.168.88.1", "LOCAL-MANAGEMENT", port=443)
    lab.passed(lab.scenario + ": both providers down fail closed for LAN and router IPv6; management survives")
    lab.control("primary", blackhole=False)
    lab.control("backup", blackhole=False)
    lab.wait_selected("primary")
    lab.bound("primary", CHANGED["primary"])
    if lab.identity.read_bytes() != identity:
        raise Failure("restoration changed stable identity")
    lab.passed(lab.scenario + ": recovery restores real IPv6/DNS without rewriting saved settings")


def exercise_wg_failclosed(lab):
    lab.fixture()
    # Prove both plaintext destinations exist before measuring blocked flows.
    for slot in ("primary", "backup"):
        def ready():
            try:
                lab.http(slot, old.REMOTE4, "WAN-" + slot)
                lab.http(slot, REMOTE6, "WAN-" + slot)
                return True
            except Failure:
                return False
        lab.wait_for(ready, slot + " real plaintext fixture readiness")
    lab.install()
    lab.wait_selected("primary")
    for slot in ("primary", "backup"):
        for expression in (("ip", "daddr", old.REMOTE4, "tcp", "dport", "8080"),
                           ("ip6", "daddr", REMOTE6, "tcp", "dport", "8080"),
                           ("udp", "dport", "53"), ("tcp", "dport", "53")):
            lab.run(["nft", "add", "rule", "inet", "routertop_test_isp", "upstream", *expression, "counter"], slot)
    links = json.loads(lab.run(["ip", "-d", "-j", "link", "show", "dev", "wg0"], "router").stdout)
    if links[0].get("linkinfo", {}).get("info_kind") != "wireguard":
        raise Failure("full-tunnel leak test lacks actual kernel WireGuard interface")
    identities = {name: lab.identity.with_name(name).read_bytes() for name in ("duid", "backup-duid")}

    def bound(slot, prefix):
        net = ipaddress.IPv6Network(prefix)
        def published():
            status = lab.public_status()
            return status.get("provider") == slot and bool(status.get("delegated")) and all(
                ipaddress.IPv6Address(item["address"].split("/")[0]) in net for item in status["delegated"])
        lab.wait_for(published, "WG unavailable retains actual " + slot + " PD", timeout=65)
        lan = str(ipaddress.IPv6Network((net.network_address, 64)))
        lab.wait_for(lambda: lab.client_address("client", "eth0", lan), "WG unavailable retains actual client SLAAC")
        if lab.public_status().get("dns_servers") or (lab.runtime / "resolv.conf").read_text().strip():
            raise Failure("full tunnel adopted outside WAN-learned DNS")
        if len(lab.active_clients()) != 1:
            raise Failure("full tunnel does not retain one selected DHCPv6 manager")

    def blocked(slot):
        for role in ("client", "router"):
            lab.http(role, old.REMOTE4, allowed=False)
            lab.http(role, REMOTE6, allowed=False)
        query = lab.run(["timeout", "4", "busybox", "nslookup", "-type=A", "pd.routertop.test", "192.168.88.1"],
                        "client", check=False, timeout=8)
        if query.returncode == 0:
            raise Failure("unavailable full tunnel resolved through direct WAN DNS")
        for provider in ("primary", "backup"):
            lab.assert_no_retired_packets(provider)
        lab.http("client", "192.168.88.1", "LOCAL-MANAGEMENT", port=443)
        if lab.config_path.read_bytes() != lab.config_bytes:
            raise Failure("WG provider switching changed saved settings")
        handshakes = lab.run(["wg", "show", "wg0", "latest-handshakes"], "router").stdout.splitlines()
        if not handshakes or any(line.split()[-1] != "0" for line in handshakes):
            raise Failure("unavailable peer test unexpectedly has a working handshake")
        lab.passed("active-standby + WG unavailable: " + slot + " actual PD remains; client/router IPv4/IPv6 and outside DNS plaintext counters all zero")

    bound("primary", PREFIXES["primary"])
    first_generation = lab.public_status()["generation"]
    blocked("primary")
    lab.control("primary", prefix=CHANGED["primary"])
    bound("primary", CHANGED["primary"])
    if lab.public_status()["generation"] != first_generation:
        raise Failure("ordinary PD renewal changed provider generation")
    blocked("primary")
    lab.cut_carrier(0, True)
    lab.wait_selected("backup")
    bound("backup", PREFIXES["backup"])
    if lab.public_status()["generation"] <= first_generation:
        raise Failure("provider switch did not advance generation")
    blocked("backup")
    for name, value in identities.items():
        if lab.identity.with_name(name).read_bytes() != value:
            raise Failure("WG provider switch changed stable identity")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("routertop")
    parser.add_argument("--case", choices=MODES, action="append", dest="cases")
    parser.add_argument("--wg-failclosed", action="store_true", help="one actual unavailable-peer full-tunnel guard case")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        print(json.dumps({"status": "FAIL", "error": "Linux root required"}))
        return 1
    os.umask(0o077)
    def interrupted(*_):
        raise Failure("interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    failed, total = False, 0
    for scenario in (["dhcp-dhcp"] if args.wg_failclosed else args.cases or MODES):
        lab = Lab(args.routertop, scenario, args.wg_failclosed)
        try:
            (exercise_wg_failclosed if args.wg_failclosed else exercise)(lab)
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
