#!/usr/bin/env python3
"""Focused active-standby LAN/VLAN20 PD packets with two real DHCP providers.

Complements network-v08-smoke.py's four transport pairings. Positive flows use
actual client SLAAC and learned DNS. Deprecated old source addresses are injected
only for explicit negative authorization probes in the disposable client netns.
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
import traceback

spec = importlib.util.spec_from_file_location("v08", Path(__file__).with_name("network-v08-smoke.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
Failure = base.Failure


class Lab(base.Lab):
    def __init__(self, binary):
        super().__init__(binary, "dhcp-dhcp")
        self.vlan_sources = {}

    def fixture(self):
        super().fixture()
        self.namespace("vlan")
        self.connect("vlan", "eth0", "lanhub")
        self.run(["sysctl", "-qw", "net.ipv6.conf.eth0.accept_ra=0",
                  "net.ipv6.conf.eth0.autoconf=0"], "vlan")
        self.run(["ip", "link", "add", "link", "eth0", "name", "tag0", "type", "vlan", "id", "20"], "vlan")
        self.run(["ip", "link", "set", "tag0", "up"], "vlan")
        self.address("vlan", "tag0", "192.168.20.10/24", "192.168.20.1")
        self.run(["sysctl", "-qw", "net.ipv6.conf.tag0.accept_ra=2",
                  "net.ipv6.conf.tag0.autoconf=1"], "vlan")

    def config(self):
        path = super().config()
        source = path.read_text().replace('lan_subnet_id = 0\nvlans = []',
                                        'lan_subnet_id = 0\nvlans = [{ interface = "vlan20", subnet_id = 1 }]')
        source += '\n[[vlans]]\ninterface = "vlan20"\nparent = "lan0"\nid = 20\naddress = "192.168.20.1/24"\ninternet = true\n'
        path.write_text(source)
        self.config_bytes = path.read_bytes()
        return path

    def bound(self, slot, prefix):
        lan = super().bound(slot, prefix)
        net = ipaddress.IPv6Network(prefix)
        vlan = str(ipaddress.IPv6Network((ipaddress.IPv6Address(int(net.network_address) + (1 << 64)), 64)))
        self.wait_for(lambda: len(self.public_status().get("delegated", [])) == 2,
                      slot + " publishes separate LAN/VLAN20 delegated /64s")
        self.wait_for(lambda: self.client_address("vlan", "tag0", vlan), slot + " actual VLAN20 SLAAC")
        address = self.client_address("vlan", "tag0", vlan)
        if ipaddress.IPv6Address(lan) in ipaddress.IPv6Network(vlan):
            raise Failure("LAN and VLAN20 share a delegated /64")
        self.vlan_sources[prefix] = address
        def traffic():
            try:
                self.http("vlan", base.REMOTE6, "WAN-" + slot)
                return True
            except Failure:
                return False
        self.wait_for(traffic, slot + " actual VLAN20 IPv6 HTTP", timeout=30)
        def resolved():
            result = self.run(["busybox", "nslookup", "-type=A", "pd.routertop.test", "192.168.20.1"],
                              "vlan", check=False, timeout=10)
            return result.returncode == 0 and base.ANSWERS[slot] in result.stdout
        self.wait_for(resolved, slot + " actual VLAN20 learned-provider DNS")
        self.passed("VLAN20 " + slot + ": separate actual SLAAC /64, routed IPv6 HTTP and selected-provider DNS")
        return lan

    def retired(self, prefix, address):
        # Keep explicit negative probes meaningful even after a legitimate RA
        # has already removed an old address. Positive flows never use these.
        self.run(["ip", "-6", "address", "replace", address + "/64", "dev", "eth0",
                  "preferred_lft", "0", "valid_lft", "20"], "client")
        super().retired(prefix, address)
        net = ipaddress.IPv6Network(prefix)
        self.wait_for(lambda: not any(ipaddress.IPv6Address(item["local"]) in net
                                     for item in self.addresses("router", "vlan20")), "retired router VLAN20 prefix removed")
        old = self.vlan_sources[prefix]
        self.run(["ip", "-6", "address", "replace", old + "/64", "dev", "tag0",
                  "preferred_lft", "0", "valid_lft", "20"], "vlan")
        self.tcp_source_port += 1
        result = self.run(["curl", "--noproxy", "*", "--silent", "--fail", "--max-time", "3",
                           "--interface", old, "--local-port", str(self.tcp_source_port),
                           "http://[" + base.REMOTE6 + "]:8080/"], "vlan", check=False)
        if result.returncode == 0:
            raise Failure("retired VLAN20 delegated source escaped through new provider")
        self.passed("VLAN20 retired source denied; router old /64 removed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("routertop")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        print(json.dumps({"status": "FAIL", "error": "Linux root required"}))
        return 1
    os.umask(0o077)
    def interrupted(*_):
        raise Failure("interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    lab = Lab(args.routertop)
    failed = False
    try:
        base.exercise(lab)
    except Exception as error:
        failed = True
        if isinstance(error, Failure):
            message = str(error)
        else:
            frame = traceback.extract_tb(error.__traceback__)[-1]
            message = type(error).__name__ + " at " + frame.name + ":" + str(frame.lineno)
        lab.diagnostics(message)
        print(json.dumps({"status": "FAIL", "error": message}), flush=True)
    finally:
        count = len(lab.results)
        lab.close()
    print(json.dumps({"status": "FAIL" if failed else "PASS", "passed_cases": count,
                      "binary_sha256": hashlib.sha256(Path(args.routertop).read_bytes()).hexdigest(),
                      "harness_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      "base_harness_sha256": hashlib.sha256(Path(__file__).with_name("network-v08-smoke.py").read_bytes()).hexdigest()}), flush=True)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
