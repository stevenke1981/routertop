#!/usr/bin/env python3
"""Root-only disposable Linux VM acceptance for generated RouterTop networking.

All links, routes, forwarding settings and firewall mutations occur in uniquely
named network namespaces. The host's networking is never reconfigured. Temporary
WireGuard secrets are mode 0600 and removed in finally; output contains no keys.
Requires: Python 3, iproute2, nftables, wg, dnsmasq, curl, BusyBox udhcpc/ping.
Usage: python3 scripts/network-v03-smoke.py ./target/release/routertop
"""

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time


class Failure(Exception):
    pass


class Lab:
    def __init__(self, binary):
        self.binary = str(Path(binary).resolve()) if "/" in binary else binary
        self.directory = tempfile.TemporaryDirectory(prefix="routertop-v03-")
        self.work = Path(self.directory.name)
        os.chmod(self.work, 0o700)
        self.prefix = "rt3-" + secrets.token_hex(3)
        self.namespaces = {}
        self.children = []
        self.results = []
        self.link_index = 0
        self.config_generation = 0
        self.tcp_source_port = 40000

    def run(self, args, namespace=None, check=True, timeout=20, input_text=None):
        argv = [str(arg) for arg in args]
        if namespace:
            argv = ["ip", "netns", "exec", self.namespaces[namespace], *argv]
        try:
            result = subprocess.run(argv, input=input_text, capture_output=True,
                                    text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            raise Failure("command timed out: " + str(args[0])) from None
        if check and result.returncode:
            # Do not echo argv, stdin, stderr or generated files: any may contain
            # key material when a third-party command reports configuration errors.
            raise Failure("command failed: " + str(args[0]) +
                          " (exit " + str(result.returncode) + ")")
        return result

    def secret_file(self, name, text):
        path = self.work / name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(text)
        return path

    def namespace(self, role):
        name = self.prefix + "-" + role
        self.run(["ip", "netns", "add", name])
        self.namespaces[role] = name
        self.run(["ip", "link", "set", "lo", "up"], role)

    def connect(self, role, interface, switch):
        self.link_index += 1
        peer = "p" + str(self.link_index)
        self.run(["ip", "link", "add", interface, "type", "veth", "peer", "name", peer], role)
        self.run(["ip", "link", "set", peer, "netns", self.namespaces[switch]], role)
        self.run(["ip", "link", "set", peer, "master", "br0"], switch)
        self.run(["ip", "link", "set", peer, "up"], switch)
        self.run(["ip", "link", "set", interface, "up"], role)

    def address(self, role, interface, address, gateway=None):
        self.run(["ip", "address", "add", address, "dev", interface], role)
        if gateway:
            self.run(["ip", "route", "add", "default", "via", gateway], role)

    def start(self, role, args, logfile):
        stream = open(self.work / logfile, "w", encoding="utf-8")
        process = subprocess.Popen(["ip", "netns", "exec", self.namespaces[role],
                                    *map(str, args)], stdout=stream, stderr=stream)
        stream.close()
        self.children.append(process)
        return process

    def http_server(self, role, marker):
        directory = self.work / ("www-" + role)
        directory.mkdir()
        (directory / "index.html").write_text(marker, encoding="ascii")
        self.start(role, [sys.executable, "-m", "http.server", "8080", "--bind",
                          "0.0.0.0", "--directory", directory], role + ".log")

    def http(self, role, address, expected=None, allowed=True):
        # A new tuple must be used after every rule change: generated system
        # established/related rules intentionally precede user rules.
        self.tcp_source_port += 1
        result = self.run(["curl", "--noproxy", "*", "--fail", "--silent",
                           "--max-time", "3", "--connect-timeout", "2",
                           "--local-port", str(self.tcp_source_port),
                           "http://" + address + ":8080/"], role, check=False)
        success = result.returncode == 0 and result.stdout == expected
        if allowed and not success:
            raise Failure("HTTP traffic expected to pass: " + role + " -> " + address)
        if not allowed and result.returncode == 0:
            raise Failure("HTTP traffic unexpectedly passed: " + role + " -> " + address)

    def ping(self, role, address, allowed=True):
        result = self.run(["busybox", "ping", "-c", "1", "-W", "2", address],
                          role, check=False, timeout=5)
        if (result.returncode == 0) != allowed:
            raise Failure("unexpected ICMP result: " + role + " -> " + address)

    def passed(self, name):
        self.results.append({"case": name, "status": "PASS"})
        print(json.dumps(self.results[-1]), flush=True)

    def render(self, peer_public, rules):
        self.config_generation += 1
        config = self.work / ("config-" + str(self.config_generation) + ".toml")
        output = self.work / ("render-" + str(self.config_generation))
        source = '''hostname = "routertop-v03-smoke"
[wan]
interface = "wan0"
[lan]
interface = "lan0"
address = "192.168.88.1/24"
[dhcp]
start = "192.168.88.100"
end = "192.168.88.150"
lease_hours = 1
[dns]
upstream = ["198.18.0.1"]
[firewall]
https_port = 443
'''
        for rule in rules:
            source += "\n[[firewall.rules]]\n"
            for key, value in rule.items():
                source += key + " = " + json.dumps(value) + "\n"
        source += '''
[[vlans]]
interface = "vlan20"
parent = "lan0"
id = 20
address = "192.168.20.1/24"
internet = true
[vlans.dhcp]
start = "192.168.20.100"
end = "192.168.20.150"
lease_hours = 1
[[vlans]]
interface = "vlan30"
parent = "lan0"
id = 30
address = "192.168.30.1/24"
internet = false
[[wireguard]]
interface = "wg0"
address = "10.44.0.1/24"
listen_port = 51820
mtu = 1420
internet = false
[[wireguard.peers]]
public_key = "''' + peer_public + '''"
allowed_ips = ["10.44.0.2/32"]
endpoint = "198.18.0.3:51821"
persistent_keepalive = 0
'''
        config.write_text(source, encoding="ascii")
        self.run([self.binary, "render", config, "--output", output])
        return config, output

    def firewall(self, peer_public, rules):
        _, output = self.render(peer_public, rules)
        self.run(["nft", "-c", "-f", output / "nftables.nft"], "router")
        self.run(["nft", "-f", output / "nftables.nft"], "router")

    def setup_peer(self, role, private, router_public, address, port):
        config = self.secret_file(role + "-wg.conf", "[Interface]\nPrivateKey = " + private +
                                  "\nListenPort = " + str(port) + "\n[Peer]\nPublicKey = " +
                                  router_public + "\nAllowedIPs = 10.44.0.1/32, 192.168.20.0/24\n"
                                  "Endpoint = 198.18.0.2:51820\nPersistentKeepalive = 0\n")
        self.run(["ip", "link", "add", "wg0", "type", "wireguard"], role)
        self.run(["wg", "setconf", "wg0", config], role)
        self.address(role, "wg0", address)
        self.run(["ip", "link", "set", "wg0", "up"], role)
        self.run(["ip", "route", "add", "192.168.20.0/24", "dev", "wg0"], role)

    def close(self):
        for process in self.children:
            if process.poll() is None:
                process.terminate()
        for process in self.children:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        for name in reversed(list(self.namespaces.values())):
            # Each namespace was successfully created by this exact invocation.
            self.run(["ip", "netns", "delete", name], check=False)
        self.directory.cleanup()


def rule(identifier, action, incoming, outgoing=None, protocol="tcp", port=8080, enabled=True):
    value = {"id": identifier, "enabled": enabled,
             "chain": "forward" if outgoing else "input", "action": action,
             "protocol": protocol, "in_interface": incoming, "comment": "smoke fixture"}
    if outgoing:
        value["out_interface"] = outgoing
    if port is not None:
        value["destination_port"] = port
    return value


def exercise(lab):
    for module in ("8021q", "wireguard"):
        # May already be built into the kernel. Actual link creation below is
        # the decisive capability test, not modprobe's module-file availability.
        lab.run(["modprobe", module], check=False)
    for role in ("router", "trunk", "wanhub", "v20a", "v20b", "v30", "lan", "wan", "peer", "bad"):
        lab.namespace(role)
    for switch in ("trunk", "wanhub"):
        lab.run(["ip", "link", "add", "br0", "type", "bridge"], switch)
        lab.run(["ip", "link", "set", "br0", "up"], switch)
    lab.connect("router", "lan0", "trunk")
    lab.connect("router", "wan0", "wanhub")
    lab.address("router", "lan0", "192.168.88.1/24")
    lab.address("router", "wan0", "198.18.0.2/24", "198.18.0.1")
    for role, suffix in (("wan", 1), ("peer", 3), ("bad", 4)):
        lab.connect(role, "eth0", "wanhub")
        lab.address(role, "eth0", "198.18.0." + str(suffix) + "/24")
    for role, tag, address in (("v20a", 20, None), ("v20b", 20, "192.168.20.10/24"),
                               ("v30", 30, "192.168.30.10/24")):
        lab.connect(role, "eth0", "trunk")
        lab.run(["ip", "link", "add", "link", "eth0", "name", "tag0", "type", "vlan", "id", tag], role)
        lab.run(["ip", "link", "set", "tag0", "up"], role)
        if address:
            lab.address(role, "tag0", address, "192.168." + str(tag) + ".1")
    lab.connect("lan", "eth0", "trunk")
    lab.address("lan", "eth0", "192.168.88.10/24", "192.168.88.1")

    private = lab.run(["wg", "genkey"]).stdout.strip()
    public = lab.run(["wg", "pubkey"], input_text=private + "\n").stdout.strip()
    base = [rule("wg-ping-router", "accept", "wg0", protocol="icmp", port=None)]
    config, output = lab.render(public, base)
    # The WAN subnet comes from a live address/lease rather than the saved
    # schema. Run the production preflight in the isolated router namespace.
    lab.run([lab.binary, "network-check", config], "router")
    baseline_source = config.read_text(encoding="ascii")
    gateway_before = json.loads(lab.run(
        ["ip", "-j", "route", "get", "198.18.0.1"], "router").stdout)[0]["dev"]
    if gateway_before != "wan0":
        raise Failure("WAN fixture gateway is not on wan0 before preflight")
    bad_sources = {
        "peer-captures-wan": baseline_source.replace(
            'allowed_ips = ["10.44.0.2/32"]',
            'allowed_ips = ["198.18.0.0/24"]').replace(
                'endpoint = "198.18.0.3:51821"',
                'endpoint = "203.0.113.8:51821"'),
        "wg-local-overlaps-wan": baseline_source.replace(
            'address = "10.44.0.1/24"',
            'address = "198.18.0.9/24"').replace(
                'allowed_ips = ["10.44.0.2/32"]',
                'allowed_ips = ["192.0.2.0/24"]').replace(
                    'endpoint = "198.18.0.3:51821"',
                    'endpoint = "203.0.113.8:51821"'),
    }
    for fixture, source in bad_sources.items():
        bad_config = lab.work / (fixture + ".toml")
        bad_config.write_text(source, encoding="ascii")
        # Static rendering must accept the fixture: otherwise an unrelated
        # schema rejection could masquerade as a live WAN-overlap check.
        lab.run([lab.binary, "render", bad_config, "--output", lab.work / fixture])
        result = lab.run([lab.binary, "network-check", bad_config], "router", check=False)
        if result.returncode == 0:
            raise Failure("network preflight accepted WAN overlap: " + fixture)
        gateway_after = json.loads(lab.run(
            ["ip", "-j", "route", "get", "198.18.0.1"], "router").stdout)[0]["dev"]
        if gateway_after != "wan0":
            raise Failure("rejected preflight changed the WAN gateway route")
        # Deliberately never execute setup or nft from the rejected config.
    lab.passed("live WAN preflight rejects peer-route and local-WG overlap without route changes")
    lab.run([lab.binary, "storage-init", lab.work / "state", config])
    wg_directory = lab.work / "wireguard"
    lab.run([lab.binary, "wg-configs", lab.work / "state", wg_directory])
    if wg_directory.stat().st_mode & 0o777 != 0o700:
        raise Failure("WireGuard directory is not mode 0700")
    if (wg_directory / "wg0.conf").stat().st_mode & 0o777 != 0o600:
        raise Failure("WireGuard configuration is not mode 0600")
    lab.run(["nft", "-f", output / "nftables.nft"], "router")
    setup = (output / "network-setup.sh").read_text(encoding="utf-8")
    if "/run/routertop/wireguard/" not in setup:
        raise Failure("generated setup is missing expected private configuration path")
    setup = setup.replace("/run/routertop/wireguard/", str(wg_directory) + "/")
    setup_path = lab.work / "network-setup.sh"
    setup_path.write_text(setup, encoding="utf-8")
    lab.run(["sh", setup_path], "router")
    lab.run(["sysctl", "-p", output / "sysctl.conf"], "router")
    lab.passed("generated VLAN/WireGuard setup and private file permissions")
    router_public = lab.run(["wg", "show", "wg0", "public-key"], "router").stdout.strip()
    lab.setup_peer("peer", private, router_public, "10.44.0.2/24", 51821)
    del private
    wrong_private = lab.run(["wg", "genkey"]).stdout.strip()
    lab.setup_peer("bad", wrong_private, router_public, "10.44.0.99/24", 51822)
    del wrong_private

    for role in ("v20b", "v30", "lan", "wan"):
        lab.http_server(role, "routertop-v03-" + role)
    dns_source = (output / "dnsmasq.conf").read_text(encoding="utf-8")
    dns_source = "\n".join("dhcp-leasefile=" + str(lab.work / "leases")
                           if line.startswith("dhcp-leasefile=") else line
                           for line in dns_source.splitlines()) + "\n"
    dns_path = lab.work / "dnsmasq.conf"
    dns_path.write_text(dns_source, encoding="utf-8")
    lab.run(["dnsmasq", "--test", "--conf-file=" + str(dns_path)], "router")
    lab.start("router", ["dnsmasq", "--keep-in-foreground", "--user=root",
                          "--conf-file=" + str(dns_path), "--pid-file=" + str(lab.work / "dns.pid")], "dns.log")
    hook = lab.secret_file("udhcpc-hook", '''#!/bin/sh
set -eu
case "$1" in
 deconfig) ip address flush dev "$interface" ;;
 bound|renew)
  [ "$interface" = tag0 ]
  [ "$subnet" = 255.255.255.0 ]
  [ "${router%% *}" = 192.168.20.1 ]
  [ "${dns%% *}" = 192.168.20.1 ]
  ip address replace "$ip/24" dev "$interface"
  ip route replace default via 192.168.20.1 dev "$interface"
  ;;
esac
''')
    hook.chmod(0o700)
    time.sleep(1)
    lab.run(["busybox", "udhcpc", "-i", "tag0", "-s", hook, "-f", "-n", "-q",
             "-t", "5", "-T", "2"], "v20a", timeout=20)
    addresses = json.loads(lab.run(["ip", "-j", "-4", "address", "show", "dev", "tag0"], "v20a").stdout)
    assigned = [item["local"] for device in addresses for item in device["addr_info"]]
    if not any(address.startswith("192.168.20.") and 100 <= int(address.split(".")[-1]) <= 150
               for address in assigned):
        raise Failure("VLAN DHCP did not allocate from the configured pool")
    lab.passed("802.1Q VLAN20 DHCP address, mask, router and DNS")
    lab.http("v20a", "192.168.20.10", "routertop-v03-v20b")
    lab.ping("v20a", "192.168.20.10")
    lab.passed("same VLAN traffic across independent tagged trunk ports")
    # Assert the targets really listen before interpreting timeout as firewall denial.
    for role, address in (("v30", "192.168.30.10"), ("lan", "192.168.88.10")):
        lab.http(role, address, "routertop-v03-" + role)
        lab.http("v20a", address, allowed=False)
    lab.http("v30", "192.168.20.10", allowed=False)
    lab.passed("VLAN-to-VLAN and VLAN-to-untagged-LAN isolation")
    if lab.run(["ip", "route", "show", "192.168.20.0/24"], "wan").stdout.strip():
        raise Failure("WAN fixture unexpectedly has a return route")
    lab.http("v20a", "198.18.0.1", "routertop-v03-wan")
    lab.http("v30", "198.18.0.1", allowed=False)
    lab.passed("VLAN internet opt-in NAT and disabled VLAN internet denial")

    lab.ping("peer", "10.44.0.1")
    handshakes = lab.run(["wg", "show", "wg0", "latest-handshakes"], "router").stdout.splitlines()
    if not any(len(line.split()) == 2 and line.split()[0] == public and int(line.split()[1]) > 0
               for line in handshakes):
        raise Failure("authorized WireGuard peer has no completed handshake")
    lab.passed("kernel WireGuard handshake and encrypted tunnel ICMP")
    lab.http("peer", "192.168.20.10", allowed=False)
    lab.passed("VPN-to-VLAN forwarding denied without an explicit rule")
    vpn = [rule("vpn-web", "accept", "wg0", "vlan20"),
           rule("vpn-icmp", "accept", "wg0", "vlan20", protocol="icmp", port=None)]
    lab.firewall(public, base + vpn)
    lab.http("peer", "192.168.20.10", "routertop-v03-v20b")
    lab.ping("peer", "192.168.20.10")
    lab.passed("explicit VPN forwarding rule permits tunneled VLAN HTTP and ICMP")
    lab.ping("bad", "10.44.0.1", allowed=False)
    lab.http("bad", "192.168.20.10", allowed=False)
    bad_handshakes = lab.run(["wg", "show", "wg0", "latest-handshakes"], "bad").stdout.splitlines()
    if not bad_handshakes or any(int(line.split()[1]) != 0 for line in bad_handshakes):
        raise Failure("unrecognized WireGuard key unexpectedly completed a handshake")
    lab.passed("unrecognized WireGuard peer cannot handshake or send tunneled traffic")

    deny = rule("v20-v30-drop", "drop", "vlan20", "vlan30")
    allow = rule("v20-v30-allow", "accept", "vlan20", "vlan30")
    lab.firewall(public, base + vpn + [deny, allow])
    lab.http("v20a", "192.168.30.10", allowed=False)
    lab.passed("ordered drop before accept denies a new TCP flow")
    lab.firewall(public, base + vpn + [allow, deny])
    lab.http("v20a", "192.168.30.10", "routertop-v03-v30")
    lab.passed("reordering accept before drop permits a new TCP flow")
    disabled = dict(allow, enabled=False)
    lab.firewall(public, base + vpn + [disabled, deny])
    lab.http("v20a", "192.168.30.10", allowed=False)
    lab.passed("disabling the accept rule restores denial")
    lab.firewall(public, base + vpn + [allow])
    lab.http("v20a", "192.168.30.10", "routertop-v03-v30")
    lab.passed("deleting drop rule and re-enabling accept permits traffic")
    lab.firewall(public, base + vpn)
    lab.http("v20a", "192.168.30.10", allowed=False)
    lab.passed("deleting the accept rule restores default isolation")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("routertop", nargs="?", default="routertop")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        print(json.dumps({"status": "FAIL", "error": "run as root in a disposable Linux VM"}))
        return 1
    for executable in ("ip", "nft", "wg", "dnsmasq", "curl", "busybox", "sysctl", "modprobe"):
        if not shutil.which(executable):
            print(json.dumps({"status": "FAIL", "error": "missing dependency: " + executable}))
            return 1
    os.umask(0o077)
    lab = Lab(args.routertop)

    def interrupted(_signum, _frame):
        raise Failure("interrupted")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    outcome = 0
    try:
        exercise(lab)
    except Failure as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}), flush=True)
        outcome = 1
    except Exception as error:
        print(json.dumps({"status": "FAIL", "error": "unexpected " + type(error).__name__}), flush=True)
        outcome = 1
    finally:
        try:
            lab.close()
        except Exception:
            print(json.dumps({"status": "FAIL", "error": "namespace cleanup failed"}), flush=True)
            outcome = 1
    print(json.dumps({"status": "PASS" if outcome == 0 else "FAIL", "passed_cases": len(lab.results)}), flush=True)
    return outcome


if __name__ == "__main__":
    raise SystemExit(main())
