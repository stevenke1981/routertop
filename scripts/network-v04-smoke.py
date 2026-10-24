#!/usr/bin/env python3
"""Real isolated IPv6 / WireGuard full-tunnel acceptance, Linux root only.

Usage: python3 scripts/network-v04-smoke.py ./target/release/routertop
Imports the 0.3 namespace lifecycle; never changes host links/routes/firewall.
Secrets remain in private temporary files, removed along with owned namespaces.
"""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import sys
import time

spec = importlib.util.spec_from_file_location("routertop_lab03", Path(__file__).with_name("network-v03-smoke.py"))
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)
Failure = old.Failure

REMOTE4 = "203.0.113.9"
REMOTE6 = "2001:db8:99::9"
MARK = "21076"


class Lab(old.Lab):
    def __init__(self, binary, mode):
        super().__init__(binary)
        self.mode = mode
        self.public = None
        self.private = None
        self.client6 = None
        self.vlan6 = None

    def http(self, role, address, expected=None, allowed=True, port=8080):
        self.tcp_source_port += 1
        address = "[" + address + "]" if ":" in address else address
        result = self.run(["curl", "--noproxy", "*", "--fail", "--silent", "--max-time", "3",
                           "--local-port", str(self.tcp_source_port),
                           "http://" + address + ":" + str(port) + "/"], role, check=False)
        if allowed and (result.returncode != 0 or result.stdout != expected):
            raise Failure(self.mode + ": unexpected HTTP result from " + role + " to " + address)
        if not allowed and result.returncode == 0:
            raise Failure(self.mode + ": forbidden HTTP flow succeeded from " + role + " to " + address)

    def server(self, role, bind, marker, port=8080):
        directory = self.work / ("www-" + role + "-" + str(port) + "-" + ("6" if ":" in bind else "4"))
        directory.mkdir()
        (directory / "index.html").write_text(marker, encoding="ascii")
        # Python's CLI selects AF_INET6 for ::; using IPV6_V6ONLY avoids an
        # accidental collision with its independently bound IPv4 fixture.
        source = (
            "import functools,http.server,socket,sys;"
            # HTTPServer.server_bind otherwise performs an unrelated PTR query
            # using the builder's resolver before listen(). These isolated labs
            # test their DNS explicitly, and must not depend on that resolver.
            "socket.getfqdn=lambda _name='':'routertop-fixture';"
            "S=type('Server',(http.server.ThreadingHTTPServer,),"
            "{'address_family':socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET});"
            "s=S((sys.argv[1],int(sys.argv[2])),functools.partial(http.server.SimpleHTTPRequestHandler,"
            "directory=sys.argv[3]),bind_and_activate=False);"
            "s.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1) if ':' in sys.argv[1] else None;"
            "s.server_bind();s.server_activate();s.serve_forever()"
        )
        self.start(role, [sys.executable, "-c", source, bind, str(port), directory], directory.name + ".log")

    def make_config(self, rules=()):
        self.config_generation += 1
        config = self.work / ("config" + str(self.config_generation) + ".toml")
        output = self.work / ("render" + str(self.config_generation))
        source = '''hostname = "routertop-v04-smoke"
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
upstream = ["203.0.113.9"]
[firewall]
https_port = 443
'''
        for rule in rules:
            source += "\n[[firewall.rules]]\n"
            source += "".join(key + " = " + json.dumps(value) + "\n" for key, value in rule.items())
        source += '''
[ipv6]
wan_address = "2001:db8:1::2/64"
wan_gateway = "2001:db8:1::1"
lan_address = "2001:db8:88::1/64"
dns_upstream = []
vlans = [{ interface = "vlan20", address = "2001:db8:20::1/64" }]
[[vlans]]
interface = "vlan20"
parent = "lan0"
id = 20
address = "192.168.20.1/24"
internet = false
'''
        if self.mode != "static-ipv6":
            source += '''
[[wireguard]]
interface = "wg0"
address = "10.44.0.1/24"
listen_port = 51820
mtu = 1420
internet = false
full_tunnel = true
nat66 = ''' + ("true" if self.mode == "dual-full" else "false") + "\n"
            if self.mode == "dual-full":
                source += 'address_v6 = "fd44::1/64"\n'
            source += '\n[[wireguard.peers]]\npublic_key = "' + self.public + '"\n'
            source += "allowed_ips = " + json.dumps(["0.0.0.0/0", "::/0"] if self.mode == "dual-full" else ["0.0.0.0/0"]) + "\n"
            source += 'endpoint = "198.18.0.3:51821"\npersistent_keepalive = 0\n'
        config.write_text(source, encoding="ascii")
        self.run([self.binary, "render", config, "--output", output])
        return config, output

    def fixture(self):
        self.run(["modprobe", "wireguard"], check=False)
        self.run(["modprobe", "8021q"], check=False)
        for role in ("router", "trunk", "wanhub", "client", "vlan", "wan", "peer"):
            self.namespace(role)
            self.run(["sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=0",
                      "net.ipv6.conf.default.disable_ipv6=0"], role)
        for switch in ("trunk", "wanhub"):
            self.run(["ip", "link", "add", "br0", "type", "bridge"], switch)
            self.run(["ip", "link", "set", "br0", "up"], switch)
        self.connect("router", "wan0", "wanhub")
        self.connect("router", "lan0", "trunk")
        self.address("router", "wan0", "198.18.0.2/24", "198.18.0.1")
        self.address("router", "lan0", "192.168.88.1/24")
        self.connect("client", "eth0", "trunk")
        self.address("client", "eth0", "192.168.88.10/24", "192.168.88.1")
        self.run(["sysctl", "-qw", "net.ipv6.conf.eth0.accept_ra=2", "net.ipv6.conf.eth0.autoconf=1"], "client")
        self.connect("vlan", "eth0", "trunk")
        # The VLAN fixture uses only its tagged logical port; do not let the
        # untagged trunk parent silently acquire the trusted LAN's RA prefix.
        self.run(["sysctl", "-qw", "net.ipv6.conf.eth0.accept_ra=0", "net.ipv6.conf.eth0.autoconf=0"], "vlan")
        self.run(["ip", "link", "add", "link", "eth0", "name", "tag0", "type", "vlan", "id", "20"], "vlan")
        self.run(["ip", "link", "set", "tag0", "up"], "vlan")
        self.run(["sysctl", "-qw", "net.ipv6.conf.tag0.accept_ra=2", "net.ipv6.conf.tag0.autoconf=1"], "vlan")
        for role, suffix in (("wan", "1"), ("peer", "3")):
            self.connect(role, "eth0", "wanhub")
            self.address(role, "eth0", "198.18.0." + suffix + "/24")
            self.run(["ip", "-6", "address", "add", "2001:db8:1::" + suffix + "/64", "dev", "eth0"], role)
            self.address(role, "lo", REMOTE4 + "/32")
            self.run(["ip", "-6", "address", "add", REMOTE6 + "/128", "dev", "lo"], role)
            marker = "DIRECT-WAN" if role == "wan" else "VPN-EXIT"
            self.server(role, "0.0.0.0", marker)
            self.server(role, "::", marker)
            # Both otherwise reachable underlays must be capable of replying to
            # plaintext traffic, so timeout cannot be blamed on a missing route.
            if role == "wan":
                self.run(["ip", "route", "add", "192.168.88.0/24", "via", "198.18.0.2"], role)
                self.run(["ip", "-6", "route", "add", "2001:db8:88::/64", "via", "2001:db8:1::2"], role)
            answer = "203.0.113.19" if role == "peer" else "203.0.113.29"
            self.start(role, ["dnsmasq", "--keep-in-foreground", "--user=root", "--conf-file=/dev/null",
                              "--no-resolv", "--no-hosts", "--bind-interfaces",
                              "--listen-address=" + REMOTE4, "--address=/full.routertop.test/" + answer,
                              "--pid-file=" + str(self.work / (role + "-dns.pid"))], role + "-dns.log")
        self.server("router", "192.168.88.1", "LOCAL-MANAGEMENT", 443)
        self.server("router", "::", "ROUTER6")
        self.server("vlan", "::", "VLAN6")
        if self.mode != "static-ipv6":
            self.private = self.run(["wg", "genkey"]).stdout.strip()
            self.public = self.run(["wg", "pubkey"], input_text=self.private + "\n").stdout.strip()

    def install(self, rules=()):
        config, output = self.make_config(rules)
        self.run([self.binary, "network-check", config], "router")
        self.run([self.binary, "storage-init", self.work / "state", config])
        keys = self.work / "wireguard"
        self.run([self.binary, "wg-configs", self.work / "state", keys])
        self.run(["nft", "-f", output / "nftables.nft"], "router")
        self.run(["sysctl", "-p", output / "sysctl.conf"], "router")
        source = (output / "network-setup.sh").read_text(encoding="utf-8")
        source = source.replace("/run/routertop/wireguard/", str(keys) + "/")
        setup = self.work / "network-setup.sh"
        setup.write_text(source, encoding="utf-8")
        self.run(["sh", setup], "router")
        if self.private:
            router_public = self.run(["wg", "show", "wg0", "public-key"], "router").stdout.strip()
            peer_config = self.secret_file("peer.conf", "[Interface]\nPrivateKey = " + self.private +
                                           "\nListenPort = 51821\n[Peer]\nPublicKey = " + router_public +
                                           "\nAllowedIPs = 10.44.0.0/24, fd44::/64\n")
            self.private = None
            self.run(["ip", "link", "add", "wg0", "type", "wireguard"], "peer")
            self.run(["wg", "setconf", "wg0", peer_config], "peer")
            self.address("peer", "wg0", "10.44.0.2/24")
            self.run(["ip", "-6", "address", "add", "fd44::2/64", "dev", "wg0"], "peer")
            self.run(["ip", "link", "set", "wg0", "up"], "peer")
        dns_source = (output / "dnsmasq.conf").read_text(encoding="utf-8")
        dns_source = "\n".join("dhcp-leasefile=" + str(self.work / "leases")
                               if line.startswith("dhcp-leasefile=") else line
                               for line in dns_source.splitlines()) + "\n"
        dns_path = self.work / "dnsmasq.conf"
        dns_path.write_text(dns_source, encoding="utf-8")
        self.run(["dnsmasq", "--test", "--conf-file=" + str(dns_path)], "router")
        self.start("router", ["dnsmasq", "--keep-in-foreground", "--user=root",
                               "--conf-file=" + str(dns_path), "--pid-file=" + str(self.work / "dns.pid")], "router-dns.log")
        self.client6 = self.slaac("client", "eth0", "2001:db8:88::/64")
        self.vlan6 = self.slaac("vlan", "tag0", "2001:db8:20::/64")
        default = self.run(["ip", "-6", "route", "show", "default"], "client").stdout
        if self.mode != "ipv4-full" and "proto ra" not in default:
            raise Failure("LAN client did not receive an RA default route")
        if self.mode == "ipv4-full" and default.strip():
            raise Failure("IPv4-only VPN unexpectedly advertised an IPv6 default")
        self.passed(self.mode + ": real LAN and tagged VLAN SLAAC; RA default policy")
        # VLAN internet=false advertises no default; provide a deliberate route
        # back to LAN for the independent forwarding-rule tests.
        self.run(["ip", "-6", "route", "add", "2001:db8:88::/64", "via", "2001:db8:20::1", "dev", "tag0"], "vlan")
        time.sleep(1)

    def slaac(self, role, interface, prefix):
        deadline = time.monotonic() + 35
        network = ipaddress.ip_network(prefix)
        while time.monotonic() < deadline:
            addresses = json.loads(self.run(["ip", "-j", "-6", "address", "show", "dev", interface], role).stdout)
            for device in addresses:
                for address in device.get("addr_info", []):
                    if (ipaddress.ip_address(address["local"]) in network
                            and not address.get("tentative", False)
                            and "tentative" not in address.get("flags", [])):
                        return address["local"]
            time.sleep(0.25)
        self.slaac_diagnostics(role, interface)
        raise Failure(role + ": timed out waiting for an actual SLAAC address")

    def slaac_diagnostics(self, role, interface):
        """Bounded allowlisted diagnostics; never read keys or durable state."""
        diagnostics = {"diagnostics": "slaac-timeout", "phase": self.mode,
                       "role": role, "interface": interface, "commands": {}, "files": {}}
        commands = [
            ("router", ["ip", "-d", "link", "show"]),
            ("router", ["ip", "-6", "address", "show"]),
            ("router", ["ip", "-6", "route", "show", "table", "all"]),
            ("router", ["nft", "list", "table", "inet", "routertop"]),
            (role, ["ip", "-d", "link", "show"]),
            (role, ["ip", "-6", "address", "show"]),
            (role, ["ip", "-6", "route", "show", "table", "all"]),
            (role, ["sysctl", "net.ipv6.conf." + interface + ".accept_ra",
                    "net.ipv6.conf." + interface + ".autoconf",
                    "net.ipv6.conf." + interface + ".disable_ipv6",
                    "net.ipv6.conf." + interface + ".forwarding",
                    "net.ipv6.conf." + interface + ".accept_ra_pinfo"]),
            ("trunk", ["ip", "-d", "link", "show"]),
        ]
        for namespace, command in commands:
            label = namespace + ": " + " ".join(command)
            try:
                result = self.run(command, namespace, check=False, timeout=5)
                diagnostics["commands"][label] = {"exit": result.returncode,
                                                  "stdout": result.stdout[-16000:],
                                                  "stderr": result.stderr[-2000:]}
            except Exception as error:
                diagnostics["commands"][label] = {"error": type(error).__name__}
        # These names are authored by this harness and contain only service
        # parameters/logs; no glob or config/state/WireGuard file is inspected.
        for name in ("router-dns.log", "dnsmasq.conf"):
            try:
                diagnostics["files"][name] = (self.work / name).read_text(encoding="utf-8", errors="replace")[-20000:]
            except OSError as error:
                diagnostics["files"][name] = type(error).__name__
        print(json.dumps(diagnostics), flush=True)

    def firewall(self, rules):
        _, output = self.make_config(rules)
        self.run(["nft", "-f", output / "nftables.nft"], "router")

    def ping6(self, role, address, allowed=True, size=56):
        result = self.run(["busybox", "ping6", "-c", "1", "-W", "3", "-s", str(size), address], role, check=False, timeout=6)
        if (result.returncode == 0) != allowed:
            raise Failure("unexpected IPv6 ICMP result from " + role)


def ipv6_rule(identifier, action, incoming, outgoing=None, port=8080):
    value = old.rule(identifier, action, incoming, outgoing, port=port)
    value["family"] = "ipv6"
    return value


def dhcp_v4_disabled(lab):
    """Prove no DHCPv4 service leaks onto the IPv6-only autoconfigured VLAN."""
    offers = lab.work / "dhcp-v4-events"
    hook = lab.secret_file("dhcp-v4-probe", "#!/bin/sh\ncase \"$1\" in\n"
                           "bound|renew) printf '%s %s\\n' \"$interface\" \"$ip\" >> "
                           + shlex.quote(str(offers)) + ";;\nesac\n")
    hook.chmod(0o700)
    # A no-op deconfig hook preserves all fixture addresses/routes. A real LAN
    # DHCP transaction must first succeed, proving client and server readiness.
    positive = lab.run(["busybox", "udhcpc", "-i", "eth0", "-s", hook, "-f", "-n", "-q",
                        "-t", "5", "-T", "2"], "client", check=False, timeout=20)
    if positive.returncode or not offers.exists():
        print(json.dumps({"diagnostics": "lan-dhcp-positive-control",
                          "exit": positive.returncode, "stdout": positive.stdout[-3000:],
                          "stderr": positive.stderr[-3000:],
                          "hook": hook.read_text(encoding="ascii"),
                          "events": offers.read_text(encoding="ascii") if offers.exists() else None}), flush=True)
        raise Failure("LAN DHCP positive control did not complete a real lease transaction")
    lease = offers.read_text(encoding="ascii").strip().split()
    if (len(lease) != 2 or lease[0] != "eth0" or not lease[1].startswith("192.168.88.")
            or not 100 <= int(lease[1].split(".")[-1]) <= 150):
        raise Failure("LAN DHCP positive control returned an unexpected lease")
    offers.unlink()
    # A counter-only rule preserves the generated default-drop policy and
    # proves actual discover packets reached the router, rather than mistaking
    # an unconfigured client for successful isolation.
    lab.run(["nft", "add", "rule", "inet", "routertop", "input", "iifname", "vlan20",
             "udp", "sport", "68", "udp", "dport", "67", "counter",
             "comment", "v04-dhcp-denial-proof"], "router")
    denied = lab.run(["busybox", "udhcpc", "-i", "tag0", "-s", hook, "-f", "-n", "-q",
                      "-t", "2", "-T", "1"], "vlan", check=False, timeout=10)
    if denied.returncode == 0 or offers.exists():
        raise Failure("DHCPv4 was offered on a VLAN with no configured IPv4 pool")
    rules = json.loads(lab.run(["nft", "-j", "list", "chain", "inet", "routertop", "input"], "router").stdout)
    packets = sum(expression.get("counter", {}).get("packets", 0)
                  for item in rules["nftables"]
                  if item.get("rule", {}).get("comment") == "v04-dhcp-denial-proof"
                  for expression in item["rule"].get("expr", []))
    if packets < 1:
        raise Failure("DHCPv4 denial fixture sent no discover packets through the router input policy")
    lab.passed("LAN DHCP positive control succeeds; actual VLAN DHCPv4 discovers hit default deny with no lease")


def static_checks(lab):
    trusted = ipv6_rule("lan6-input", "accept", "lan0")
    lab.fixture()
    lab.install([trusted])
    dhcp_v4_disabled(lab)
    lab.ping6("client", "2001:db8:88::1")
    lab.ping6("client", REMOTE6)
    lab.http("client", REMOTE6, "DIRECT-WAN")
    lab.http("client", "2001:db8:88::1", "ROUTER6")
    lab.http("wan", "2001:db8:1::2", allowed=False)
    lab.passed("IPv6 ND, routed ICMP/HTTP, custom LAN input allow and WAN default deny")
    lab.http("vlan", lab.vlan6, "VLAN6")
    lab.http("client", lab.vlan6, allowed=False)
    lab.passed("IPv6 inter-LAN/VLAN default isolation with live target")
    deny = ipv6_rule("drop-vlan6", "drop", "lan0", "vlan20")
    allow = ipv6_rule("allow-vlan6", "accept", "lan0", "vlan20")
    lab.firewall([trusted, deny, allow])
    lab.http("client", lab.vlan6, allowed=False)
    lab.firewall([trusted, allow, deny])
    lab.http("client", lab.vlan6, "VLAN6")
    lab.passed("typed IPv6 firewall preserves drop/accept ordering on new flows")
    # A 1448-byte IPv6 packet cannot traverse a 1280-byte router WAN. Receiving
    # the generated Packet Too Big must update the client's actual PMTU cache.
    lab.run(["ip", "link", "set", "wan0", "mtu", "1280"], "router")
    lab.run(["busybox", "ping6", "-c", "1", "-W", "2", "-s", "1400", REMOTE6], "client", check=False, timeout=5)
    route = lab.run(["ip", "-6", "route", "get", REMOTE6], "client").stdout
    if "mtu 1280" not in route:
        raise Failure("IPv6 Packet Too Big did not update the client PMTU cache")
    lab.http("client", REMOTE6, "DIRECT-WAN")
    lab.passed("IPv6 Packet Too Big reaches client and subsequent HTTP obeys learned PMTU")


def full_checks(lab):
    lab.fixture()
    lab.install()
    # Verify both physical exit fixtures remain alive independently of policy.
    for role, marker in (("wan", "DIRECT-WAN"), ("peer", "VPN-EXIT")):
        lab.http(role, REMOTE4, marker)
        lab.http(role, REMOTE6, marker)
    for role in ("client", "router"):
        lab.http(role, REMOTE4, "VPN-EXIT")
        if lab.mode == "dual-full":
            lab.http(role, REMOTE6, "VPN-EXIT")
    if lab.mode == "ipv4-full":
        # Enforce a client route manually: absence of RA alone is insufficient
        # evidence that an intentional IPv6 bypass is blocked by the firewall.
        lab.run(["ip", "-6", "route", "add", "default", "via", "2001:db8:88::1", "dev", "eth0"], "client")
        for role in ("client", "router"):
            lab.http(role, REMOTE6, allowed=False)
        lab.passed("IPv4-only VPN blocks client/router IPv6 even with explicit underlay routes")
    handshakes = lab.run(["wg", "show", "wg0", "latest-handshakes"], "router").stdout.splitlines()
    if not any(len(line.split()) == 2 and int(line.split()[1]) > 0 for line in handshakes):
        raise Failure("full tunnel has no real kernel WireGuard handshake")
    mark = lab.run(["wg", "show", "wg0", "fwmark"], "router").stdout.strip()
    if int(mark, 0) != int(MARK):
        raise Failure("WireGuard socket does not carry reserved transport mark")
    marked_route = json.loads(lab.run(["ip", "-j", "route", "get", "198.18.0.3", "mark", MARK], "router").stdout)[0]
    if marked_route["dev"] != "wan0":
        raise Failure("encrypted WireGuard transport did not retain WAN underlay route")
    lab.passed(lab.mode + ": real handshake, marked WAN transport and VPN-only HTTP exit")
    dns = lab.run(["busybox", "nslookup", "-type=A", "full.routertop.test", REMOTE4], "router").stdout
    if "203.0.113.19" not in dns or "203.0.113.29" in dns:
        raise Failure("router-originated DNS escaped the VPN exit")
    lab.passed(lab.mode + ": router-originated DNS exits through WireGuard")
    lab.http("client", "192.168.88.1", "LOCAL-MANAGEMENT", port=443)
    lab.passed(lab.mode + ": local LAN management stays reachable")
    lab.run(["ip", "link", "delete", "wg0"], "router")
    for role in ("client", "router"):
        lab.http(role, REMOTE4, allowed=False)
        lab.http(role, REMOTE6, allowed=False)
    lab.http("client", "192.168.88.1", "LOCAL-MANAGEMENT", port=443)
    lab.passed(lab.mode + ": deleting tunnel blocks both-family plaintext fallback, preserves local management")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("routertop", nargs="?", default="routertop")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        print(json.dumps({"status": "FAIL", "error": "run as root in a disposable Linux VM"}))
        return 1
    for tool in ("ip", "nft", "wg", "dnsmasq", "curl", "busybox", "sysctl", "modprobe"):
        if not shutil.which(tool):
            print(json.dumps({"status": "FAIL", "error": "missing " + tool}))
            return 1
    os.umask(0o077)
    def interrupted(_signum, _frame):
        raise Failure("interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    count = 0
    failed = False
    for mode in ("static-ipv6", "dual-full", "ipv4-full"):
        lab = Lab(args.routertop, mode)
        try:
            static_checks(lab) if mode == "static-ipv6" else full_checks(lab)
        except Failure as error:
            print(json.dumps({"status": "FAIL", "phase": mode, "error": str(error)}), flush=True)
            failed = True
        except Exception as error:
            print(json.dumps({"status": "FAIL", "phase": mode, "error": type(error).__name__}), flush=True)
            failed = True
        finally:
            count += len(lab.results)
            try:
                lab.close()
            except Exception:
                print(json.dumps({"status": "FAIL", "phase": mode, "error": "namespace cleanup failed"}), flush=True)
                failed = True
        if failed:
            break
    print(json.dumps({"status": "FAIL" if failed else "PASS", "passed_cases": count}), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
