#!/usr/bin/env python3
"""Real DHCPv6/RA/PD lifecycle acceptance in disposable Linux namespaces.

Uses the packaged dhcpcd client and production RouterTop renderer/event/monitor.
Only filesystem paths are relocated. Never prints DUIDs, IAIDs, keys or raw
dhcpcd logs. Run as root: python3 scripts/network-v05-smoke.py BINARY
"""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import shlex
import signal
import sys
import threading
import time
import traceback

spec = importlib.util.spec_from_file_location("lab04", Path(__file__).with_name("network-v04-smoke.py"))
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)
Failure = old.Failure
PREFIX_A = "2001:db8:100::/56"
PREFIX_B = "2001:db8:200::/56"
REMOTE = "2001:db8:99::9"


class Lab(old.Lab):
    def __init__(self, binary, full):
        super().__init__(binary, "pd-full" if full else "pd-direct")
        self.full = full
        self.runtime = self.work / "pd"
        self.identity = self.work / "identity" / "duid"
        self.control_file = self.work / "isp-control.json"
        self.server_status = self.work / "isp-status.json"
        self.stop_dns = threading.Event()
        self.dns_thread = None
        self.dns_process = None
        self.dns_error = None
        self.dns_restarts = 0
        self.environment_names = self.work / "hook-environment-names"
        self.dhcp_environment_names = self.work / "hook-dhcp-environment-names"
        self.hook_errors = self.work / "hook-errors"

    def control(self, prefix=PREFIX_A, silent=False):
        value = {"prefix": prefix, "address": "2001:db8:1::2", "upstream_prefix": "2001:db8:1::/64",
                 "dns_server": "2001:db8:1::1", "t1": 8, "t2": 16,
                 "preferred_lifetime": 24, "valid_lifetime": 32, "ra_lifetime": 20,
                 "silent": silent, "ra_enabled": True}
        temporary = self.control_file.with_suffix(".tmp")
        temporary.write_text(json.dumps(value), encoding="ascii")
        os.replace(temporary, self.control_file)

    def fixture(self):
        for module in ("8021q", "wireguard"):
            self.run(["modprobe", module], check=False)
        for role in ("router", "trunk", "wanhub", "client", "vlan", "wan", "peer"):
            self.namespace(role)
        for role in ("trunk", "wanhub"):
            self.run(["ip", "link", "add", "br0", "type", "bridge"], role)
            self.run(["ip", "link", "set", "br0", "up"], role)
        self.connect("router", "wan0", "wanhub")
        self.connect("router", "lan0", "trunk")
        self.address("router", "wan0", "198.18.0.2/24", "198.18.0.1")
        self.address("router", "lan0", "192.168.88.1/24")
        self.connect("client", "eth0", "trunk")
        self.address("client", "eth0", "192.168.88.10/24", "192.168.88.1")
        self.run(["sysctl", "-qw", "net.ipv6.conf.eth0.accept_ra=2", "net.ipv6.conf.eth0.autoconf=1"], "client")
        self.connect("vlan", "eth0", "trunk")
        self.run(["sysctl", "-qw", "net.ipv6.conf.eth0.accept_ra=0", "net.ipv6.conf.eth0.autoconf=0"], "vlan")
        self.run(["ip", "link", "add", "link", "eth0", "name", "tag0", "type", "vlan", "id", "20"], "vlan")
        self.run(["ip", "link", "set", "tag0", "up"], "vlan")
        self.run(["sysctl", "-qw", "net.ipv6.conf.tag0.accept_ra=2", "net.ipv6.conf.tag0.autoconf=1"], "vlan")
        for role, suffix in (("wan", 1), ("peer", 3)):
            self.connect(role, "eth0", "wanhub")
            self.address(role, "eth0", "198.18.0." + str(suffix) + "/24")
            self.run(["ip", "-6", "address", "add", "2001:db8:1::" + str(suffix) + "/64", "dev", "eth0"], role)
            self.run(["ip", "-6", "address", "add", REMOTE + "/128", "dev", "lo"], role)
            self.server(role, "::", "VPN-EXIT" if role == "peer" else "ISP-EXIT")
        # Both potential PD grants have real return routes at the isolated ISP.
        for prefix in (PREFIX_A, PREFIX_B):
            self.run(["ip", "-6", "route", "add", prefix, "via", "2001:db8:1::2"], "wan")
        self.start("wan", ["dnsmasq", "--keep-in-foreground", "--user=root", "--conf-file=/dev/null",
                           "--no-resolv", "--no-hosts", "--bind-interfaces",
                           # The configured static IPv4 resolver deliberately
                           # has no listener: this domain proves learned DNS.
                           "--listen-address=2001:db8:1::1",
                           "--address=/pd.routertop.test/203.0.113.5",
                           "--pid-file=" + str(self.work / "isp-dns.pid")], "isp-dns.log")
        self.server("router", "::", "ROUTER-LISTENER")
        self.server("router", "192.168.88.1", "LOCAL-MANAGEMENT", 443)
        self.control()
        helper = Path(__file__).with_name("fixtures") / "dhcpv6-server.py"
        self.start("wan", [sys.executable, helper, "--interface", "eth0", "--state-file", self.control_file,
                           "--status-file", self.server_status, "--ra"], "isp.log")
        if self.full:
            self.private = self.run(["wg", "genkey"]).stdout.strip()
            self.public = self.run(["wg", "pubkey"], input_text=self.private + "\n").stdout.strip()

    def config(self):
        text = '''hostname = "routertop-pd-test"
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
[ipv6]
wan_mode = "auto"
lan_address = ""
vlans = []
dns_upstream = []
dns_auto = true
[ipv6.pd]
prefix_length = 56
lan_subnet_id = 0
vlans = [{ interface = "vlan20", subnet_id = 1 }]
[[vlans]]
interface = "vlan20"
parent = "lan0"
id = 20
address = "192.168.20.1/24"
internet = true
'''
        if self.full:
            text += '''
[[wireguard]]
interface = "wg0"
address = "10.44.0.1/24"
address_v6 = "fd44::1/64"
listen_port = 51820
mtu = 1420
internet = false
full_tunnel = true
nat66 = true
[[wireguard.peers]]
public_key = "''' + self.public + '''"
allowed_ips = ["0.0.0.0/0", "::/0"]
endpoint = "198.18.0.3:51821"
persistent_keepalive = 0
'''
        path = self.work / "routertop.toml"
        path.write_text(text, encoding="ascii")
        return path

    def install(self):
        config = self.config()
        output = self.work / "rendered"
        self.run([self.binary, "render", config, "--output", output])
        self.run([self.binary, "network-check", config], "router")
        self.run([self.binary, "storage-init", self.work / "state", config])
        keys = self.work / "wireguard"
        self.run([self.binary, "wg-configs", self.work / "state", keys])
        self.run([self.binary, "ipv6-init", config, self.runtime, self.identity])
        self.run(["nft", "-f", output / "nftables.nft"], "router")
        self.run(["sysctl", "-p", output / "sysctl.conf"], "router")
        setup = self.work / "network-setup.sh"
        setup.write_text((output / "network-setup.sh").read_text().replace("/run/routertop/wireguard/", str(keys) + "/"))
        self.run(["sh", setup], "router")
        if self.full:
            public = self.run(["wg", "show", "wg0", "public-key"], "router").stdout.strip()
            secret = self.secret_file("peer.conf", "[Interface]\nPrivateKey = " + self.private +
                                      "\nListenPort = 51821\n[Peer]\nPublicKey = " + public +
                                      "\nAllowedIPs = 10.44.0.0/24,fd44::/64\n")
            self.private = None
            self.run(["ip", "link", "add", "wg0", "type", "wireguard"], "peer")
            self.run(["wg", "setconf", "wg0", secret], "peer")
            self.address("peer", "wg0", "10.44.0.2/24")
            self.run(["ip", "-6", "address", "add", "fd44::2/64", "dev", "wg0"], "peer")
            self.run(["ip", "link", "set", "wg0", "up"], "peer")
        # A relocated wrapper dispatches to the exact production event parser;
        # it does not synthesize leases or modify client-provided environment.
        hook = self.secret_file("ipv6-hook", "#!/bin/sh\nenv | cut -d= -f1 | sort > "
                                + shlex.quote(str(self.environment_names))
                                + "\ncase \"$reason\" in BOUND6|RENEW6|REBIND6|REBOOT6) env | cut -d= -f1 | sort > "
                                + shlex.quote(str(self.dhcp_environment_names)) + ";; esac\nexec " + shlex.quote(self.binary)
                                + " ipv6-event \"$ROUTERTOP_CONFIG\" \"$ROUTERTOP_PD_RUNTIME\" 2>> "
                                + shlex.quote(str(self.hook_errors)) + "\n")
        hook.chmod(0o700)
        client_config = self.runtime / "dhcpcd.conf"
        source = client_config.read_text().replace("script /usr/sbin/routertop-ipv6-hook", "script " + str(hook))
        source = "env ROUTERTOP_CONFIG=" + str(config) + "\nenv ROUTERTOP_PD_RUNTIME=" + str(self.runtime) + "\n" + source
        client_config.write_text(source)
        dns = (output / "dnsmasq.conf").read_text().replace("/run/routertop/pd", str(self.runtime))
        dns = "\n".join("dhcp-leasefile=" + str(self.work / "leases") if line.startswith("dhcp-leasefile=") else line for line in dns.splitlines()) + "\n"
        self.dns_config = self.work / "dnsmasq.conf"
        self.dns_config.write_text(dns)
        self.run(["dnsmasq", "--test", "--conf-file=" + str(self.dns_config)], "router")
        self.restart_dns()
        self.dns_thread = threading.Thread(target=self.watch_dns, daemon=True)
        self.dns_thread.start()
        self.start("router", [self.binary, "ipv6-monitor", config, self.runtime], "monitor.log")
        database = self.work / "dhcpcd-db"
        database.mkdir(mode=0o755)
        # dhcpcd's fixed PID/database paths are isolated in a private mount
        # namespace. The builder's /run, resolver and identity remain untouched.
        wrapper = self.secret_file("dhcpcd-start", "#!/bin/sh\nset -eu\nmount --make-rprivate /\nmount -t tmpfs tmpfs /run\n"
                                   "mount --bind \"$1\" /var/lib/dhcpcd\nexec dhcpcd -B -6 -f \"$2\"\n")
        wrapper.chmod(0o700)
        self.start("router", ["unshare", "-m", "sh", wrapper, database, client_config], "dhcpcd.log")

    def restart_dns(self):
        if self.dns_process is not None and self.dns_process.poll() is None:
            self.dns_process.terminate()
            try:
                self.dns_process.wait(timeout=3)
            except Exception:
                self.dns_process.kill()
                self.dns_process.wait(timeout=3)
        self.dns_process = self.start("router", ["dnsmasq", "--keep-in-foreground", "--user=root",
                                                "--conf-file=" + str(self.dns_config), "--log-facility=-",
                                                "--pid-file=" + str(self.work / "dnsmasq.pid")], "dnsmasq.log")
        self.dns_restarts += 1

    def watch_dns(self):
        while not self.stop_dns.wait(0.2):
            marker = self.runtime / "dnsmasq-restart"
            if marker.exists():
                try:
                    marker.unlink()
                    self.restart_dns()
                except Exception as error:
                    self.dns_error = type(error).__name__
                    return

    def public_status(self):
        try:
            value = json.loads((self.runtime / "status.json").read_text())
            return value if isinstance(value, dict) else {}
        except (OSError, ValueError):
            return {}

    def wait_for(self, predicate, label, timeout=45):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.dns_error:
                raise Failure("test DNS supervisor failed: " + self.dns_error)
            if predicate():
                return
            time.sleep(0.4)
        self.diagnostics(label)
        raise Failure("timed out: " + label)

    def addresses(self, role, interface):
        values = json.loads(self.run(["ip", "-j", "-6", "address", "show", "dev", interface], role).stdout)
        return [item for device in values for item in device.get("addr_info", []) if item.get("scope") == "global"]

    def client_address(self, role, interface, prefix):
        network = ipaddress.IPv6Network(prefix)
        for item in self.addresses(role, interface):
            if (ipaddress.IPv6Address(item["local"]) in network
                    and item.get("preferred_life_time", 0) != 0
                    and not item.get("tentative", False)
                    and "tentative" not in item.get("flags", [])):
                return item["local"]
        return None

    def bound(self, prefix):
        base = ipaddress.IPv6Network(prefix)
        lan = str(ipaddress.IPv6Network((base.network_address, 64)))
        vlan = str(ipaddress.IPv6Network((ipaddress.IPv6Address(int(base.network_address) + (1 << 64)), 64)))
        self.wait_for(lambda: len(self.public_status().get("delegated", [])) == 2
                      and all(ipaddress.IPv6Address(entry["address"].split('/')[0]) in base
                              for entry in self.public_status()["delegated"]), "production bound PD status")
        self.wait_for(lambda: self.client_address("client", "eth0", lan), "LAN real delegated-prefix SLAAC")
        self.wait_for(lambda: self.client_address("vlan", "tag0", vlan), "VLAN real delegated-prefix SLAAC")
        self.client6 = self.client_address("client", "eth0", lan)
        self.vlan6 = self.client_address("vlan", "tag0", vlan)
        self.wait_for(lambda: bool(self.run(["ip", "-6", "route", "show", "default"], "client").stdout.strip()), "LAN RA default")
        marker = "VPN-EXIT" if self.full else "ISP-EXIT"
        # Address publication can precede router-side DAD and neighbor discovery.
        # Bound readiness requires real traffic convergence, never a forced
        # source address or removal of a client's previous prefix.
        for role in ("client", "vlan"):
            def traffic_ready():
                try:
                    self.http(role, REMOTE, marker)
                    return True
                except Failure:
                    return False
            self.wait_for(traffic_ready, role + " routed HTTP convergence", timeout=15)
        self.passed(self.mode + ": acquired IA_NA/PD, separate LAN/VLAN /64 SLAAC and real routed HTTP")

    def disconnected(self):
        self.wait_for(lambda: self.public_status().get("delegated") == [], "PD removal after WAN loss", timeout=40)
        self.wait_for(lambda: not any(ipaddress.IPv6Address(a["local"]) in ipaddress.IPv6Network("2001:db8::/32")
                                     for interface in ("lan0", "vlan20") for a in self.addresses("router", interface)),
                      "retired router PD addresses removed", timeout=40)
        self.http("client", REMOTE, allowed=False)
        self.http("vlan", REMOTE, allowed=False)

    def diagnostics(self, label):
        # Explicit public state and fixed protocol-neutral errors only. Raw
        # dhcpcd logs contain DUID/IAID and are deliberately never emitted.
        value = {"diagnostics": label, "mode": self.mode, "status": self.public_status()}
        value["network"] = {}
        for role in ("router", "client", "vlan", "wan"):
            value["network"][role] = {
                "addresses": self.run(["ip", "-j", "-6", "address", "show"], role, check=False).stdout,
                "routes": self.run(["ip", "-6", "route", "show", "table", "all"], role, check=False).stdout,
                "selected_route": self.run(["ip", "-6", "route", "get", REMOTE], role, check=False).stdout,
            }
        value["nft"] = self.run(["nft", "list", "ruleset"], "router", check=False).stdout
        if self.server_status.exists():
            value["server"] = json.loads(self.server_status.read_text())
        for name in ("monitor.log", "dnsmasq.log", "isp.log"):
            value[name] = (self.work / name).read_text(errors="replace")[-4000:] if (self.work / name).exists() else "absent"
        value["hook_environment_names"] = self.environment_names.read_text().splitlines() if self.environment_names.exists() else []
        value["dhcp_environment_names"] = self.dhcp_environment_names.read_text().splitlines() if self.dhcp_environment_names.exists() else []
        value["hook_errors"] = self.hook_errors.read_text()[-4000:] if self.hook_errors.exists() else ""
        print(json.dumps(value), flush=True)

    def close(self):
        self.stop_dns.set()
        if self.dns_thread:
            self.dns_thread.join(timeout=5)
        # dhcpcd privilege-separation children share the owned network namespace
        # even when their process group differs. Reap only those namespaces.
        for signum in (signal.SIGTERM, signal.SIGKILL):
            for namespace in self.namespaces.values():
                result = self.run(["ip", "netns", "pids", namespace], check=False)
                for text in result.stdout.split():
                    try:
                        os.kill(int(text), signum)
                    except ProcessLookupError:
                        pass
            time.sleep(0.2)
        super().close()


def exercise(lab):
    lab.fixture()
    lab.install()
    lab.bound(PREFIX_A)
    if lab.full:
        if lab.public_status().get("dns_servers"):
            raise Failure("full tunnel accepted WAN-learned DNS outside the tunnel")
        lab.passed("full tunnel ignores WAN-learned DHCPv6/RDNSS resolvers")
    else:
        answer = lab.run(["busybox", "nslookup", "-type=A", "pd.routertop.test", "192.168.88.1"],
                         "client", timeout=15).stdout
        if "203.0.113.5" not in answer:
            raise Failure("client DNS did not resolve through learned IPv6 resolver")
        lab.passed("real client DNS resolves through learned IPv6 DNS with static upstream unavailable")
    lab.wait_for(lambda: json.loads(lab.server_status.read_text()).get("messages", {}).get("request", 0) > 0,
                 "actual DHCPv6 REQUEST/REPLY exchange")
    # Prove the target listener is alive, then verify actual unsolicited WAN
    # TCP remains blocked while DHCPv6 and RA packets are accepted.
    lab.http("router", "::1", "ROUTER-LISTENER")
    lab.http("wan", "2001:db8:1::2", allowed=False)
    lab.passed(lab.mode + ": DHCPv6/RA coexist with unsolicited WAN denial")
    if lab.full:
        handshakes = lab.run(["wg", "show", "wg0", "latest-handshakes"], "router").stdout.splitlines()
        if not any(int(line.split()[1]) > 0 for line in handshakes):
            raise Failure("dynamic PD full tunnel has no real WireGuard handshake")
        lab.run(["ip", "link", "delete", "wg0"], "router")
        lab.http("client", REMOTE, allowed=False)
        lab.http("router", REMOTE, allowed=False)
        lab.http("client", "192.168.88.1", "LOCAL-MANAGEMENT", port=443)
        lab.passed("dynamic PD + WireGuard: real VPN exit and no plaintext fallback after tunnel deletion")
        return
    old_client = lab.client6
    identity_before = lab.identity.read_bytes()
    lab.control(PREFIX_B)
    lab.bound(PREFIX_B)
    lab.wait_for(lambda: json.loads(lab.server_status.read_text()).get("messages", {}).get("renew", 0) > 0,
                 "actual DHCPv6 renewal")
    # Retired client addresses may remain deprecated for RFC 4862's defensive
    # lifetime, but cannot remain authorized for traffic by stale conntrack.
    result = lab.run(["curl", "--noproxy", "*", "--silent", "--fail", "--max-time", "3",
                      "--interface", old_client, "http://[" + REMOTE + "]:8080/"], "client", check=False)
    if result.returncode == 0:
        raise Failure("retired PD source still forwarded after real renumbering")
    lab.passed("real DHCPv6 RENEW changes prefix; new LAN/VLAN routes work and old source is denied")
    # A deliberately undersized real grant must fail closed rather than alias
    # two /64 IDs or continually restart the shared IPv4 DNS service.
    lab.control("2001:db8:300::/64")
    lab.wait_for(lambda: lab.public_status().get("state") == "degraded"
                 and lab.public_status().get("delegated") == [], "undersized real PD grant rejected")
    time.sleep(3)
    restart_count = lab.dns_restarts
    dns_pid = lab.dns_process.pid
    time.sleep(4)
    if lab.dns_restarts != restart_count or lab.dns_process.pid != dns_pid or lab.dns_process.poll() is not None:
        raise Failure("invalid PD grant caused repeated shared DNS restarts")
    # Degraded PD intentionally withdraws learned upstream resolvers. Query a
    # real hosts record to test shared IPv4 DNS service continuity independently
    # of that correct upstream shutdown. Initial acquisition above separately
    # proves actual forwarding to the learned IPv6-only DNS server.
    dns = lab.run(["busybox", "nslookup", "-type=A", "localhost", "192.168.88.1"], "client", timeout=10).stdout
    if "127.0.0.1" not in dns:
        raise Failure("IPv4 DNS stopped serving while the IPv6 delegation was invalid")
    lab.passed("invalid /64 grant fails closed without PD aliasing or IPv4 DNS restart storm")
    lab.control(PREFIX_B)
    lab.bound(PREFIX_B)
    lab.passed("valid delegation recovers after the server issued an undersized prefix")
    lab.run(["ip", "link", "set", "wan0", "down"], "router")
    lab.disconnected()
    lab.passed("WAN link loss withdraws delegated router addresses and blocks stale client forwarding")
    lab.run(["ip", "link", "set", "wan0", "up"], "router")
    lab.bound(PREFIX_B)
    if lab.identity.read_bytes() != identity_before:
        raise Failure("reconnect changed persistent DHCPv6 identity")
    lab.passed("WAN reconnect reacquires real delegation with unchanged persistent identity")
    lab.control(PREFIX_B, silent=True)
    lab.disconnected()
    lab.wait_for(lambda: not lab.run(["ip", "-6", "route", "show", "default"], "client").stdout.strip(),
                 "expired PD no longer advertises LAN default", timeout=40)
    lab.passed("server silence expires actual DHCPv6 lease and removes delegated addresses/default advertisement")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("routertop")
    parser.add_argument("--direct-only", action="store_true")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        print(json.dumps({"status": "FAIL", "error": "Linux root required"}))
        return 1
    os.umask(0o077)
    def interrupted(_signal, _frame):
        raise Failure("interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    count = 0
    failed = False
    for full in ([False] if args.direct_only else [False, True]):
        lab = Lab(args.routertop, full)
        try:
            exercise(lab)
        except Exception as error:
            if isinstance(error, Failure):
                message = str(error)
            else:
                frame = traceback.extract_tb(error.__traceback__)[-1]
                message = type(error).__name__ + " at " + frame.name + ":" + str(frame.lineno)
            lab.diagnostics(message)
            print(json.dumps({"status": "FAIL", "phase": lab.mode, "error": message}), flush=True)
            failed = True
        finally:
            count += len(lab.results)
            lab.close()
        if failed:
            break
    print(json.dumps({"status": "FAIL" if failed else "PASS", "passed_cases": count}), flush=True)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
