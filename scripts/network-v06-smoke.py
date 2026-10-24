#!/usr/bin/env python3
"""Real PPPoE/IPv4/IPv6/PD acceptance in disposable Linux namespaces.

Uses production rendering, pppd supervisor, real PPP lifecycle hooks and dhcpcd.
The isolated ISP uses actual rp-pppoe/pppd PAP authentication and UDP DHCPv6.
Never prints credential-bearing files, raw PPP logs, DUIDs or packet payloads.
"""
import argparse
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shlex
import signal
import sys
import tempfile
import threading
import time
import traceback

spec = importlib.util.spec_from_file_location("lab05", Path(__file__).with_name("network-v05-smoke.py"))
old = importlib.util.module_from_spec(spec)
spec.loader.exec_module(old)
Failure = old.Failure
PREFIX_A, PREFIX_B, REMOTE6 = old.PREFIX_A, old.PREFIX_B, old.REMOTE
REMOTE4 = "203.0.113.9"


class Lab(old.Lab):
    def __init__(self, binary, pd_only=False):
        super().__init__(binary, False)
        # pppd 2.5.3 checks every parent of executable lifecycle hooks and
        # rejects group/world-writable ancestors, including sticky /tmp.
        # Keep its protection enabled; use a private root-owned lab directory.
        self.directory.cleanup()
        self.directory = tempfile.TemporaryDirectory(prefix="routertop-v06-", dir="/var/lib")
        self.work = Path(self.directory.name)
        self.mode = "pppoe"
        self.pd_only = pd_only
        if pd_only:
            self.mode = "pppoe-pd-only"
        self.username = "routertop-lab"
        self.password = secrets.token_urlsafe(24)
        self.config_path = self.work / "routertop.toml"
        self.root_runtime = self.work / "routertop"
        self.runtime = self.root_runtime / "pd"
        self.ppp_runtime = self.root_runtime / "pppoe"
        self.server_status = self.work / "isp-status.json"
        self.control_file = self.work / "isp-control.json"
        self.identity = self.work / "identity" / "duid"
        self.server_process = None
        self.ppp_process = None

    def control(self, prefix=PREFIX_A, silent=False, enabled=True):
        value = {"prefix": prefix, "address": "2001:db8:1::2",
                 "upstream_prefix": "2001:db8:1::/64", "dns_server": "2001:db8:1::1",
                 "t1": 8, "t2": 16, "preferred_lifetime": 24, "valid_lifetime": 32,
                 "ra_lifetime": 20, "silent": silent, "ra_enabled": False,
                 "pppoe_enabled": enabled, "assign_address": not self.pd_only}
        temporary = self.control_file.with_suffix(".tmp")
        temporary.write_text(json.dumps(value))
        os.replace(temporary, self.control_file)

    def fixture(self):
        for module in ("8021q", "ppp_generic", "ppp_async"):
            self.run(["modprobe", module], check=False)
        if not Path("/dev/ppp").exists():
            raise Failure("/dev/ppp is required in the disposable Linux lab")
        for role in ("router", "trunk", "wanhub", "client", "vlan", "wan"):
            self.namespace(role)
        for role in ("trunk", "wanhub"):
            self.run(["ip", "link", "add", "br0", "type", "bridge"], role)
            self.run(["ip", "link", "set", "br0", "up"], role)
        self.connect("router", "wan0", "wanhub")
        self.connect("wan", "eth0", "wanhub")
        self.connect("router", "lan0", "trunk")
        self.address("router", "lan0", "192.168.88.1/24")
        self.connect("client", "eth0", "trunk")
        self.address("client", "eth0", "192.168.88.10/24", "192.168.88.1")
        self.run(["sysctl", "-qw", "net.ipv6.conf.eth0.accept_ra=2",
                  "net.ipv6.conf.eth0.autoconf=1"], "client")
        self.connect("vlan", "eth0", "trunk")
        self.run(["sysctl", "-qw", "net.ipv6.conf.eth0.accept_ra=0",
                  "net.ipv6.conf.eth0.autoconf=0"], "vlan")
        self.run(["ip", "link", "add", "link", "eth0", "name", "tag0", "type", "vlan", "id", "20"], "vlan")
        self.run(["ip", "link", "set", "tag0", "up"], "vlan")
        self.address("vlan", "tag0", "192.168.20.10/24", "192.168.20.1")
        self.run(["sysctl", "-qw", "net.ipv6.conf.tag0.accept_ra=2",
                  "net.ipv6.conf.tag0.autoconf=1"], "vlan")
        self.server("router", "192.168.88.1", "LOCAL-MANAGEMENT", 443)
        self.server("router", "0.0.0.0", "ROUTER-LISTENER")
        self.server("router", "::", "ROUTER-LISTENER")
        self.control()
        credentials = self.secret_file("isp-credentials.json",
                                       json.dumps({"username": self.username, "password": self.password}))
        helper = Path(__file__).with_name("fixtures") / "pppoe-isp.py"
        self.server_process = self.start("wan", [
            sys.executable, helper, "--interface", "eth0", "--credentials-file", credentials,
            "--control-file", self.control_file, "--status-file", self.server_status,
            "--runtime", self.work / "isp"], "isp.log")

    def config(self):
        source = '''hostname = "routertop-pppoe-test"
[wan]
interface = "wan0"
mode = "pppoe"
[wan.pppoe]
username = ''' + json.dumps(self.username) + "\npassword = " + json.dumps(self.password) + '''
mtu = 1492
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
        self.secret_file("routertop.toml", source)
        return self.config_path

    def install(self):
        config = self.config()
        output = self.work / "rendered"
        self.run([self.binary, "render", config, "--output", output])
        rendered = "\n".join(path.read_text() for path in output.iterdir() if path.is_file())
        if self.password in rendered:
            raise Failure("public render contains PPP credentials")
        interfaces = (output / "interfaces").read_text()
        if "iface wan0 inet dhcp" in interfaces:
            raise Failure("PPPoE underlay still starts DHCPv4")
        self.passed("public rendering contains no PPP password and no DHCPv4 underlay client")
        self.run([self.binary, "storage-init", self.work / "state", config])
        self.run([self.binary, "ipv6-init", config, self.runtime, self.identity])
        self.run([self.binary, "pppoe-init", config, self.ppp_runtime])
        if (self.ppp_runtime / "peer").stat().st_mode & 0o077:
            raise Failure("PPPoE private runtime options are readable outside root")
        self.passed("private PPP credential options use root-only permissions")
        self.run(["nft", "-f", output / "nftables.nft"], "router")
        self.run(["sysctl", "-p", output / "sysctl.conf"], "router")
        self.run(["sh", output / "network-setup.sh"], "router")
        hook = self.secret_file("ipv6-hook", "#!/bin/sh\nexec " + shlex.quote(self.binary)
                                + ' ipv6-event "$ROUTERTOP_CONFIG" "$ROUTERTOP_PD_RUNTIME"\n')
        hook.chmod(0o700)
        conf = self.runtime / "dhcpcd.conf"
        # Only filesystem paths and the lab's absent udev service are relocated.
        conf.write_text("env ROUTERTOP_CONFIG=" + str(config) + "\n"
                        "env ROUTERTOP_PD_RUNTIME=" + str(self.runtime) + "\nnodev\n" + conf.read_text().replace(
            "script /usr/sbin/routertop-ipv6-hook", "script " + str(hook)))
        peer = self.ppp_runtime / "peer"
        text = peer.read_text()
        for action, suffix in (("ipv4-up", "ip-up"), ("ipv4-down", "ip-down"),
                               ("ipv6-up", "ipv6-up"), ("ipv6-down", "ipv6-down")):
            wrapper = self.secret_file("ppp-" + action,
                                       "#!/bin/sh\nexport PATH=/sbin:/usr/sbin:/bin:/usr/bin\n"
                                       "printf '" + action + "\\n' >> "
                                       + shlex.quote(str(self.work / "ppp-events")) + "\n"
                                       + shlex.quote(self.binary) + " pppoe-event "
                                       + shlex.quote(str(config)) + " " + shlex.quote(str(self.ppp_runtime))
                                       + " " + action + ' "$1" >> '
                                       + shlex.quote(str(self.work / "ppp-hook.log")) + " 2>&1\n"
                                       + "code=$?\nprintf '" + action + ":%s\\n' \"$code\" >> "
                                       + shlex.quote(str(self.work / "ppp-event-codes")) + "\nexit \"$code\"\n")
            wrapper.chmod(0o700)
            text = text.replace("/usr/sbin/routertop-ppp-" + suffix, str(wrapper))
        peer.write_text(text + "\ndebug\nlogfile " + str(self.work / "client-ppp.log") + "\n")
        dns = (output / "dnsmasq.conf").read_text().replace("/run/routertop/pd", str(self.runtime))
        dns = "\n".join("dhcp-leasefile=" + str(self.work / "leases")
                        if line.startswith("dhcp-leasefile=") else line for line in dns.splitlines()) + "\n"
        self.dns_config = self.work / "dnsmasq.conf"
        self.dns_config.write_text(dns)
        self.run(["dnsmasq", "--test", "--conf-file=" + str(self.dns_config)], "router")
        self.restart_dns()
        self.dns_thread = threading.Thread(target=self.watch_dns, daemon=True)
        self.dns_thread.start()
        self.start("router", [self.binary, "ipv6-monitor", config, self.runtime], "monitor.log")
        database = self.work / "dhcpcd-db"
        database.mkdir(mode=0o755)
        pppdir = self.work / "ppp-system"
        pppdir.mkdir(mode=0o700)
        wrapper = self.secret_file("ppp-start", '#!/bin/sh\nset -eu\nmount --make-rprivate /\n'
                                   'mount -t tmpfs tmpfs /run\nmkdir -p /run/routertop\n'
                                   'mount --bind "$1" /run/routertop\n'
                                   'mount --bind "$2" /var/lib/dhcpcd\n'
                                   'mount --bind "$3" /etc/ppp\nshift 3\nexec "$@"\n')
        wrapper.chmod(0o700)
        self.ppp_process = self.start("router", ["unshare", "-m", "sh", wrapper, self.root_runtime,
                                                database, pppdir, self.binary, "pppoe-run",
                                                config, self.ppp_runtime], "ppp-client.log")

    def wan_status(self):
        try:
            return json.loads((self.root_runtime / "wan-status.json").read_text())
        except (OSError, ValueError):
            return {}

    def isp_status(self):
        try:
            return json.loads(self.server_status.read_text())
        except (OSError, ValueError):
            return {}

    def wait_for(self, predicate, label, timeout=60):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.server_process and self.server_process.poll() is not None:
                raise Failure("ISP fixture exited (exit " + str(self.server_process.returncode) + ")")
            if self.ppp_process and self.ppp_process.poll() is not None:
                raise Failure("PPP supervisor exited (exit " + str(self.ppp_process.returncode) + ")")
            if self.dns_error:
                raise Failure("test DNS supervisor failed: " + self.dns_error)
            if predicate():
                return
            time.sleep(0.4)
        raise Failure("timed out: " + label)

    def bound(self, prefix):
        self.wait_for(lambda: self.wan_status().get("state") == "connected"
                      and self.wan_status().get("ipv4_address") == "198.18.0.2", "authenticated PPP IPv4")
        self.wait_for(lambda: self.wan_status().get("ipv6_ready") is True, "negotiated IPv6CP")
        self.wait_for(lambda: self.isp_status().get("messages", {}).get("pads", 0) > 0
                      and self.isp_status().get("messages", {}).get("session_frames", 0) > 0,
                      "actual PPPoE discovery/session frames")
        for role in ("client", "vlan"):
            self.wait_for(lambda: self.http_ready(role, REMOTE4), role + " real IPv4 NAT HTTP")
        # The inherited assertion expects the ISP's normal response marker.
        original_http = self.http
        self.http = lambda role, address, expected=None, allowed=True, port=8080: original_http(
            role, address, "PPPOE-ISP" if expected == "ISP-EXIT" else expected, allowed, port)
        try:
            super().bound(prefix)
        finally:
            self.http = original_http

    def http_ready(self, role, address):
        try:
            self.http(role, address, "PPPOE-ISP")
            return True
        except Failure:
            return False

    def passed(self, name):
        if self.pd_only:
            name = name.replace("IA_NA/PD", "IA_PD without IA_NA")
        super().passed(name)

    def diagnostics(self, label):
        # Fixed categories only. Raw client/server PPP output can contain secrets.
        value = {"diagnostics": label, "wan": self.wan_status(),
                 "ipv6": self.public_status(), "isp": self.isp_status(), "logs": {}}
        for name in ("ppp-events", "ppp-event-codes"):
            path = self.work / name
            value[name] = path.read_text().splitlines() if path.exists() else []
        for name in ("ppp-client.log", "client-ppp.log", "ppp-hook.log", "isp.log", "isp/server.log", "isp/server-ppp.log", "isp/dhcp.log"):
            path = self.work / name
            text = path.read_text(errors="replace")[-65536:] if path.exists() else ""
            value["logs"][name] = {"present": bool(text), "categories": [
                category for category, patterns in {
                    "invalid_option": ("unrecognized option", "unknown option"),
                    "permission": ("permission denied", "operation not permitted"),
                    "auth_rejected": ("authentication failed", "login incorrect"),
                    "no_device": ("no such device", "no such file or directory"),
                    "ppp_connected": ("connect:", "local  ip address", "local  ll address"),
                    "discovery_timeout": ("timeout waiting for pado", "timeout waiting for pads"),
                }.items() if any(p in text.lower() for p in patterns)]}
        print(json.dumps(value), flush=True)


def exercise(lab):
    lab.fixture()
    lab.wait_for(lambda: lab.isp_status().get("server_generation") == 1, "ISP fixture initialized")
    # Start with a real rejecting PAP server, then restore its private secret.
    # No client negotiation or production event is synthesized by this test.
    pap = lab.work / "isp" / "ppp" / "pap-secrets"
    accepted_secret = pap.read_bytes()
    pap.write_text('"' + lab.username + '" routertop-isp "deliberately-wrong-' + secrets.token_hex(8) + '" *\n')
    lab.install()
    lab.wait_for(lambda: lab.isp_status().get("messages", {}).get("auth_rejection_observed") == 1,
                 "real PAP invalid-password rejection", timeout=45)
    if lab.wan_status().get("ipv4_address"):
        raise Failure("incorrect PPP credentials acquired an IPv4 session")
    lab.http("client", REMOTE4, allowed=False)
    lab.http("client", "192.168.88.1", "LOCAL-MANAGEMENT", port=443)
    lab.passed("actual PAP authentication rejects wrong credentials while LAN management stays available")
    pap.write_bytes(accepted_secret)
    lab.bound(PREFIX_A)
    lab.passed("real PPPoE PADI/PADO/PADR/PADS and authenticated PPP IPv4 NAT")
    lab.passed("IPv6CP and DHCPv6-PD work on PPP without ISP router advertisements")
    lab.wait_for(lambda: all(lab.isp_status().get("messages", {}).get("ipv" + str(family) + "_syn", 0) >= 2
                            for family in (4, 6)), "wire SYN metrics published", timeout=5)
    observed = lab.isp_status()
    for family, maximum in ((4, 1452), (6, 1432)):
        values = observed.get("syn_mss", {}).get(str(family), [])
        if (not values or any(value > maximum for value in values)
                or observed.get("messages", {}).get("ipv" + str(family) + "_syn_bad_checksum", 0)):
            raise Failure("PPP IPv" + str(family) + " SYN MSS/checksum regression observed on real wire")
    lab.passed("real wire IPv4/IPv6 SYN MSS fits PPP MTU and TCP checksums remain valid for LAN/VLAN")
    for role in ("client", "vlan"):
        for address in (REMOTE4, REMOTE6):
            host = "[" + address + "]" if ":" in address else address
            result = lab.run(["curl", "--noproxy", "*", "--silent", "--fail", "--max-time", "20",
                              "http://" + host + ":8080/large.bin"], role, check=False, timeout=25)
            if result.returncode or result.stdout != "routertop-pppoe\n" * 8192:
                raise Failure(role + " bulk PPP IPv4/IPv6 HTTP payload failed")
    lab.passed("LAN/VLAN each transfer and verify a 120 KiB payload over IPv4 and IPv6 PPP paths")
    link = json.loads(lab.run(["ip", "-j", "link", "show", "dev", "ppp0"], "router").stdout)[0]
    if link.get("mtu") != 1492 or "POINTOPOINT" not in link.get("flags", []):
        raise Failure("negotiated PPP interface MTU/type differs from requested settings")
    lab.passed("actual point-to-point PPP interface uses the configured 1492-byte MTU")
    lab.http("router", "127.0.0.1", "ROUTER-LISTENER")
    lab.http("router", "::1", "ROUTER-LISTENER")
    lab.http("wan", "198.18.0.2", allowed=False)
    lab.http("wan", "2001:db8:1::2", allowed=False)
    lab.passed("logical PPP WAN denies unsolicited IPv4/IPv6 access to live listeners")
    messages = lab.isp_status().get("messages", {})
    if messages.get("underlay_dhcpv4", 0):
        raise Failure("DHCPv4 traffic escaped onto the PPPoE underlay")
    lab.passed("no DHCPv4 discovery on the PPPoE physical underlay")
    original_identity = lab.identity.read_bytes()
    old_client = lab.client6
    lab.control(PREFIX_B)
    lab.bound(PREFIX_B)
    retired = lab.run(["curl", "--noproxy", "*", "--silent", "--fail", "--max-time", "3",
                       "--interface", old_client, "http://[" + REMOTE6 + "]:8080/"], "client", check=False)
    if retired.returncode == 0:
        raise Failure("retired delegated source is still forwarded")
    lab.passed("real renewal changes PPP delegation; new routes work and retired source is denied")
    lab.control(PREFIX_B, enabled=False)
    lab.wait_for(lambda: lab.wan_status().get("state") == "reconnecting", "PPP session loss/redial state")
    lab.disconnected()
    lab.http("client", "192.168.88.1", "LOCAL-MANAGEMENT", port=443)
    lab.passed("ISP session termination withdraws PD and leaves LAN management available")
    lab.control(PREFIX_B)
    lab.bound(PREFIX_B)
    if lab.identity.read_bytes() != original_identity:
        raise Failure("PPP redial changed persistent DHCPv6 identity")
    if lab.isp_status().get("messages", {}).get("padi", 0) < 2:
        raise Failure("no actual second PPPoE discovery observed")
    lab.passed("ISP recovery triggers real PPPoE redial with restored IPv4/IPv6/PD and stable identity")
    lab.control(PREFIX_B, silent=True)
    lab.disconnected()
    lab.http("client", REMOTE4, "PPPOE-ISP")
    lab.passed("DHCPv6 lease expiry blocks stale IPv6 while authenticated PPP IPv4 remains usable")


def exercise_pd_only(lab):
    lab.fixture()
    lab.install()
    lab.bound(PREFIX_A)
    if lab.public_status().get("wan_addresses") != []:
        raise Failure("PD-only ISP unexpectedly assigned a global IPv6 WAN address")
    if not lab.run(["ip", "-6", "route", "show", "default", "dev", "ppp0"], "router").stdout.strip():
        raise Failure("PD-only PPP has no negotiated IPv6CP default route")
    lab.wait_for(lambda: lab.isp_status().get("dhcp", {}).get("messages", {}).get("ia_na_noaddrsavail", 0) > 0,
                 "actual IA_NA NoAddrsAvail alongside successful IA_PD")
    lab.passed("PD-only ISP returns NoAddrsAvail for IA_NA; IPv6CP default and LAN/VLAN IPv6 HTTP work without WAN GUA")
    identity = lab.identity.read_bytes()
    lab.control(PREFIX_A, enabled=False)
    lab.disconnected()
    lab.control(PREFIX_B)
    lab.bound(PREFIX_B)
    if lab.public_status().get("wan_addresses") != [] or lab.identity.read_bytes() != identity:
        raise Failure("PD-only reconnect changed identity or acquired unexpected WAN GUA")
    lab.passed("PD-only PPP reconnect changes delegated prefix and restores LAN/VLAN IPv6 traffic with stable identity")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("routertop")
    parser.add_argument("--pd-only", action="store_true",
                        help="targeted IA_PD/IPv6CP test with IA_NA NoAddrsAvail and no global IPv6 WAN address")
    args = parser.parse_args()
    if sys.platform != "linux" or os.geteuid() != 0:
        print(json.dumps({"status": "FAIL", "error": "Linux root required"}))
        return 1
    os.umask(0o077)
    def interrupted(*_):
        raise Failure("interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    lab = Lab(args.routertop, args.pd_only)
    failed = False
    try:
        (exercise_pd_only if args.pd_only else exercise)(lab)
    except Exception as error:
        if isinstance(error, Failure):
            message = str(error)
        else:
            frame = traceback.extract_tb(error.__traceback__)[-1]
            message = type(error).__name__ + " at " + frame.name + ":" + str(frame.lineno)
        lab.diagnostics(message)
        print(json.dumps({"status": "FAIL", "error": message}), flush=True)
        failed = True
    finally:
        count = len(lab.results)
        lab.close()
    print(json.dumps({"status": "FAIL" if failed else "PASS", "passed_cases": count}), flush=True)
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
