#!/usr/bin/env python3
"""One isolated lab ISP: run one instance per disposable network namespace.

Provides real DHCPv4 or PPPoE, HTTP/ICMP reachability, and optional IPv6/PD.
Control-file blackhole drops upstream IPv4 without changing carrier or PPP LCP.
No host namespace creation or physical-interface migration is performed here.
"""
import argparse
import json
import ipaddress
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

REMOTE4 = "203.0.113.9"


def run(args, check=True):
    return subprocess.run(list(map(str, args)), check=check, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)


class Isp:
    def __init__(self, args):
        self.args = args
        self.running = True
        self.children = []
        self.runtime = args.runtime.resolve()
        self.runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.runtime.chmod(0o700)
        self.blackhole = None
        self.dhcp = None
        self.ipv6_routes = set()
        run(["ip", "link", "set", args.interface, "up"])
        if args.mode == "pppoe":
            self.start([sys.executable, Path(__file__).with_name("pppoe-isp.py"),
                        "--interface", args.interface, "--credentials-file", args.credentials_file,
                        "--control-file", args.control_file, "--status-file", self.runtime / "pppoe-status.json",
                        "--runtime", self.runtime / "pppoe", "--marker", args.marker,
                        "--gateway", args.gateway, "--client", args.client], "pppoe.log")
        else:
            run(["ip", "address", "replace", args.gateway + "/24", "dev", args.interface])
            run(["ip", "address", "replace", REMOTE4 + "/32", "dev", "lo"])
            www = self.runtime / "www"
            www.mkdir(exist_ok=True)
            (www / "index.html").write_text(args.marker)
            source = ("import functools,http.server,socket,sys;socket.getfqdn=lambda _name='':'isp';"
                      "http.server.ThreadingHTTPServer(('0.0.0.0',8080),"
                      "functools.partial(http.server.SimpleHTTPRequestHandler,directory=sys.argv[1])).serve_forever()")
            self.start([sys.executable, "-c", source, www], "http.log")
            if args.ipv6:
                run(["sysctl", "-qw", "net.ipv6.conf.all.forwarding=1"])
                run(["ip", "-6", "address", "replace", "2001:db8:99::9/128", "dev", "lo"])
                source6 = ("import functools,http.server,socket,sys;socket.getfqdn=lambda _name='':'isp';"
                           "S=type('S',(http.server.ThreadingHTTPServer,),{'address_family':socket.AF_INET6});"
                           "s=S(('::',8080),functools.partial(http.server.SimpleHTTPRequestHandler,directory=sys.argv[1]),"
                           "bind_and_activate=False);s.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);"
                           "s.server_bind();s.server_activate();s.serve_forever()")
                self.start([sys.executable, "-c", source6, www], "http6.log")
                self.start([sys.executable, Path(__file__).with_name("dhcpv6-server.py"),
                            "--interface", args.interface, "--state-file", args.control_file,
                            "--status-file", self.runtime / "dhcpv6-status.json", "--ra"], "dhcpv6.log")
        if args.ipv6 or args.mode == "pppoe":
            # A persistent real TCP flow detects stale established-connection
            # authorization when the selected uplink changes underneath it.
            stream_source = ("import socketserver;"
                             "H=type('H',(socketserver.BaseRequestHandler,),"
                             "{'handle':lambda self:exec('while self.request.recv(4096): pass')});"
                             "S=type('S',(socketserver.ThreadingTCPServer,),{'address_family':10,'allow_reuse_address':True,'daemon_threads':True});"
                             "S(('::',8081),H).serve_forever()")
            self.start([sys.executable, "-c", stream_source], "stream.log")
            state = json.loads(args.control_file.read_text())
            dns = state.get("dns_server", "2001:db8:1::1")
            run(["ip", "-6", "address", "replace", dns + "/128", "dev", "lo"])
            self.start(["dnsmasq", "--keep-in-foreground", "--user=root", "--conf-file=/dev/null",
                        "--no-resolv", "--no-hosts", "--bind-interfaces", "--listen-address=" + dns,
                        "--address=/pd.routertop.test/" + args.dns_answer,
                        "--pid-file=" + str(self.runtime / "ipv6-dns.pid")], "ipv6-dns.log")
        run(["nft", "add", "table", "inet", "routertop_test_isp"])
        run(["nft", "add", "chain", "inet", "routertop_test_isp", "upstream",
             "{", "type", "filter", "hook", "input", "priority", "-20", ";", "policy", "accept", ";", "}"])

    def start(self, argv, filename):
        with (self.runtime / filename).open("ab") as stream:
            child = subprocess.Popen(list(map(str, argv)), stdout=stream, stderr=stream, start_new_session=True)
        self.children.append(child)
        return child

    @staticmethod
    def stop(child):
        if child is None or child.poll() is not None:
            return
        try:
            os.killpg(child.pid, signal.SIGTERM)
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL)
            child.wait(timeout=5)
        except ProcessLookupError:
            pass

    def update(self):
        control = json.loads(self.args.control_file.read_text())
        if self.args.ipv6 and self.args.mode != "pppoe":
            upstream = ipaddress.IPv6Network(control.get("upstream_prefix", "2001:db8:1::/64"))
            gateway = str(upstream.network_address + 1)
            run(["ip", "-6", "address", "replace", gateway + "/64", "dev", self.args.interface])
            prefix = control.get("prefix", "2001:db8:100::/56")
            address = control.get("address", "2001:db8:1::2")
            self.ipv6_routes.add(prefix)
            for delegated in self.ipv6_routes:
                run(["ip", "-6", "route", "replace", delegated, "via", address, "dev", self.args.interface])
        blackhole = bool(control.get("blackhole", False))
        if self.blackhole != blackhole:
            run(["nft", "flush", "chain", "inet", "routertop_test_isp", "upstream"])
            if blackhole:
                run(["nft", "add", "rule", "inet", "routertop_test_isp", "upstream",
                     "ip", "daddr", REMOTE4, "drop"])
                run(["nft", "add", "rule", "inet", "routertop_test_isp", "upstream",
                     "ip6", "daddr", "2001:db8:99::9", "drop"])
            self.blackhole = blackhole
        if self.args.mode == "dhcp":
            enabled = bool(control.get("dhcp_enabled", True))
            if enabled and (self.dhcp is None or self.dhcp.poll() is not None):
                self.dhcp = self.start(["dnsmasq", "--keep-in-foreground", "--user=root",
                                        "--conf-file=/dev/null", "--port=0", "--interface=" + self.args.interface,
                                        "--bind-interfaces", "--dhcp-range=" + self.args.client + "," + self.args.client + ",255.255.255.0,60s",
                                        "--dhcp-option=3," + self.args.gateway, "--dhcp-option=6," + REMOTE4,
                                        "--dhcp-leasefile=" + str(self.runtime / "leases"),
                                        "--pid-file=" + str(self.runtime / "dnsmasq.pid")], "dhcp.log")
            elif not enabled and self.dhcp is not None:
                self.stop(self.dhcp)
                self.dhcp = None
        status = {"fixture": "dual-wan-isp", "mode": self.args.mode,
                  "blackhole": blackhole, "dhcp_running": self.dhcp is not None and self.dhcp.poll() is None}
        if self.args.mode == "pppoe":
            try:
                status["pppoe"] = json.loads((self.runtime / "pppoe-status.json").read_text())
            except (OSError, ValueError):
                pass
        temporary = self.args.status_file.with_suffix(".tmp")
        temporary.write_text(json.dumps(status))
        os.replace(temporary, self.args.status_file)

    def loop(self):
        try:
            while self.running:
                self.update()
                time.sleep(0.2)
        finally:
            for child in self.children:
                self.stop(child)
            run(["nft", "delete", "table", "inet", "routertop_test_isp"], check=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--mode", choices=("static", "dhcp", "pppoe"), required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--control-file", type=Path, required=True)
    parser.add_argument("--status-file", type=Path, required=True)
    parser.add_argument("--credentials-file", type=Path)
    parser.add_argument("--marker", default="WAN-ISP")
    parser.add_argument("--gateway", default="198.18.0.1")
    parser.add_argument("--client", default="198.18.0.2")
    parser.add_argument("--ipv6", action="store_true")
    parser.add_argument("--dns-answer", default="203.0.113.5")
    args = parser.parse_args()
    if args.mode == "pppoe" and args.credentials_file is None:
        parser.error("PPPoE requires a private credentials file")
    os.umask(0o077)
    fixture = Isp(args)
    signal.signal(signal.SIGTERM, lambda *_: setattr(fixture, "running", False))
    signal.signal(signal.SIGINT, lambda *_: setattr(fixture, "running", False))
    fixture.loop()


if __name__ == "__main__":
    main()
