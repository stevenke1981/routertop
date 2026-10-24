#!/usr/bin/env python3
"""Real PPPoE/PPP-authentication ISP for disposable namespaces/VMs only.

Uses rp-pppoe and pppd plus the existing real UDP DHCPv6 packet fixture.
Status contains counters, never credentials, identities or packet payloads.
"""
import argparse
from collections import Counter
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import subprocess
import sys
import time

REMOTE4 = "203.0.113.9"
REMOTE6 = "2001:db8:99::9"
DNS6 = "2001:db8:1::1"


def quote(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 256 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("invalid fixture credentials")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def run(args):
    return subprocess.run(list(map(str, args)), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def private(path, text, executable=False):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700 if executable else 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write(text)
    path.chmod(0o700 if executable else 0o600)


def stop(process):
    if process is None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)


class Isp:
    def __init__(self, args):
        self.args = args
        self.directory = args.runtime.resolve()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.directory.chmod(0o700)
        credentials = json.loads(args.credentials_file.read_text())
        self.counts = Counter()
        self.syn_mss = {4: set(), 6: set()}
        self.running = True
        self.server = None
        self.dhcp = None
        self.generation = 0
        self.pppdir = self.directory / "ppp"
        self.pppdir.mkdir(mode=0o700, exist_ok=True)
        private(self.pppdir / "options", "")
        private(self.pppdir / "pap-secrets",
                quote(credentials["username"]) + " routertop-isp " + quote(credentials["password"]) + " *\n")
        private(self.pppdir / "chap-secrets", "")
        self.options = self.directory / "server.options"
        self.pppd_wrapper = self.directory / "pppd-capture"
        private(self.pppd_wrapper, '#!/bin/sh\nexec /usr/sbin/pppd "$@" >> '
                + str(self.directory / "server-ppp.log") + ' 2>&1\n', True)
        private(self.options, "\n".join([
            "auth", "require-pap", "refuse-chap", "refuse-eap", "refuse-mschap", "refuse-mschap-v2",
            "name routertop-isp", "hide-password", "noipdefault", "nodefaultroute",
            # The lab ISP declines link/header compression so the wire
            # checksum/MSS assertions inspect actual IP headers directly.
            "noccp", "novj", "noaccomp", "nopcomp",
            "ipv6 ::1,::2", "ipv6cp-accept-remote", "mtu 1492", "mru 1492",
            "lcp-echo-interval 2", "lcp-echo-failure 3", "ifname isp0",
            "logfile " + str(self.directory / "server-ppp.log"), "",
        ]))
        # Mount isolation keeps the VM's /etc/ppp secret store untouched.
        self.wrapper = self.directory / "server-start"
        private(self.wrapper, '#!/bin/sh\nset -eu\nmount --make-rprivate /\n'
                'mount --bind "$1" /etc/ppp\nshift\nexec pppoe-server -F "$@"\n', True)
        self.capture = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        self.capture.bind((args.interface, 0))
        self.capture.setblocking(False)
        for address, family in ((REMOTE4 + "/32", []), (REMOTE6 + "/128", ["-6"]), (DNS6 + "/128", ["-6"])):
            run(["ip", *family, "address", "replace", address, "dev", "lo"])
        run(["sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"])
        self.http = []
        for bind in ("0.0.0.0", "::"):
            directory = self.directory / ("www6" if ":" in bind else "www4")
            directory.mkdir(exist_ok=True)
            (directory / "index.html").write_text("PPPOE-ISP")
            (directory / "large.bin").write_text("routertop-pppoe\n" * 8192)
            script = (
                "import functools,http.server,socket,sys;socket.getfqdn=lambda _name='':'isp';"
                "S=type('S',(http.server.ThreadingHTTPServer,),"
                "{'address_family':socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET});"
                "s=S((sys.argv[1],8080),functools.partial(http.server.SimpleHTTPRequestHandler,"
                "directory=sys.argv[2]),bind_and_activate=False);"
                "s.socket.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1) if ':' in sys.argv[1] else None;"
                "s.server_bind();s.server_activate();s.serve_forever()"
            )
            self.http.append(self.start([sys.executable, "-c", script, bind, directory], directory.name + ".log"))

    def start(self, args, name):
        with (self.directory / name).open("ab") as output:
            return subprocess.Popen(list(map(str, args)), stdout=output, stderr=output, start_new_session=True)

    def link_up(self):
        result = subprocess.run(["ip", "-j", "link", "show", "dev", "isp0"], capture_output=True, text=True)
        if result.returncode:
            return False
        try:
            return "UP" in json.loads(result.stdout)[0]["flags"]
        except (ValueError, KeyError, IndexError):
            return False

    def update(self):
        state = json.loads(self.args.control_file.read_text())
        enabled = state.get("pppoe_enabled", True)
        if enabled and self.server is None:
            self.server = self.start(["unshare", "-m", "sh", self.wrapper, self.pppdir,
                                      "-I", self.args.interface, "-L", "198.18.0.1", "-R", "198.18.0.2",
                                      "-N", "1", "-C", "routertop-lab", "-O", self.options,
                                      "-q", self.pppd_wrapper], "server.log")
            self.generation += 1
        elif not enabled and self.server is not None:
            stop(self.dhcp)
            self.dhcp = None
            stop(self.server)
            self.server = None
        up = self.link_up()
        if up and enabled:
            run(["ip", "-6", "route", "replace", str(state.get("address", "2001:db8:1::2")) + "/128",
                 "dev", "isp0"])
            for prefix in ("2001:db8:100::/56", "2001:db8:200::/56", state.get("prefix", "2001:db8:100::/56")):
                run(["ip", "-6", "route", "replace", prefix, "dev", "isp0"])
            if self.dhcp is None or self.dhcp.poll() is not None:
                helper = Path(__file__).with_name("dhcpv6-server.py")
                self.dhcp = self.start([sys.executable, helper, "--interface", "isp0",
                                        "--state-file", self.args.control_file,
                                        "--status-file", self.directory / "dhcp-status.json"], "dhcp.log")
                self.counts["ipv6cp_sessions"] += 1
        elif self.dhcp is not None:
            stop(self.dhcp)
            self.dhcp = None
        log = self.directory / "server-ppp.log"
        text = log.read_text(errors="replace")[-65536:] if log.exists() else ""
        self.counts["auth_rejection_observed"] = int(
            "authentication failed" in text.lower() or "login incorrect" in text.lower())
        # The server has a fixed option vocabulary; never echo arbitrary text.
        self.option_errors = [
            token for token in re.findall(r"unrecognized option ['\"]?([A-Za-z0-9_-]+)", text)
            if token in {"auth", "require-pap", "refuse-chap", "refuse-eap", "refuse-mschap",
                         "refuse-mschap-v2", "name", "hide-password", "noipdefault",
                         "nodefaultroute", "ipv6", "ipv6cp-accept-remote", "mtu", "mru",
                         "lcp-echo-interval", "lcp-echo-failure", "ifname", "logfile",
                         "noaccomp", "nopcomp", "default-asyncmap", "remotenumber"}
        ]
        self.status(up)

    def status(self, up):
        data = {"fixture": "pppoe-isp", "ppp_interface_up": up, "server_generation": self.generation,
                "messages": dict(self.counts), "server_exit": self.server.poll() if self.server is not None else None,
                "dhcp": None, "option_errors": getattr(self, "option_errors", []),
                "syn_mss": {str(family): sorted(values) for family, values in self.syn_mss.items()}}
        path = self.directory / "dhcp-status.json"
        if path.exists():
            try:
                data["dhcp"] = json.loads(path.read_text())
            except ValueError:
                pass
        temporary = self.args.status_file.with_suffix(".tmp")
        temporary.write_text(json.dumps(data))
        os.replace(temporary, self.args.status_file)

    def capture_packets(self):
        while True:
            try:
                packet = self.capture.recv(8192)
            except BlockingIOError:
                break
            if len(packet) < 20:
                continue
            protocol = int.from_bytes(packet[12:14], "big")
            if protocol == 0x8863:
                label = {9: "padi", 7: "pado", 25: "padr", 101: "pads", 167: "padt"}.get(packet[15])
                if label:
                    self.counts[label] += 1
            elif protocol == 0x8864:
                self.counts["session_frames"] += 1
                self.inspect_syn(packet[20:])
            elif protocol == 0x0800 and len(packet) >= 42:
                header = (packet[14] & 15) * 4
                if packet[23] == 17 and len(packet) >= 14 + header + 4:
                    ports = struct.unpack_from("!HH", packet, 14 + header)
                    if set(ports) == {67, 68}:
                        self.counts["underlay_dhcpv4"] += 1

    def inspect_syn(self, ppp):
        # PPP PAP/CHAP/control payloads are ignored before any inspection.
        # Retain only aggregate MSS/checksum results for fixture-destination SYNs.
        if len(ppp) < 3:
            return
        # RFC 1661 protocol-field compression may reduce an odd protocol to
        # one byte after negotiation. Read only the protocol selector first.
        compressed = bool(ppp[0] & 1)
        protocol = ppp[0] if compressed else int.from_bytes(ppp[:2], "big")
        packet = ppp[1:] if compressed else ppp[2:]
        if protocol == 0x21 and len(packet) >= 40 and packet[0] >> 4 == 4:
            family = 4
            offset = (packet[0] & 15) * 4
            length = int.from_bytes(packet[2:4], "big")
            if packet[9] != 6 or packet[16:20] != ipaddress.IPv4Address(REMOTE4).packed:
                return
            tcp = packet[offset:length]
            pseudo = packet[12:20] + b"\0\x06" + len(tcp).to_bytes(2, "big")
        elif protocol == 0x57 and len(packet) >= 60 and packet[0] >> 4 == 6:
            family = 6
            if packet[6] != 6 or packet[24:40] != ipaddress.IPv6Address(REMOTE6).packed:
                return
            tcp = packet[40:40 + int.from_bytes(packet[4:6], "big")]
            pseudo = packet[8:40] + len(tcp).to_bytes(4, "big") + b"\0\0\0\x06"
        else:
            return
        if len(tcp) < 20 or tcp[13] & 0x12 != 0x02:
            return
        header = (tcp[12] >> 4) * 4
        # curl's test connections do not use TCP Fast Open; never retain data.
        if not 20 <= header == len(tcp) <= 60:
            return
        self.counts["ipv" + str(family) + "_syn"] += 1
        data = pseudo + tcp
        if len(data) & 1:
            data += b"\0"
        checksum = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
        while checksum >> 16:
            checksum = (checksum & 0xffff) + (checksum >> 16)
        if checksum != 0xffff:
            self.counts["ipv" + str(family) + "_syn_bad_checksum"] += 1
        index = 20
        while index < header:
            kind = tcp[index]
            if kind == 0:
                break
            if kind == 1:
                index += 1
                continue
            if index + 2 > header or tcp[index + 1] < 2 or index + tcp[index + 1] > header:
                break
            length = tcp[index + 1]
            if kind == 2 and length == 4:
                self.syn_mss[family].add(int.from_bytes(tcp[index + 2:index + 4], "big"))
            index += length

    def loop(self):
        try:
            while self.running:
                self.capture_packets()
                self.update()
                time.sleep(0.2)
        finally:
            stop(self.dhcp)
            stop(self.server)
            for process in self.http:
                stop(process)
            self.capture.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--credentials-file", type=Path, required=True)
    parser.add_argument("--control-file", type=Path, required=True)
    parser.add_argument("--status-file", type=Path, required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    isp = Isp(args)
    signal.signal(signal.SIGTERM, lambda *_: setattr(isp, "running", False))
    signal.signal(signal.SIGINT, lambda *_: setattr(isp, "running", False))
    isp.loop()


if __name__ == "__main__":
    main()
