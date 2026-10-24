#!/usr/bin/env python3
"""Bounded DHCPv6/RA packet fixture, NOT a production DHCP server.

Implements real RFC 8415 SOLICIT/ADVERTISE/REQUEST/REPLY/RENEW/REBIND
exchanges with IA_NA and IA_PD. The caller selects an isolated interface and
configures its addresses/routes; this helper never changes host networking.
Control JSON may be changed atomically while running to renumber or stop leases.
Status contains counters only: client/server DUIDs and IAIDs are never logged.
Reference: https://www.rfc-editor.org/rfc/rfc8415.html
"""
import argparse
from collections import Counter
import ipaddress
import json
import os
from pathlib import Path
import select
import signal
import socket
import struct
import time


def option(code, value):
    return struct.pack("!HH", code, len(value)) + value


def options(data):
    result = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise ValueError("truncated option")
        code, length = struct.unpack_from("!HH", data, offset)
        offset += 4
        if offset + length > len(data):
            raise ValueError("truncated value")
        result.append((code, data[offset:offset + length]))
        offset += length
    return result


def control(path):
    if path.stat().st_size > 16384:
        raise ValueError("control too large")
    state = json.loads(path.read_text(encoding="utf-8"))
    state["prefix"] = ipaddress.IPv6Network(state.get("prefix", "2001:db8:100::/56"))
    state["address"] = ipaddress.IPv6Address(state.get("address", "2001:db8:1::2"))
    state["upstream_prefix"] = ipaddress.IPv6Network(state.get("upstream_prefix", "2001:db8:1::/64"))
    state["dns_server"] = ipaddress.IPv6Address(state.get("dns_server", "2001:db8:1::1"))
    for key, default in (("t1", 8), ("t2", 16), ("preferred_lifetime", 24),
                         ("valid_lifetime", 32), ("ra_lifetime", 30)):
        value = state.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 3600:
            raise ValueError("invalid timer")
        state[key] = value
    if not 0 < state["t1"] < state["t2"] < state["valid_lifetime"]:
        raise ValueError("invalid lease timer order")
    if not 0 < state["preferred_lifetime"] <= state["valid_lifetime"]:
        raise ValueError("invalid preferred lifetime")
    if state["prefix"].prefixlen > 64 or state["upstream_prefix"].prefixlen != 64:
        raise ValueError("unsupported fixture prefix")
    return state


def ia_value(code, value, state):
    if len(value) < 12:
        raise ValueError("short IA")
    answer = value[:4] + struct.pack("!II", state["t1"], state["t2"])
    if code == 3:
        answer += option(5, state["address"].packed + struct.pack("!II", state["preferred_lifetime"], state["valid_lifetime"]))
        for subcode, subvalue in options(value[12:]):
            if subcode == 5 and len(subvalue) >= 24 and subvalue[:16] != state["address"].packed:
                answer += option(5, subvalue[:16] + struct.pack("!II", 0, 0))
    elif code == 25:
        network = state["prefix"]
        answer += option(26, struct.pack("!IIB", state["preferred_lifetime"], state["valid_lifetime"], network.prefixlen)
                         + network.network_address.packed)
        # Explicitly retire the requested old prefix during a real renewal.
        for subcode, subvalue in options(value[12:]):
            if subcode == 26 and len(subvalue) >= 25:
                old_prefix = ipaddress.IPv6Network((ipaddress.IPv6Address(subvalue[9:25]), subvalue[8]))
                if old_prefix != network:
                    answer += option(26, struct.pack("!IIB", 0, 0, old_prefix.prefixlen) + old_prefix.network_address.packed)
    return option(code, answer)


class Fixture:
    def __init__(self, interface, state_file, status_file, advertise):
        self.interface = interface
        self.index = socket.if_nametoindex(interface)
        self.state_file = state_file
        self.status_file = status_file
        self.advertise = advertise
        self.running = True
        # DUID-UUID is generated once for this test process, never emitted.
        self.duid = struct.pack("!H", 4) + os.urandom(16)
        self.clients = set()
        self.counts = Counter()
        self.current_prefix = None
        self.last_reply = None
        self.udp = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
        self.udp.bind(("::", 547))
        group = socket.inet_pton(socket.AF_INET6, "ff02::1:2") + struct.pack("@I", self.index)
        self.udp.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, group)
        self.raw = None
        if advertise:
            self.raw = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
            self.raw.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
            self.raw.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, self.index)
            self.raw.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
            self.raw.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)

    def status(self):
        value = {"fixture": "dhcpv6", "messages": dict(self.counts), "distinct_clients": len(self.clients),
                 "current_prefix": self.current_prefix, "last_reply_monotonic": self.last_reply}
        temp = self.status_file.with_name(self.status_file.name + ".tmp")
        temp.write_text(json.dumps(value), encoding="ascii")
        os.replace(temp, self.status_file)

    def ra(self, state):
        if not self.raw or not state.get("ra_enabled", True):
            return
        # Select an established link-local address explicitly. An early global
        # source while LL DAD is still pending would make a legitimate host
        # reject the RA; this fixture waits rather than weakening acceptance.
        source = None
        for line in Path("/proc/net/if_inet6").read_text().splitlines():
            fields = line.split()
            if fields[5] == self.interface and int(fields[3], 16) == 0x20 and not (int(fields[4], 16) & 0x40):
                source = bytes.fromhex(fields[0])
                break
        if not source:
            return
        # M/O indicate IA_NA and DHCPv6 information availability. The on-link
        # /64 also has autonomous addressing, exercising real SLAAC reception.
        flags = 0xc0 if state.get("managed", True) else 0x40
        payload = struct.pack("!BBHBBHII", 134, 0, 0, 64, flags, state["ra_lifetime"], 0, 0)
        payload += struct.pack("!BBBBIII", 3, 4, 64, 0xc0, state["valid_lifetime"], state["preferred_lifetime"], 0)
        payload += state["upstream_prefix"].network_address.packed
        payload += struct.pack("!BBHI", 25, 3, 0, state["valid_lifetime"]) + state["dns_server"].packed
        ancillary = [(socket.IPPROTO_IPV6, socket.IPV6_PKTINFO, source + struct.pack("@I", self.index))]
        self.raw.sendmsg([payload], ancillary, 0, ("ff02::1", 0, 0, self.index))
        self.counts["ra_sent"] += 1

    def dhcp(self, packet, sender, state):
        if len(packet) < 4 or len(packet) > 8192:
            self.counts["malformed"] += 1
            return
        kind = packet[0]
        labels = {1: "solicit", 3: "request", 5: "renew", 6: "rebind", 8: "release", 11: "information_request"}
        if kind not in labels:
            self.counts["unsupported"] += 1
            return
        parsed = options(packet[4:])
        client = next((value for code, value in parsed if code == 1), None)
        server = next((value for code, value in parsed if code == 2), None)
        if not client or len(client) > 128 or (server is not None and server != self.duid):
            self.counts["ignored"] += 1
            return
        if client not in self.clients and len(self.clients) >= 16:
            self.counts["client_limit"] += 1
            return
        self.clients.add(client)
        self.counts[labels[kind]] += 1
        if state.get("silent", False):
            self.counts["silently_dropped"] += 1
            return
        reply_type = 2 if kind == 1 else 7
        reply = bytes([reply_type]) + packet[1:4] + option(1, client) + option(2, self.duid)
        reply += option(7, b"\xff")
        if kind == 8:
            reply += option(13, b"\0\0")
        else:
            for code, value in parsed:
                if code in (3, 25):
                    reply += ia_value(code, value, state)
            reply += option(23, state["dns_server"].packed)
        self.udp.sendto(reply, (sender[0], 546, 0, self.index))
        self.counts["advertise" if reply_type == 2 else "reply"] += 1
        self.current_prefix = str(state["prefix"])
        self.last_reply = round(time.monotonic(), 3)

    def run(self):
        next_ra = 0
        next_status = 0
        while self.running:
            try:
                state = control(self.state_file)
            except (OSError, ValueError, KeyError, TypeError):
                self.counts["control_errors"] += 1
                time.sleep(0.2)
                continue
            now = time.monotonic()
            if now >= next_ra:
                try:
                    self.ra(state)
                except OSError:
                    self.counts["ra_send_errors"] += 1
                next_ra = now + 2
            readers, _, _ = select.select([self.udp] + ([self.raw] if self.raw else []), [], [], 0.2)
            for reader in readers:
                try:
                    packet, sender = reader.recvfrom(8192)
                    if reader is self.udp:
                        self.dhcp(packet, sender, state)
                    elif packet and packet[0] == 133:
                        self.counts["router_solicit"] += 1
                        self.ra(state)
                except (OSError, ValueError, IndexError, struct.error):
                    self.counts["packet_errors"] += 1
            if now >= next_status:
                self.status()
                next_status = now + 0.5
        self.status()
        self.udp.close()
        if self.raw:
            self.raw.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--interface", required=True)
    parser.add_argument("--state-file", type=Path, required=True)
    parser.add_argument("--status-file", type=Path, required=True)
    parser.add_argument("--ra", action="store_true", help="also send actual ICMPv6 router advertisements")
    args = parser.parse_args()
    os.umask(0o077)
    fixture = Fixture(args.interface, args.state_file, args.status_file, args.ra)
    def stop(_signal, _frame):
        fixture.running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    fixture.run()


if __name__ == "__main__":
    main()
