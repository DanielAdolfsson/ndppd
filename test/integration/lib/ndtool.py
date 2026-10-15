#!/usr/bin/env python3
# ndppd - NDP Proxy Daemon
# Copyright (C) 2011-2026  Daniel Adolfsson <daniel@ashen.se>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# A neighbor-discovery packet tool, for the integration cases that need to
# assert on a frame rather than on whether a ping got through.
#
# Three of ndppd's behaviours cannot be reached with `ping` and `ip`:
#
#   - the Ethernet destination of an outgoing solicitation.  A wrong
#     solicited-node multicast MAC still reaches a veth peer, because the
#     peer's IPv6 stack accepts the frame on the strength of the IPv6
#     destination alone -- there is no hardware filter in the way.  On a
#     real bridge or NIC it is dropped, which is the bug fixed in #93.  The
#     only way to see it here is to look at the frame.
#
#   - a unicast NUD solicitation that omits the source link-layer address
#     option, as RFC 4861 7.7.3 says it should.  Linux always includes the
#     option, so the peer kernel cannot produce this packet; it has to be
#     built by hand.
#
#   - solicitations that ndppd is required to discard (multicast target,
#     hop limit below 255), which no cooperating kernel will emit.
#
# Everything here is stdlib: AF_PACKET sockets and struct.  Inside the
# suite's user namespace CAP_NET_RAW is available, so no privileges beyond
# what run.sh already establishes are needed.

import argparse
import binascii
import socket
import struct
import sys
import time

ETH_P_IPV6 = 0x86DD
ETH_P_ALL = 0x0003

IPPROTO_ICMPV6 = 58

ND_ROUTER_SOLICIT = 133
ND_ROUTER_ADVERT = 134
ND_NEIGHBOR_SOLICIT = 135
ND_NEIGHBOR_ADVERT = 136

ND_OPT_SOURCE_LINKADDR = 1
ND_OPT_TARGET_LINKADDR = 2

NA_FLAG_ROUTER = 0x80000000
NA_FLAG_SOLICITED = 0x40000000
NA_FLAG_OVERRIDE = 0x20000000


def mac_bytes(text):
    return binascii.unhexlify(text.replace(":", "").replace("-", ""))


def mac_text(raw):
    return ":".join("%02x" % b for b in raw)


def ip6_bytes(text):
    return socket.inet_pton(socket.AF_INET6, text)


def ip6_text(raw):
    return socket.inet_ntop(socket.AF_INET6, raw)


def solicited_node(target):
    """The ff02::1:ffXX:XXXX address a host joins for `target`."""
    raw = ip6_bytes(target)
    return ip6_bytes("ff02::1:ff00:0")[:13] + raw[13:16]


def solicited_node_mac(addr6):
    """The Ethernet MAC for an IPv6 multicast address: 33:33 followed by the
    last four bytes of the address.  For a solicited-node address that is
    always 33:33:ff:XX:XX:XX -- the 0xff comes from the address, not from
    the target, which is the distinction #93 fixed."""
    raw = ip6_bytes(addr6)
    return b"\x33\x33" + raw[12:16]


def checksum(data):
    if len(data) % 2:
        data += b"\x00"

    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]

    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)

    return (~total) & 0xFFFF


def icmp6_checksum(src, dst, payload):
    pseudo = src + dst + struct.pack("!I3xB", len(payload), IPPROTO_ICMPV6)
    return checksum(pseudo + payload)


def build_ns(src_mac, dst_mac, src_ip, dst_ip, target, sllao=True, hop_limit=255):
    body = struct.pack("!BBHI", ND_NEIGHBOR_SOLICIT, 0, 0, 0) + ip6_bytes(target)

    if sllao:
        body += struct.pack("!BB", ND_OPT_SOURCE_LINKADDR, 1) + mac_bytes(src_mac)

    src = ip6_bytes(src_ip)
    dst = ip6_bytes(dst_ip)

    cksum = icmp6_checksum(src, dst, body)
    body = body[:2] + struct.pack("!H", cksum) + body[4:]

    ip6 = struct.pack("!IHBB", 6 << 28, len(body), IPPROTO_ICMPV6, hop_limit) + src + dst
    eth = mac_bytes(dst_mac) + mac_bytes(src_mac) + struct.pack("!H", ETH_P_IPV6)

    return eth + ip6 + body


def parse(frame):
    """Decodes a frame into a dict, or returns None if it is not an ND
    message we care about."""
    if len(frame) < 14 + 40 + 8:
        return None

    eth_dst, eth_src, ethertype = frame[0:6], frame[6:12], struct.unpack("!H", frame[12:14])[0]

    if ethertype != ETH_P_IPV6:
        return None

    ip6 = frame[14:54]
    plen, nxt, hops = struct.unpack("!HBB", ip6[4:8])
    src, dst = ip6[8:24], ip6[24:40]

    if nxt != IPPROTO_ICMPV6:
        return None

    icmp = frame[54 : 54 + plen]

    if len(icmp) < 8:
        return None

    icmp_type = icmp[0]

    if icmp_type not in (ND_NEIGHBOR_SOLICIT, ND_NEIGHBOR_ADVERT):
        return None

    if len(icmp) < 24:
        return None

    out = {
        "type": "NS" if icmp_type == ND_NEIGHBOR_SOLICIT else "NA",
        "eth_dst": mac_text(eth_dst),
        "eth_src": mac_text(eth_src),
        "ip_src": ip6_text(src),
        "ip_dst": ip6_text(dst),
        "hop_limit": hops,
        "target": ip6_text(icmp[8:24]),
        "options": {},
    }

    if out["type"] == "NA":
        flags = struct.unpack("!I", icmp[4:8])[0]
        out["router"] = bool(flags & NA_FLAG_ROUTER)
        out["solicited"] = bool(flags & NA_FLAG_SOLICITED)
        out["override"] = bool(flags & NA_FLAG_OVERRIDE)

    offset = 24
    while offset + 8 <= len(icmp):
        opt_type, opt_len = icmp[offset], icmp[offset + 1]

        if opt_len == 0:
            break

        if opt_type in (ND_OPT_SOURCE_LINKADDR, ND_OPT_TARGET_LINKADDR):
            name = "sllao" if opt_type == ND_OPT_SOURCE_LINKADDR else "tllao"
            out["options"][name] = mac_text(icmp[offset + 2 : offset + 8])

        offset += opt_len * 8

    return out


def render(pkt):
    parts = [
        pkt["type"],
        "eth_src=" + pkt["eth_src"],
        "eth_dst=" + pkt["eth_dst"],
        "ip_src=" + pkt["ip_src"],
        "ip_dst=" + pkt["ip_dst"],
        "target=" + pkt["target"],
        "hop_limit=%d" % pkt["hop_limit"],
    ]

    if pkt["type"] == "NA":
        flags = [n for n in ("router", "solicited", "override") if pkt[n]]
        parts.append("flags=" + (",".join(flags) if flags else "none"))

    for name in ("sllao", "tllao"):
        if name in pkt["options"]:
            parts.append(name + "=" + pkt["options"][name])
        else:
            parts.append(name + "=none")

    return " ".join(parts)


def open_socket(iface, protocol=ETH_P_IPV6):
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(protocol))
    sock.bind((iface, 0))
    return sock


def cmd_sniff(args):
    sock = open_socket(args.iface)
    sock.settimeout(0.25)

    deadline = time.time() + args.seconds
    seen = 0

    while time.time() < deadline:
        try:
            frame = sock.recv(2048)
        except socket.timeout:
            continue

        pkt = parse(frame)

        if pkt is None:
            continue

        if args.type and pkt["type"] != args.type:
            continue

        if args.target and pkt["target"] != args.target:
            continue

        print(render(pkt))
        seen += 1

        if args.count and seen >= args.count:
            break

    return 0 if seen else 1


def cmd_send_ns(args):
    sock = open_socket(args.iface)
    frame = build_ns(
        args.src_mac,
        args.dst_mac,
        args.src_ip,
        args.dst_ip,
        args.target,
        sllao=not args.no_sllao,
        hop_limit=args.hop_limit,
    )
    sock.send(frame)
    return 0


def cmd_probe(args):
    """Sends a solicitation and reports any advertisement that comes back.

    Exits 0 if an advertisement for the target arrived, 1 if not -- so a
    case can assert on the exit status and read the decoded packet from
    stdout at the same time."""
    sock = open_socket(args.iface)
    sock.settimeout(0.25)

    frame = build_ns(
        args.src_mac,
        args.dst_mac,
        args.src_ip,
        args.dst_ip,
        args.target,
        sllao=not args.no_sllao,
        hop_limit=args.hop_limit,
    )

    for _ in range(args.retries):
        sock.send(frame)

        deadline = time.time() + args.timeout

        while time.time() < deadline:
            try:
                reply = sock.recv(2048)
            except socket.timeout:
                continue

            pkt = parse(reply)

            if pkt is None or pkt["type"] != "NA":
                continue

            if pkt["target"] != args.target:
                continue

            print(render(pkt))
            return 0

    print("no advertisement for %s" % args.target, file=sys.stderr)
    return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("sniff", help="decode neighbor discovery frames on an interface")
    p.add_argument("--iface", required=True)
    p.add_argument("--seconds", type=float, default=5.0)
    p.add_argument("--type", choices=("NS", "NA"))
    p.add_argument("--target")
    p.add_argument("--count", type=int, default=0)
    p.set_defaults(func=cmd_sniff)

    def add_ns_args(p):
        p.add_argument("--iface", required=True)
        p.add_argument("--src-mac", required=True)
        p.add_argument("--dst-mac", required=True)
        p.add_argument("--src-ip", required=True)
        p.add_argument("--dst-ip", required=True)
        p.add_argument("--target", required=True)
        p.add_argument("--no-sllao", action="store_true")
        p.add_argument("--hop-limit", type=int, default=255)

    p = sub.add_parser("send-ns", help="send one neighbor solicitation")
    add_ns_args(p)
    p.set_defaults(func=cmd_send_ns)

    p = sub.add_parser("probe", help="send a solicitation and wait for an advertisement")
    add_ns_args(p)
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--retries", type=int, default=3)
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("solicited-node", help="print the solicited-node address and MAC for a target")
    p.add_argument("target")
    p.set_defaults(
        func=lambda a: (
            print("%s %s" % (ip6_text(solicited_node(a.target)), mac_text(solicited_node_mac(ip6_text(solicited_node(a.target)))))),
            0,
        )[1]
    )

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
