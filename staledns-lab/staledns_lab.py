#!/usr/bin/env python3
"""Stale DNS lab: NetFlow v9 for "Could you see that in flow data?" (deck slide 9).

Four fake routers export NetFlow v9 for the stale DNS record outage:

  edge_office_east  192.168.252.11   office east LAN 10.41.2.0/24 (22 hosts)
  edge_office_west  192.168.252.12   office west LAN 10.52.0.0/24 (12 hosts)
  core_dc1          192.168.252.21   dc1 core: batch 10.20.9.0/24 (4 hosts), old orders-api 10.20.4.15
  hub_aws           192.168.252.31   transit hub: us-east-1 apps 10.60.4.0/24 (31 hosts),
                                     us-west-2 apps 10.61.4.0/24 (9 hosts), new orders-api 10.60.1.20

Phases match the deck's map states:

  before   everyone talks to orders-api at 10.20.4.15 (dc1) and gets replies
  change   cloud apps moved to 10.60.1.20; the few office lookups at night fail
  impact   38 office and batch hosts send SYNs to 10.20.4.15, nothing comes back;
           40 cloud hosts talk to 10.60.1.20 normally            <- slide 9
  fix      everyone talks to 10.60.1.20; 10.20.4.15 gets nothing

Each flow is exported by every router it enters (ingress), with input and output
interface. A real AWS side would come from VPC flow logs; here hub_aws stands in
as a router exporting NetFlow.

Standard library only. Kentik credentials come from the environment, never from here.

  sudo python3 staledns_lab.py aliases --apply
  python3 staledns_lab.py run --collector 127.0.0.1 --port 9995 --phase impact
  python3 staledns_lab.py kentik onboard --dry-run
  python3 staledns_lab.py kentik dimensions --dry-run
  python3 staledns_lab.py listen --port 9995          # decode what's being sent
  sudo python3 staledns_lab.py run --dns ...          # plus fake DNS on 192.168.252.53 / .54
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import random
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Dict, List, Optional, Tuple

# ------------------------------------------------------------------ the lab

OLD = "10.20.4.15"   # orders-api in dc1, released in IPAM
NEW = "10.60.1.20"   # orders-api in AWS us-east-1
PORT = 443

# group -> label, subnet, host count, host offsets that must be present (match the slide's sample records)
GROUPS = {
    "office_east": ("Office east", "10.41.2.0/24", 22, [17, 88]),
    "office_west": ("Office west", "10.52.0.0/24", 12, [31]),
    "batch":       ("dc1 batch", "10.20.9.0/24", 4, [14]),
    "aws_east":    ("AWS us-east-1 apps", "10.60.4.0/24", 31, [22]),
    "aws_west":    ("AWS us-west-2 apps", "10.61.4.0/24", 9, []),
}
DESTS = {"old": ("orders-api old (dc1)", OLD), "new": ("orders-api new (AWS)", NEW)}

# device -> sending IP, {ifIndex: description}
DEVICES = {
    "edge_office_east": ("192.168.252.11", {1: "LAN 10.41.2.0/24", 2: "WAN to dc1"}),
    "edge_office_west": ("192.168.252.12", {1: "LAN 10.52.0.0/24", 2: "WAN to dc1"}),
    "core_dc1": ("192.168.252.21", {1: "WAN office east", 2: "WAN office west", 3: "Server VLAN (orders-api old)",
                                    4: "Batch VLAN", 5: "Interconnect to AWS"}),
    "hub_aws": ("192.168.252.31", {1: "Interconnect to dc1", 2: "orders VPC us-east-1",
                                   3: "apps VPC us-east-1", 4: "apps VPC us-west-2"}),
}

# (group, dest) -> hops (device, in ifIndex, out ifIndex), source to destination
PATHS = {
    ("office_east", "old"): [("edge_office_east", 1, 2), ("core_dc1", 1, 3)],
    ("office_west", "old"): [("edge_office_west", 1, 2), ("core_dc1", 2, 3)],
    ("batch", "old"):       [("core_dc1", 4, 3)],
    ("aws_east", "old"):    [("hub_aws", 3, 1), ("core_dc1", 5, 3)],
    ("aws_west", "old"):    [("hub_aws", 4, 1), ("core_dc1", 5, 3)],
    ("office_east", "new"): [("edge_office_east", 1, 2), ("core_dc1", 1, 5), ("hub_aws", 1, 2)],
    ("office_west", "new"): [("edge_office_west", 1, 2), ("core_dc1", 2, 5), ("hub_aws", 1, 2)],
    ("batch", "new"):       [("core_dc1", 4, 5), ("hub_aws", 1, 2)],
    ("aws_east", "new"):    [("hub_aws", 3, 2)],
    ("aws_west", "new"):    [("hub_aws", 4, 2)],
}

# phase -> group -> (dest, healthy, activity 0..1)
_ALL = list(GROUPS)
PHASES = {
    "before": {g: ("old", True, 1.0) for g in _ALL},
    "change": {"aws_east": ("new", True, 1.0), "aws_west": ("new", True, 1.0),
               "office_east": ("old", False, 0.1), "office_west": ("old", False, 0.1)},
    "impact": {"office_east": ("old", False, 1.0), "office_west": ("old", False, 1.0), "batch": ("old", False, 1.0),
               "aws_east": ("new", True, 1.0), "aws_west": ("new", True, 1.0)},
    "fix": {g: ("new", True, 1.0) for g in _ALL},
}
PHASE_HELP = {
    "before": "everyone -> 10.20.4.15, normal replies",
    "change": "cloud apps -> 10.60.1.20; a few office lookups -> 10.20.4.15 fail",
    "impact": "38 office/batch hosts -> 10.20.4.15 SYN only, no replies; 40 cloud hosts -> 10.60.1.20 (slide 9)",
    "fix": "everyone -> 10.60.1.20; nothing to 10.20.4.15",
}

# ------------------------------------------------------------------ fake DNS (for Kentik synthetic tests)

DNS_ZONE = "corp.example"
ORDERS_NAME = "orders-api.corp.example"
# server -> label, listen IP
DNS_SERVERS = {"onprem": ("On-prem DNS", "192.168.252.53"), "cloud": ("Cloud DNS (private zone)", "192.168.252.54")}
# phase -> server -> (address, TTL) for orders-api. The on-prem copy is the one nobody owned.
ORDERS_ANSWERS = {
    "before": {"onprem": (OLD, 86400), "cloud": (OLD, 300)},
    "change": {"onprem": (OLD, 86400), "cloud": (NEW, 300)},
    "impact": {"onprem": (OLD, 86400), "cloud": (NEW, 300)},
    "fix":    {"onprem": (NEW, 300), "cloud": (NEW, 300)},
}
# Names that answer the same everywhere, in every phase: a healthy control test.
STATIC_RECORDS = {"payments-db.corp.example": ("10.30.8.40", 3600)}
QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"}


def dns_lookup(server: str, phase: str, name: str) -> Optional[Tuple[str, int]]:
    name = name.lower().rstrip(".")
    if name == ORDERS_NAME:
        return ORDERS_ANSWERS[phase][server]
    return STATIC_RECORDS.get(name)


def _qname(pkt: bytes, off: int) -> Tuple[str, int]:
    labels = []
    while True:
        if off >= len(pkt):
            raise ValueError("truncated name")
        n = pkt[off]
        if n == 0:
            return ".".join(labels), off + 1
        if n & 0xC0:
            raise ValueError("compressed name in question")
        labels.append(pkt[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n


def _name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\0"


def _soa() -> bytes:
    rdata = _name("ns1." + DNS_ZONE) + _name("hostmaster." + DNS_ZONE) + struct.pack("!IIIII", 2026110301, 3600, 600, 86400, 60)
    return _name(DNS_ZONE) + struct.pack("!HHIH", 6, 1, 60, len(rdata)) + rdata


def dns_response(pkt: bytes, server: str, phase: str) -> Tuple[Optional[bytes], str]:
    """Answer one DNS query as `server` would in `phase`. Returns (response or None, log text)."""
    if len(pkt) < 12:
        return None, "short packet ignored"
    qid, flags, qd, _an, _ns, ar = struct.unpack("!HHHHHH", pkt[:12])
    rd = flags & 0x0100
    if flags & 0x8000:
        return None, "response ignored"
    try:
        qname, off = _qname(pkt, 12)
        qtype, qclass = struct.unpack("!HH", pkt[off:off + 4])
    except (ValueError, struct.error):
        return struct.pack("!HHHHHH", qid, 0x8000 | rd | 1, 0, 0, 0, 0), "malformed query: FORMERR"
    qend = off + 4
    question = pkt[12:qend]
    edns = ar > 0 and pkt[qend:qend + 3] == b"\x00\x00\x29"
    opt = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0) if edns else b""
    name = qname.lower().rstrip(".")
    tname = QTYPES.get(qtype, str(qtype))

    def reply(rcode: int, answers: bytes = b"", n_ans: int = 0, soa: bool = False) -> bytes:
        f = 0x8000 | (0x0400 if rcode != 5 else 0) | rd | rcode
        return (struct.pack("!HHHHHH", qid, f, 1, n_ans, 1 if soa else 0, 1 if edns else 0)
                + question + answers + (_soa() if soa else b"") + opt)

    if (flags >> 11) & 0xF:
        return reply(4), "%s %s: NOTIMP" % (tname, name)
    if name != DNS_ZONE and not name.endswith("." + DNS_ZONE):
        return reply(5), "%s %s: REFUSED (not %s)" % (tname, name, DNS_ZONE)
    hit = dns_lookup(server, phase, name)
    if hit is None:
        if name == DNS_ZONE and qtype == 6:
            return reply(0, _soa(), 1), "SOA %s" % name
        return reply(3 if name != DNS_ZONE else 0, soa=True), "%s %s: %s" % (tname, name, "NXDOMAIN" if name != DNS_ZONE else "no data")
    if qtype in (1, 255) and qclass == 1:
        ip, ttl = hit
        rr = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, ttl, 4) + socket.inet_aton(ip)
        return reply(0, rr, 1), "A %s -> %s (TTL %d)" % (name, ip, ttl)
    return reply(0, soa=True), "%s %s: no %s record" % (tname, name, tname)


class DnsServer:
    """One fake DNS server on UDP and TCP, answering for the current phase."""

    def __init__(self, key: str, ip: str, port: int, get_phase, quiet: bool = False):
        self.key, self.label = key, DNS_SERVERS[key][0]
        self.ip, self.port, self.get_phase, self.quiet = ip, port, get_phase, quiet
        self.queries = 0
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind((ip, port))
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind((ip, port))
        self.tcp.listen(16)

    def start(self) -> "DnsServer":
        threading.Thread(target=self._udp_loop, daemon=True).start()
        threading.Thread(target=self._tcp_loop, daemon=True).start()
        return self

    def _answer(self, data: bytes, peer: str, proto: str) -> Optional[bytes]:
        resp, text = dns_response(data, self.key, self.get_phase())
        self.queries += 1
        if not self.quiet:
            print("[%s] %-24s %s/%s <- %-15s %s" % (time.strftime("%H:%M:%S"), self.label, self.ip, proto, peer, text), flush=True)
        return resp

    def _udp_loop(self) -> None:
        while True:
            try:
                data, addr = self.udp.recvfrom(4096)
            except OSError:
                return
            resp = self._answer(data, addr[0], "udp")
            if resp:
                self.udp.sendto(resp, addr)

    def _tcp_loop(self) -> None:
        while True:
            try:
                conn, addr = self.tcp.accept()
            except OSError:
                return
            threading.Thread(target=self._tcp_conn, args=(conn, addr[0]), daemon=True).start()

    def _tcp_conn(self, conn: socket.socket, peer: str) -> None:
        conn.settimeout(10)
        try:
            while True:
                hdr = conn.recv(2)
                if len(hdr) < 2:
                    return
                need, data = struct.unpack("!H", hdr)[0], b""
                while len(data) < need:
                    chunk = conn.recv(need - len(data))
                    if not chunk:
                        return
                    data += chunk
                resp = self._answer(data, peer, "tcp")
                if resp:
                    conn.sendall(struct.pack("!H", len(resp)) + resp)
        except OSError:
            return
        finally:
            conn.close()

    def close(self) -> None:
        for s in (self.udp, self.tcp):
            try:
                s.close()
            except OSError:
                pass


def start_dns(get_phase, port: int = 53, ips: Optional[List[str]] = None, quiet: bool = False) -> List[DnsServer]:
    keys = list(DNS_SERVERS)
    ips = ips or [DNS_SERVERS[k][1] for k in keys]
    return [DnsServer(k, ip, port, get_phase, quiet).start() for k, ip in zip(keys, ips)]


def _dns_bind_help(e: OSError, port: int) -> str:
    hint = ("Port %d needs root: run with sudo (the run and dns commands don't need your Kentik env vars)." % port
            if port < 1024 and getattr(e, "errno", None) == 13 else
            "Add the DNS IPs first: sudo python3 %s aliases --apply" % sys.argv[0])
    return "Can't start the DNS servers (%s). %s" % (e, hint)


SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01
FULL = SYN | ACK | PSH | FIN


def hosts(group: str) -> List[str]:
    """The group's host IPs: its required offsets, then a fixed pseudo-random fill."""
    _, subnet, count, must = GROUPS[group]
    net = ipaddress.ip_network(subnet)
    rng = random.Random(subnet)
    offs = list(must)
    pool = [o for o in range(10, 250) if o not in offs]
    rng.shuffle(pool)
    offs += pool[:count - len(offs)]
    return [str(net.network_address + o) for o in sorted(offs)]


def conversation(group: str, src: str, dest: str, healthy: bool, now: float, rng: random.Random) -> List[Tuple]:
    """Flow records for one connection attempt: (device, record dict)."""
    dst = DESTS[dest][1]
    sport = rng.randint(49152, 65535)
    out = []
    if healthy:
        start = now - rng.uniform(1, 9)
        pk = rng.randint(20, 300)
        fwd = (pk, pk * rng.randint(90, 400))
        rp = int(pk * rng.uniform(1.1, 1.6))
        rev = (rp, rp * rng.randint(900, 1400))
        for dev, i, o in PATHS[(group, dest)]:
            out.append((dev, rec(src, dst, sport, PORT, FULL, i, o, fwd[0], fwd[1], start, now)))
        for dev, i, o in reversed(PATHS[(group, dest)]):
            out.append((dev, rec(dst, src, PORT, sport, FULL, o, i, rev[0], rev[1], start, now)))
    else:
        start = now - 7   # SYN plus two retransmits
        pk = 6 if group == "batch" else 3
        for dev, i, o in PATHS[(group, dest)]:
            out.append((dev, rec(src, dst, sport, PORT, SYN, i, o, pk, pk * 60, start, now)))
    return out


def rec(src, dst, sport, dport, flags, in_if, out_if, pkts, octets, first, last) -> Dict:
    return {"src": src, "dst": dst, "sport": sport, "dport": dport, "proto": 6, "flags": flags, "tos": 0,
            "in_if": in_if, "out_if": out_if, "pkts": pkts, "bytes": octets, "first": first, "last": last}


def generate(phase: str, interval: float, now: float, rng: random.Random, period: float = 12.0) -> List[Tuple]:
    """All flow records for one tick: each host starts a connection about every `period` seconds."""
    out = []
    for group, rule in PHASES[phase].items():
        dest, healthy, activity = rule
        p = min(1.0, interval * activity / period)
        for h in hosts(group):
            if rng.random() < p:
                out += conversation(group, h, dest, healthy, now, rng)
    return out


# ------------------------------------------------------------------ NetFlow v9

TEMPLATE_ID = 256
# (field type, length): src addr, dst addr, src port, dst port, protocol, tcp flags, tos,
# input snmp, output snmp, packets, bytes, first switched, last switched, src mask, dst mask
FIELDS = [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (6, 1), (5, 1), (10, 2), (14, 2),
          (2, 4), (1, 4), (22, 4), (21, 4), (9, 1), (13, 1)]
REC_FMT = "!4s4sHHBBBHHIIIIBB"
REC_LEN = struct.calcsize(REC_FMT)   # 37
MAX_PER_PACKET = 30


def _pad(b: bytes) -> bytes:
    return b + b"\0" * (-len(b) % 4)


def template_flowset() -> bytes:
    body = struct.pack("!HH", TEMPLATE_ID, len(FIELDS)) + b"".join(struct.pack("!HH", t, l) for t, l in FIELDS)
    return struct.pack("!HH", 0, 4 + len(body)) + body


def encode(records: List[Dict], seq: int, boot: float, now: float, source_id: int, with_template: bool) -> bytes:
    up = lambda t: max(0, int((t - boot) * 1000)) & 0xFFFFFFFF
    body = b"".join(struct.pack(REC_FMT, socket.inet_aton(r["src"]), socket.inet_aton(r["dst"]), r["sport"], r["dport"],
                                r["proto"], r["flags"], r["tos"], r["in_if"], r["out_if"], r["pkts"], r["bytes"],
                                up(r["first"]), up(r["last"]), 24, 24)
                    for r in records)
    sets = (template_flowset() if with_template else b"")
    if records:
        data = _pad(struct.pack("!HH", TEMPLATE_ID, 0) + body)
        data = struct.pack("!HH", TEMPLATE_ID, len(data)) + data[4:]
        sets += data
    count = len(records) + (1 if with_template else 0)
    return struct.pack("!HHIIII", 9, count, up(now), int(now), seq, source_id) + sets


def decode(pkt: bytes, templates: Dict) -> Tuple[Dict, List[Dict]]:
    """Decode one v9 packet. templates is (source_id, template id) -> field list, filled as templates arrive."""
    ver, count, uptime, secs, seq, sid = struct.unpack("!HHIIII", pkt[:20])
    if ver != 9:
        raise ValueError("not NetFlow v9 (version %d)" % ver)
    hdr = {"count": count, "uptime": uptime, "secs": secs, "seq": seq, "source_id": sid}
    out, off = [], 20
    while off + 4 <= len(pkt):
        fid, ln = struct.unpack("!HH", pkt[off:off + 4])
        if ln < 4:
            break
        body = pkt[off + 4:off + ln]
        if fid == 0:
            p = 0
            while p + 4 <= len(body):
                tid, n = struct.unpack("!HH", body[p:p + 4])
                fl = [struct.unpack("!HH", body[p + 4 + 4 * i:p + 8 + 4 * i]) for i in range(n)]
                templates[(sid, tid)] = fl
                p += 4 + 4 * n
        elif fid >= 256 and (sid, fid) in templates:
            fl = templates[(sid, fid)]
            size = sum(l for _, l in fl)
            p = 0
            while p + size <= len(body):
                vals, q = {}, p
                for t, l in fl:
                    raw = body[q:q + l]
                    vals[t] = socket.inet_ntoa(raw) if t in (8, 12) else int.from_bytes(raw, "big")
                    q += l
                out.append({"src": vals[8], "dst": vals[12], "sport": vals[7], "dport": vals[11], "proto": vals[4],
                            "flags": vals[6], "in_if": vals[10], "out_if": vals[14], "pkts": vals[2], "bytes": vals[1]})
                p += size
        off += ln
    return hdr, out


class Exporter:
    """One fake router: its own UDP socket bound to its sending IP."""

    def __init__(self, name: str, ip: str, collector: Tuple[str, int], source_id: int, bind: bool = True,
                 template_every: float = 30.0):
        self.name, self.ip, self.collector, self.source_id = name, ip, collector, source_id
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if bind:
            self.sock.bind((ip, 0))
        self.boot = time.time() - 86400
        self.seq = 0
        self.last_template = 0.0
        self.template_every = template_every
        self.sent_flows = 0

    def send(self, records: List[Dict], now: float) -> None:
        chunks = [records[i:i + MAX_PER_PACKET] for i in range(0, len(records), MAX_PER_PACKET)] or [[]]
        for chunk in chunks:
            tmpl = now - self.last_template >= self.template_every
            if not chunk and not tmpl:
                continue
            self.sock.sendto(encode(chunk, self.seq, self.boot, now, self.source_id, tmpl), self.collector)
            if tmpl:
                self.last_template = now
            self.seq += len(chunk)
            self.sent_flows += len(chunk)


# ------------------------------------------------------------------ commands

def parse_timeline(spec: str) -> List[Tuple[str, float]]:
    out = []
    for part in spec.split(","):
        name, _, mins = part.strip().partition(":")
        if name not in PHASES:
            raise ValueError("unknown phase %r (choose from %s)" % (name, ", ".join(PHASES)))
        out.append((name, float(mins or 0) * 60))
    return out


def cmd_run(args) -> int:
    collector = (args.collector, args.port)
    try:
        exporters = {n: Exporter(n, ip, collector, i + 1, bind=not args.no_bind)
                     for i, (n, (ip, _)) in enumerate(DEVICES.items())}
    except OSError as e:
        print("Can't bind a device IP (%s). Run: sudo python3 %s aliases --apply\n"
              "or add --no-bind to send from this host's own IP (Kentik then sees one device)." % (e, sys.argv[0]),
              file=sys.stderr)
        return 1
    state = {"phase": args.phase, "stop": False}
    timeline = parse_timeline(args.timeline) if args.timeline else []
    rng = random.Random(args.seed)
    dns = []
    if args.dns:
        try:
            dns = start_dns(lambda: state["phase"], args.dns_port, _dns_ips(args), args.quiet_dns)
        except OSError as e:
            print(_dns_bind_help(e, args.dns_port), file=sys.stderr)
            return 1

    def console():
        for line in sys.stdin:
            cmd = line.strip().lower()
            if cmd in PHASES:
                state["phase"] = cmd
                timeline.clear()
                print("-> phase %s: %s" % (cmd, PHASE_HELP[cmd]))
            elif cmd == "status":
                print("phase %s | flows sent: %s" % (state["phase"], ", ".join(
                    "%s %d" % (n, e.sent_flows) for n, e in exporters.items())))
                for d in dns:
                    print("  %s %s:%d answered %d queries; %s now -> %s" % (
                        d.label, d.ip, d.port, d.queries, ORDERS_NAME, ORDERS_ANSWERS[state["phase"]][d.key][0]))
            elif cmd in ("quit", "exit", "q"):
                state["stop"] = True
                return
            elif cmd:
                print("commands: %s, status, quit" % ", ".join(PHASES))

    if not args.no_console and sys.stdin.isatty():
        threading.Thread(target=console, daemon=True).start()
    print("Sending NetFlow v9 to %s:%d from %s" % (args.collector, args.port, ", ".join(
        "%s %s" % (n, ip) for n, (ip, _) in DEVICES.items())))
    if timeline:
        print("Timeline: " + ", ".join("%s %gm" % (p, s / 60) for p, s in timeline))
        state["phase"] = timeline[0][0]
    for d in dns:
        print("DNS: %s on %s:%d (udp and tcp)" % (d.label, d.ip, d.port))
    print("Phase %s: %s" % (state["phase"], PHASE_HELP[state["phase"]]))
    print("Type a phase name (%s), status, or quit." % ", ".join(PHASES))
    started = phase_start = time.time()
    last_report = started
    try:
        while not state["stop"]:
            now = time.time()
            if timeline and now - phase_start >= timeline[0][1]:
                timeline.pop(0)
                phase_start = now
                if timeline:
                    state["phase"] = timeline[0][0]
                    print("-> phase %s: %s" % (state["phase"], PHASE_HELP[state["phase"]]))
            by_dev: Dict[str, List[Dict]] = {n: [] for n in DEVICES}
            for dev, r in generate(state["phase"], args.interval, now, rng):
                by_dev[dev].append(r)
            for n, recs in by_dev.items():
                exporters[n].send(recs, now)
            if now - last_report >= 60:
                last_report = now
                print("[%s] phase %s, flows sent: %d" % (time.strftime("%H:%M:%S"), state["phase"],
                                                         sum(e.sent_flows for e in exporters.values())))
            if args.duration and now - started >= args.duration:
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        pass
    for d in dns:
        d.close()
    print("Stopped. Flows sent: %d" % sum(e.sent_flows for e in exporters.values()))
    return 0


def _dns_ips(args) -> Optional[List[str]]:
    if not args.dns_ips:
        return None
    ips = [x.strip() for x in args.dns_ips.split(",") if x.strip()]
    if len(ips) != 2:
        sys.exit("--dns-ips needs two addresses: on-prem,cloud")
    return ips


def cmd_dns(args) -> int:
    """Only the DNS servers, no flow. Type a phase name to change the answers."""
    state = {"phase": args.phase}
    try:
        servers = start_dns(lambda: state["phase"], args.dns_port, _dns_ips(args), args.quiet_dns)
    except OSError as e:
        print(_dns_bind_help(e, args.dns_port), file=sys.stderr)
        return 1
    for d in servers:
        print("%s on %s:%d (udp and tcp)" % (d.label, d.ip, d.port))

    def show():
        a = ORDERS_ANSWERS[state["phase"]]
        print("Phase %s: %s -> on-prem %s, cloud %s" % (state["phase"], ORDERS_NAME, a["onprem"][0], a["cloud"][0]))
    show()
    print("Type a phase name (%s), status, or quit." % ", ".join(PHASES))
    try:
        if sys.stdin.isatty():
            for line in sys.stdin:
                cmd = line.strip().lower()
                if cmd in PHASES:
                    state["phase"] = cmd
                    show()
                elif cmd == "status":
                    show()
                    for d in servers:
                        print("  %s answered %d queries" % (d.label, d.queries))
                elif cmd in ("quit", "exit", "q"):
                    break
                elif cmd:
                    print("commands: %s, status, quit" % ", ".join(PHASES))
        else:
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        pass
    for d in servers:
        d.close()
    return 0


def cmd_listen(args) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    print("Listening on %s:%d (Ctrl-C to stop)" % (args.host, args.port))
    templates, n = {}, 0
    try:
        while not args.count or n < args.count:
            pkt, (ip, _) = sock.recvfrom(65535)
            _, recs = decode(pkt, templates)
            for r in recs:
                n += 1
                print("%-15s %15s:%-5d -> %15s:%-5d flags %-3s if %d->%d %6d pkts %9d bytes" % (
                    ip, r["src"], r["sport"], r["dst"], r["dport"], flag_str(r["flags"]), r["in_if"], r["out_if"],
                    r["pkts"], r["bytes"]))
    except KeyboardInterrupt:
        pass
    return 0


def flag_str(f: int) -> str:
    return "".join(c for b, c in ((SYN, "S"), (ACK, "A"), (PSH, "P"), (FIN, "F")) if f & b) or "-"


def cmd_preview(args) -> int:
    """Print what one phase sends over a minute, summarized like the slide."""
    rng = random.Random(args.seed)
    recs = []
    for i in range(int(60 / 5)):
        recs += [r for _, r in generate(args.phase, 5, 1000.0 + i * 5, rng)]
    srcs: Dict[Tuple[str, str], set] = {}
    replies = {OLD: 0, NEW: 0}
    for r in recs:
        if r["dport"] == PORT:
            g = next(g for g in GROUPS if r["src"] in hosts(g))
            srcs.setdefault((GROUPS[g][0], r["dst"]), set()).add(r["src"])
        elif r["src"] in replies:
            replies[r["src"]] += 1
    print("Phase %s over one minute: %s" % (args.phase, PHASE_HELP[args.phase]))
    for (label, dst), s in sorted(srcs.items(), key=lambda x: (x[0][1], x[0][0])):
        print("  %-20s -> %-11s %3d hosts" % (label, dst, len(s)))
    for dst, n in replies.items():
        print("  replies from %-11s %d flow records" % (dst, n))
    return 0


def _alias_cmds(remove: bool) -> List[List[str]]:
    out = []
    for ip in [ip for ip, _ in DEVICES.values()] + [ip for _, ip in DNS_SERVERS.values()]:
        if platform.system() == "Darwin":
            out.append(["ifconfig", "lo0", "-alias" if remove else "alias", ip + "/32"])
        else:
            out.append(["ip", "addr", "del" if remove else "add", ip + "/32", "dev", "lo"])
    return out


def cmd_aliases(args) -> int:
    cmds = _alias_cmds(args.remove)
    if not args.apply:
        print("# Run as root, or rerun with --apply under sudo:")
        for c in cmds:
            print(" ".join(c))
        return 0
    rc = 0
    for c in cmds:
        try:
            r = subprocess.run(c, capture_output=True, text=True)
        except FileNotFoundError:
            print("%s not found. Install iproute2 (sudo apt install iproute2) and retry." % c[0], file=sys.stderr)
            return 1
        msg = "ok" if r.returncode == 0 else (r.stderr.strip() or "failed")
        if r.returncode and "File exists" not in msg and "Cannot assign" not in msg:
            rc = 1
        print("%-48s %s" % (" ".join(c), msg))
    return rc


# ------------------------------------------------------------------ Kentik

DEVICE_API = "https://grpc.api.kentik.com"   # EU: https://grpc.api.kentik.eu
DEVICE_PATH = "/device/v202504beta2/device"
V5_API = "https://api.kentik.com/api/v5"      # EU: https://api.kentik.eu/api/v5
DIM_NAMES = ("c_src_outage", "c_dst_outage")


class KentikError(Exception):
    pass


class Api:
    """Small Kentik API client: spaced-out calls, 429 retried with backoff honoring Retry-After."""

    def __init__(self, email: str, token: str, base: str, delay: float = 1.0, retries: int = 6):
        self.base, self.delay, self.retries, self._last = base.rstrip("/"), delay, retries, None
        self.headers = {"X-CH-Auth-Email": email, "X-CH-Auth-API-Token": token, "Content-Type": "application/json"}

    def call(self, method: str, path: str, body: Optional[Dict] = None) -> Dict:
        data = json.dumps(body).encode() if body is not None else None
        for attempt in range(self.retries + 1):
            if self._last is not None:
                wait = self.delay - (time.monotonic() - self._last)
                if wait > 0:
                    time.sleep(wait)
            self._last = time.monotonic()
            req = urllib.request.Request(self.base + path, data=data, method=method, headers=self.headers)
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    raw = resp.read()
                return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as e:
                detail = e.read().decode(errors="replace")[:2000]
                if e.code == 429 and attempt < self.retries:
                    try:
                        backoff = max(0.0, float(e.headers.get("Retry-After")))
                    except (TypeError, ValueError):
                        backoff = min(60, 2 ** (attempt + 1))
                    print("  rate limited, waiting %gs" % backoff)
                    time.sleep(backoff)
                    continue
                raise KentikError("%s %s -> HTTP %d: %s" % (method, path, e.code, detail)) from None
            except urllib.error.URLError as e:
                raise KentikError("%s %s -> %s" % (method, path, e.reason)) from None
        raise KentikError("gave up after %d retries" % self.retries)


def build_devices(plan_id: Optional[int], site_id: Optional[int] = None) -> List[Dict]:
    out = []
    for name, (ip, ifs) in DEVICES.items():
        d = {"deviceName": name, "deviceSubtype": "router",
             "deviceDescription": "staledns lab: " + ", ".join("%d %s" % kv for kv in ifs.items()),
             "sendingIps": [ip], "deviceSampleRate": 1, "deviceBgpType": "none",
             "deviceBgpFlowspec": False, "minimizeSnmp": False}
        if plan_id is not None:
            d["planId"] = plan_id
        if site_id is not None:
            d["siteId"] = site_id
        out.append(d)
    return out

# Kentik rejects a device whose description is longer than this (HTTP 400, "device_description must not
# exceed 128 characters"). Checked before any API call, dry runs included.
MAX_DESCRIPTION = 128


def check_devices(devices: List[Dict]) -> List[str]:
    return ["%s: description is %d characters, Kentik allows %d: %r" % (
                d["deviceName"], len(d["deviceDescription"]), MAX_DESCRIPTION, d["deviceDescription"])
            for d in devices if len(d["deviceDescription"]) > MAX_DESCRIPTION]


def dimension_plan() -> List[Dict]:
    """c_src_outage / c_dst_outage: one populator per group, plus the two orders-api addresses."""
    values = [(label, [subnet]) for label, subnet, _, _ in GROUPS.values()]
    values += [(label, [ip + "/32"]) for label, ip in DESTS.values()]
    out = []
    for name, direction, title in ((DIM_NAMES[0], "src", "Src Outage group"), (DIM_NAMES[1], "dst", "Dst Outage group")):
        out.append({"name": name, "display_name": title, "type": "string",
                    "upserts": [{"value": v, "criteria": [{"direction": direction, "addr": a}]} for v, a in values]})
    return out


def _creds(args, need_plan: bool) -> Optional[str]:
    missing = [f for f, v in (("KENTIK_EMAIL", args.email), ("KENTIK_API_TOKEN", args.token)) if not v]
    if need_plan and not args.plan_id:
        missing.append("KENTIK_PLAN_ID")
    if missing:
        return ("Missing %s. Put export lines in ~/.kentik.env, chmod 600 it, then: source ~/.kentik.env\n"
                "(sudo drops env vars unless you use sudo -E). Or add --dry-run to only print the payload."
                % ", ".join(missing))
    return None


def cmd_onboard(args) -> int:
    devices = build_devices(args.plan_id, args.site_id)
    problems = check_devices(devices)
    if problems:
        print("Fix these before onboarding:\n  " + "\n  ".join(problems), file=sys.stderr)
        return 2
    if args.dry_run:
        print("# POST %s%s/batch_create (existing names go to PUT .../batch_update with their id)" % (args.api_url, DEVICE_PATH))
        print(json.dumps({"devices": devices}, indent=2))
        return 0
    err = _creds(args, True)
    if err:
        print(err, file=sys.stderr)
        return 2
    api = Api(args.email, args.token, args.api_url)
    try:
        have = {d["deviceName"]: d["id"] for d in api.call("GET", DEVICE_PATH + "?view=DEVICE_VIEW_BASIC").get("devices", [])
                if d.get("deviceName")}
        create = [d for d in devices if d["deviceName"] not in have]
        update = [dict(d, id=have[d["deviceName"]]) for d in devices if d["deviceName"] in have]
        if create:
            print("Creating: " + ", ".join(d["deviceName"] for d in create))
            resp = api.call("POST", DEVICE_PATH + "/batch_create", {"devices": create})
            if args.verbose:
                print(json.dumps(resp, indent=2))
            for d in create:   # batch answers 200 even when items fail: retry failures alone for the reason
                if d["deviceName"] in {str(x) for x in resp.get("failedDevices", [])}:
                    try:
                        api.call("POST", DEVICE_PATH, {"device": d})
                    except KentikError as e:
                        print("  %s failed: %s" % (d["deviceName"], e), file=sys.stderr)
        if update:
            print("Updating: " + ", ".join(d["deviceName"] for d in update))
            resp = api.call("PUT", DEVICE_PATH + "/batch_update", {"devices": update})
            if args.verbose:
                print(json.dumps(resp, indent=2))
        have = {d["deviceName"] for d in api.call("GET", DEVICE_PATH + "?view=DEVICE_VIEW_BASIC").get("devices", [])}
    except KentikError as e:
        print("Kentik API error: %s" % e, file=sys.stderr)
        return 1
    missing = [d["deviceName"] for d in devices if d["deviceName"] not in have]
    if missing:
        print("NOT in Kentik after the call: %s (rerun with -v to see the API's answer)" % ", ".join(missing), file=sys.stderr)
        return 1
    print("Verified: all %d devices are in Kentik. Flow from 192.168.252.x lands on them once the lab runs." % len(devices))
    return 0


def cmd_dimensions(args) -> int:
    plan = dimension_plan()
    if args.dry_run:
        print("# Each dimension is created only if missing (POST %s/customdimension), then its populators are\n"
              "# replaced in one call: POST %s/batch/customdimensions/<name>/populators (replace_all)" % (args.v5_url, args.v5_url))
        print(json.dumps(plan, indent=2))
        return 0
    err = _creds(args, False)
    if err:
        print(err, file=sys.stderr)
        return 2
    api = Api(args.email, args.token, args.v5_url)
    print("Note: replace_all removes any populators added by hand to %s." % " and ".join(DIM_NAMES))
    try:
        resp = api.call("GET", "/customdimensions")
        dims = resp.get("customDimensions", []) if isinstance(resp, dict) else resp
        have = {d["name"] for d in dims if d.get("name")}
        for dim in plan:
            if dim["name"] not in have:
                cur = api.call("POST", "/customdimension", {k: dim[k] for k in ("name", "type", "display_name")})
                cur = cur.get("customDimension", cur)
                if not cur.get("id"):
                    raise KentikError("creating %s returned no id: %s" % (dim["name"], cur))
                print("Created %s (%s)" % (dim["name"], dim["display_name"]))
            api.call("POST", "/batch/customdimensions/%s/populators" % dim["name"],
                     {"replace_all": True, "complete": True, "upserts": dim["upserts"]})
            print("%s: %d populators" % (dim["name"], len(dim["upserts"])))
        # read back: trust the dimension list, not the batch answer
        resp = api.call("GET", "/customdimensions")
        dims = {d["name"]: d for d in (resp.get("customDimensions", []) if isinstance(resp, dict) else resp)}
        for dim in plan:
            n = len((dims.get(dim["name"]) or {}).get("populators", []))
            print("  read back %s: %d populators%s" % (dim["name"], n, "" if n == len(dim["upserts"]) else
                                                       " (expected %d; populators can take a minute to apply)" % len(dim["upserts"])))
    except KentikError as e:
        print("Kentik API error: %s" % e, file=sys.stderr)
        return 1
    return 0


def main(argv=None) -> int:
    env = os.environ.get
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="send NetFlow v9 from the four fake routers")
    r.add_argument("--collector", default="127.0.0.1", help="Kentik agent/kproxy address (default 127.0.0.1)")
    r.add_argument("--port", type=int, default=9995)
    r.add_argument("--phase", choices=list(PHASES), default="impact")
    r.add_argument("--timeline", help='phases with minutes, e.g. "before:15,impact:30,fix:15" (ends on the last)')
    r.add_argument("--interval", type=float, default=5.0, help="seconds between export rounds")
    r.add_argument("--duration", type=float, default=0, help="stop after N seconds (0 = run until quit)")
    r.add_argument("--seed", type=int, default=None)
    r.add_argument("--no-bind", action="store_true", help="send from this host's IP instead of the device IPs")
    r.add_argument("--no-console", action="store_true")
    r.add_argument("--dns", action="store_true", help="also run the fake on-prem and cloud DNS servers, following the phase")
    r.set_defaults(func=cmd_run)

    dn = sub.add_parser("dns", help="run only the fake DNS servers (for Kentik synthetic DNS tests)")
    dn.add_argument("--phase", choices=list(PHASES), default="impact")
    dn.set_defaults(func=cmd_dns)
    for x in (r, dn):
        x.add_argument("--dns-port", type=int, default=53)
        x.add_argument("--dns-ips", help="on-prem,cloud listen IPs (default 192.168.252.53,192.168.252.54)")
        x.add_argument("--quiet-dns", action="store_true", help="don't print every DNS query")

    a = sub.add_parser("aliases", help="add the device IPs (192.168.252.x) to loopback")
    a.add_argument("--apply", action="store_true")
    a.add_argument("--remove", action="store_true")
    a.set_defaults(func=cmd_aliases)

    l = sub.add_parser("listen", help="decode and print NetFlow v9 arriving on a port (self-check)")
    l.add_argument("--host", default="127.0.0.1")
    l.add_argument("--port", type=int, default=9995)
    l.add_argument("--count", type=int, default=0)
    l.set_defaults(func=cmd_listen)

    v = sub.add_parser("preview", help="summarize one phase without sending anything")
    v.add_argument("--phase", choices=list(PHASES), default="impact")
    v.add_argument("--seed", type=int, default=1)
    v.set_defaults(func=cmd_preview)

    k = sub.add_parser("kentik", help="set up Kentik for the lab")
    ks = k.add_subparsers(dest="kcmd", required=True)
    for name, fn, hlp in (("onboard", cmd_onboard, "create or update the four devices (sample rate 1)"),
                          ("dimensions", cmd_dimensions, "create c_src_outage / c_dst_outage and their populators")):
        x = ks.add_parser(name, help=hlp)
        x.add_argument("--email", default=env("KENTIK_EMAIL"))
        x.add_argument("--token", default=env("KENTIK_API_TOKEN"))
        x.add_argument("--plan-id", type=int, default=int(env("KENTIK_PLAN_ID")) if (env("KENTIK_PLAN_ID") or "").strip().isdigit() else None)
        x.add_argument("--site-id", type=int, default=None)
        x.add_argument("--api-url", default=env("KENTIK_API_URL", DEVICE_API))
        x.add_argument("--v5-url", default=env("KENTIK_V5_API_URL", V5_API))
        x.add_argument("--dry-run", action="store_true")
        x.add_argument("-v", "--verbose", action="store_true")
        x.set_defaults(func=fn)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
