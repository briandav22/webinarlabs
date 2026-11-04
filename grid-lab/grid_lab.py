#!/usr/bin/env python3
"""Grid lab: a Palo Alto firewall quietly blocks the Infoblox grid after network maintenance.

Three fake devices export flow. The firewall exports the way PAN-OS does (NetFlow v9, the
"IPv4 Enterprise" template 257 with firewallEvent, flowId, App-ID and User-ID); the two routers
export plain NetFlow v9 like the other labs.

  grid_syd_wan    192.168.254.11  Sydney WAN router: Sydney LAN (grid member 10.70.1.10, office
                                  users 10.70.20.0/24), old APAC MPLS circuit, new APAC SD-WAN circuit
  grid_pa_dc_fw   192.168.254.21  Palo Alto firewall in front of dc1: ethernet1/1 trust (dc1 core),
                                  ethernet1/2 EMEA WAN (London grid member 10.80.1.10),
                                  ethernet1/3 APAC MPLS (zone apac-wan), ethernet1/4 APAC SD-WAN
                                  (zone apac-sdwan, new)
  grid_dc_core    192.168.254.31  dc1 core: infra VLAN (Grid Master 10.20.1.5), apps VLAN 10.20.30.0/24

Grid traffic is the member's VPN tunnel to the Grid Master (UDP 1194) and the key exchange a
member runs when it joins (UDP 2114).

  before       Both members' tunnels are up. The firewall sends flow update events (5) for them.
  maintenance  Sydney's WAN circuit is being moved from MPLS to SD-WAN: nothing leaves Sydney.
               The firewall ages out Sydney's tunnel session and sends flow deleted (2).
  impact       The new circuit is up on ethernet1/4 (zone apac-sdwan). The office rule was updated
               for the new zone, so users are fine and the change is closed. The grid rule was not:
               the member's retries on 1194 and 2114 hit the interzone default deny, and the
               firewall sends flow denied (3) for each one. dc1 never sees them.        <- the outage
  fix          The grid rule gets the new zone. Key exchange on 2114, a new tunnel (created, 1),
               then a burst of catch-up replication from the Grid Master.

Standard library only. Kentik credentials come from the environment, never from here.

  sudo python3 grid_lab.py aliases --apply
  python3 grid_lab.py run --collector 127.0.0.1 --port 9995 --timeline "before:10,maintenance:3,impact:20,fix:10"
  python3 grid_lab.py kentik onboard --dry-run
  python3 grid_lab.py kentik dimensions --dry-run
  python3 grid_lab.py preview --phase impact
"""
from __future__ import annotations

import argparse
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
import urllib.request
from typing import Dict, List, Optional, Tuple

# ------------------------------------------------------------------ the lab

SYD_MEMBER = "10.70.1.10"     # Infoblox grid member, Sydney
LON_MEMBER = "10.80.1.10"     # Infoblox grid member, London (control group: never breaks)
GRID_MASTER = "10.20.1.5"     # Grid Master, dc1
APP = "10.20.30.40"           # an internal app in dc1 the Sydney office uses
VPN_PORT, KEYX_PORT, APP_PORT = 1194, 2114, 443
UDP, TCP = 17, 6

OFFICE_USERS = ["ahill", "bnguyen", "cpatel", "dwong", "ekelly", "fsingh", "gmorris", "hlee", "ichen",
                "jsmith", "kobrien", "lmartin", "mtaylor", "nwhite", "ojones", "pbrown", "qli", "rcampbell"]


def office_hosts() -> List[Tuple[str, str]]:
    """(ip, User-ID) for the Sydney office users: 10.70.20.x with a fixed pseudo-random spread."""
    rng = random.Random("grid-office")
    offs = sorted(rng.sample(range(20, 240), len(OFFICE_USERS)))
    return [("10.70.20.%d" % o, "corp\\" + u) for o, u in zip(offs, OFFICE_USERS)]


# device -> sending IP, Kentik device subtype, {ifIndex: description}
DEVICES = {
    "grid_syd_wan": ("192.168.254.11", "router", {1: "Sydney LAN", 2: "APAC MPLS circuit (old)",
                                                  3: "APAC SD-WAN circuit (new)"}),
    "grid_pa_dc_fw": ("192.168.254.21", "paloalto", {1: "ethernet1/1 trust (dc1 core)",
                                                     2: "ethernet1/2 EMEA WAN (zone emea-wan)",
                                                     3: "ethernet1/3 APAC MPLS (zone apac-wan)",
                                                     4: "ethernet1/4 APAC SD-WAN (zone apac-sdwan)"}),
    "grid_dc_core": ("192.168.254.31", "router", {1: "Uplink to firewall", 2: "Infra VLAN 10.20.1.0/24 (Grid Master)",
                                                  3: "Apps VLAN 10.20.30.0/24"}),
}
FIREWALL = "grid_pa_dc_fw"
# Kentik caps device descriptions at 128 characters, so the firewall gets a shorter one than its
# interface names would make.
DESCRIPTIONS = {FIREWALL: "grid lab: 1 e1/1 trust, 2 e1/2 emea-wan, 3 e1/3 apac-wan (MPLS), 4 e1/4 apac-sdwan (SD-WAN, new)"}

# Hops (device, in ifIndex, out ifIndex) from the client to the server. The reply uses the same
# hops in reverse with in/out swapped.
PATHS = {
    ("syd", "mpls"):  [("grid_syd_wan", 1, 2), (FIREWALL, 3, 1), ("grid_dc_core", 1, 2)],
    ("syd", "sdwan"): [("grid_syd_wan", 1, 3), (FIREWALL, 4, 1), ("grid_dc_core", 1, 2)],
    ("lon", None):    [(FIREWALL, 2, 1), ("grid_dc_core", 1, 2)],
    ("office", "mpls"):  [("grid_syd_wan", 1, 2), (FIREWALL, 3, 1), ("grid_dc_core", 1, 3)],
    ("office", "sdwan"): [("grid_syd_wan", 1, 3), (FIREWALL, 4, 1), ("grid_dc_core", 1, 3)],
}

PHASES = {
    #               Sydney circuit, grid rule allows Sydney's zone
    "before":      ("mpls", True),
    "maintenance": (None, False),
    "impact":      ("sdwan", False),
    "fix":         ("sdwan", True),
}
PHASE_HELP = {
    "before": "both grid tunnels up over UDP 1194; the firewall sends flow update events",
    "maintenance": "Sydney's circuit is being moved to SD-WAN: Sydney goes quiet, its tunnel is deleted",
    "impact": "new circuit up, office users fine; grid retries on 1194/2114 denied at the firewall",
    "fix": "grid rule gets zone apac-sdwan: key exchange, new tunnel, catch-up replication",
}

# firewallEvent (IE 233) values, as PAN-OS documents them
CREATED, DELETED, DENIED, UPDATED = 1, 2, 3, 5
EVENT_NAMES = {0: "-", 1: "created", 2: "deleted", 3: "DENIED", 4: "alert", 5: "update"}

SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01
FULL = SYN | ACK | PSH | FIN

# Tunnel traffic in bytes per second each way: steady replication and heartbeats, and the catch-up
# burst from the Grid Master after the fix (it decays over CATCHUP_SECONDS).
TUNNEL_RATE = {"up": 3500, "down": 7000}
CATCHUP_RATE, CATCHUP_SECONDS = 150000, 240
VPN_RETRY, KEYX_RETRY = 10.0, 30.0   # seconds between the member's attempts while it's blocked


def rec(src, dst, sport, dport, proto, flags, in_if, out_if, pkts, octets, first, last, **pan) -> Dict:
    r = {"src": src, "dst": dst, "sport": sport, "dport": dport, "proto": proto, "flags": flags, "tos": 0,
         "in_if": in_if, "out_if": out_if, "pkts": max(1, int(pkts)), "bytes": max(1, int(octets)),
         "first": first, "last": last}
    r.update(pan)
    return r


class Tunnel:
    """A member's long-lived VPN session to the Grid Master (UDP 1194)."""

    def __init__(self, member: str, site: str, circuit: Optional[str], flow_id: int, now: float, sport: int,
                 fresh: bool, catchup: bool = False):
        self.member, self.site, self.circuit, self.flow_id = member, site, circuit, flow_id
        self.sport, self.start, self.last = sport, now, now
        self.fresh = fresh        # True: created by the lab, so the firewall announces it (event 1)
        self.catchup = catchup

    @property
    def hops(self):
        return PATHS[(self.site, self.circuit)]

    def rates(self, t0: float, t1: float) -> Tuple[float, float]:
        """Bytes up and down between t0 and t1."""
        up, down = TUNNEL_RATE["up"] * (t1 - t0), TUNNEL_RATE["down"] * (t1 - t0)
        if self.catchup:   # linear decay from CATCHUP_RATE to 0 over CATCHUP_SECONDS
            a, b = [min(CATCHUP_SECONDS, max(0.0, t - self.start)) for t in (t0, t1)]
            area = lambda x: CATCHUP_RATE * (x - x * x / (2 * CATCHUP_SECONDS))
            down += area(b) - area(a)
        return up, down


class Sim:
    """Builds the flow records each device exports, tick by tick, keeping session state across phases."""

    def __init__(self, phase: str, now: float, rng: random.Random, active_timeout: float = 60.0,
                 office_period: float = 12.0):
        self.rng, self.active_timeout, self.office_period = rng, active_timeout, office_period
        self.next_flow_id = rng.randint(200000, 900000)
        self.phase = phase
        self.pending: List[Tuple[str, Dict]] = []
        self.retry_clock = {VPN_PORT: VPN_RETRY, KEYX_PORT: KEYX_RETRY}   # first attempts right away
        # Tunnels that were already up when the lab started: no created event, just updates.
        self.tunnels = {"lon": Tunnel(LON_MEMBER, "lon", None, self._fid(), now, 1194, fresh=False)}
        circuit, allowed = PHASES[phase]
        if circuit and allowed:
            self.tunnels["syd"] = Tunnel(SYD_MEMBER, "syd", circuit, self._fid(), now, 1194, fresh=False)

    def _fid(self) -> int:
        self.next_flow_id += self.rng.randint(1, 40)
        return self.next_flow_id

    # ---- phase changes
    def set_phase(self, phase: str, now: float) -> None:
        if phase == self.phase:
            return
        self.phase = phase
        circuit, allowed = PHASES[phase]
        cur = self.tunnels.get("syd")
        if cur and (not allowed or cur.circuit != circuit):
            self.pending += self._export_tunnel(cur, now, DELETED)   # session ends: final counts
            del self.tunnels["syd"]
            cur = None
        if not cur and circuit and allowed:
            if phase == "fix":   # rejoin: key exchange first, then a new tunnel with catch-up replication
                self.pending += self._short_session(SYD_MEMBER, GRID_MASTER, KEYX_PORT, UDP, "unknown-udp", "",
                                                    PATHS[("syd", circuit)], now, (6, 2400), (6, 2100))
            self.tunnels["syd"] = Tunnel(SYD_MEMBER, "syd", circuit, self._fid(), now,
                                         self.rng.randint(49152, 65535), fresh=True, catchup=(phase == "fix"))
        self.retry_clock = {VPN_PORT: VPN_RETRY, KEYX_PORT: KEYX_RETRY}   # first attempts right away

    # ---- record builders
    @staticmethod
    def _routers(src, dst, sport, dport, proto, flags_fwd, flags_rev, hops, fwd, rev, first, last) -> List[Tuple[str, Dict]]:
        """The routers' records: one per router hop each way (the firewall is handled separately)."""
        out = []
        for dev, i, o in hops:
            if dev != FIREWALL and fwd[0]:
                out.append((dev, rec(src, dst, sport, dport, proto, flags_fwd, i, o, fwd[0], fwd[1], first, last)))
        for dev, i, o in reversed(hops):
            if dev != FIREWALL and rev[0]:
                out.append((dev, rec(dst, src, dport, sport, proto, flags_rev, o, i, rev[0], rev[1], first, last)))
        return out

    def _short_session(self, src, dst, dport, proto, app, user, hops, now, fwd, rev,
                       flags=(0, 0, 0)) -> List[Tuple[str, Dict]]:
        """A short allowed session. Routers export each direction once. The firewall announces the
        session with its first packet (created), then closes it with the rest of each direction (deleted).
        flags: (first packet, rest of client side, server side)."""
        sport, fid = self.rng.randint(49152, 65535), self._fid()
        first = now - self.rng.uniform(1, 9)
        out = self._routers(src, dst, sport, dport, proto, flags[1] | flags[0], flags[2], hops, fwd, rev, first, now)
        _, i, o = next(h for h in hops if h[0] == FIREWALL)
        c = {"event": CREATED, "flow_id": fid, "app": app, "user": user}
        d = dict(c, event=DELETED)
        head = 60 if proto == TCP else fwd[1] // fwd[0]   # the SYN, or the first datagram
        out.append((FIREWALL, rec(src, dst, sport, dport, proto, flags[0], i, o, 1, head, first, first, **c)))
        if fwd[0] > 1:
            out.append((FIREWALL, rec(src, dst, sport, dport, proto, flags[1], i, o, fwd[0] - 1, fwd[1] - head,
                                      first, now, **d)))
        out.append((FIREWALL, rec(dst, src, dport, sport, proto, flags[2], o, i, rev[0], rev[1], first, now, **d)))
        return out

    def _office_session(self, ip: str, user: str, hops, now: float) -> List[Tuple[str, Dict]]:
        pk = self.rng.randint(10, 120)
        fwd = (pk, pk * self.rng.randint(90, 300))
        rp = int(pk * self.rng.uniform(1.2, 2.0))
        rev = (rp, rp * self.rng.randint(600, 1400))
        return self._short_session(ip, APP, APP_PORT, TCP, "ssl", user, hops, now, fwd, rev,
                                   flags=(SYN, ACK | PSH | FIN, FULL))

    def _export_tunnel(self, t: Tunnel, now: float, event: int) -> List[Tuple[str, Dict]]:
        """The tunnel's counts since its last export, from every hop. On the firewall the record
        carries `event`: update (5) while it runs, deleted (2) when it ends."""
        up, down = t.rates(t.last, now)
        fwd, rev = (max(1, int(up / 220)), up), (max(1, int(down / 220)), down)   # small replication packets
        out = self._routers(t.member, GRID_MASTER, t.sport, VPN_PORT, UDP, 0, 0, t.hops, fwd, rev, t.last, now)
        _, i, o = next(h for h in t.hops if h[0] == FIREWALL)
        pan = {"event": event, "flow_id": t.flow_id, "app": "openvpn", "user": ""}
        out.append((FIREWALL, rec(t.member, GRID_MASTER, t.sport, VPN_PORT, UDP, 0, i, o, fwd[0], fwd[1], t.last, now, **pan)))
        out.append((FIREWALL, rec(GRID_MASTER, t.member, VPN_PORT, t.sport, UDP, 0, o, i, rev[0], rev[1], t.last, now, **pan)))
        t.last = now
        return out

    def _denied_attempt(self, dport: int, now: float) -> List[Tuple[str, Dict]]:
        """One blocked try from the Sydney member: the WAN router forwards it, the firewall denies it,
        nothing reaches dc1 and nothing comes back."""
        hops = PATHS[("syd", PHASES[self.phase][0])]
        sport = self.rng.randint(49152, 65535)
        size = 86 if dport == VPN_PORT else 120
        wan, fw = hops[0], hops[1]
        pan = {"event": DENIED, "flow_id": self._fid(), "app": "not-applicable", "user": ""}
        return [(wan[0], rec(SYD_MEMBER, GRID_MASTER, sport, dport, UDP, 0, wan[1], wan[2], 1, size, now, now)),
                (FIREWALL, rec(SYD_MEMBER, GRID_MASTER, sport, dport, UDP, 0, fw[1], 0, 1, size, now, now, **pan))]

    # ---- one export round
    def tick(self, interval: float, now: float) -> List[Tuple[str, Dict]]:
        out, self.pending = self.pending, []
        circuit, allowed = PHASES[self.phase]
        for t in list(self.tunnels.values()):
            if t.fresh:              # the firewall announces a new session right away
                pan = {"event": CREATED, "flow_id": t.flow_id, "app": "openvpn", "user": ""}
                fw = next(h for h in t.hops if h[0] == FIREWALL)
                out.append((FIREWALL, rec(t.member, GRID_MASTER, t.sport, VPN_PORT, UDP, 0, fw[1], fw[2], 1, 140,
                                          now, now, **pan)))
                t.fresh = False
            elif now - t.last >= self.active_timeout:
                out += self._export_tunnel(t, now, UPDATED)
        if circuit:
            p = min(1.0, interval / self.office_period)
            for ip, user in office_hosts():
                if self.rng.random() < p:
                    out += self._office_session(ip, user, PATHS[("office", circuit)], now)
            if not allowed:
                for port, every in ((VPN_PORT, VPN_RETRY), (KEYX_PORT, KEYX_RETRY)):
                    self.retry_clock[port] += interval
                    while self.retry_clock[port] >= every:
                        self.retry_clock[port] -= every
                        out += self._denied_attempt(port, now)
        return out


# ------------------------------------------------------------------ NetFlow v9

def _pad(b: bytes) -> bytes:
    return b + b"\0" * (-len(b) % 4)


def _s(text: str, n: int) -> bytes:
    return text.encode("ascii", "replace")[:n].ljust(n, b"\0")


class Template:
    """A v9 template: id, (field type, length) list, struct format and a packer for one record."""

    def __init__(self, tid: int, fields: List[Tuple[int, int]], fmt: str, packer):
        self.tid, self.fields, self.fmt, self.packer = tid, fields, fmt, packer
        self.size = struct.calcsize(fmt)
        assert self.size == sum(l for _, l in fields), (tid, self.size)

    def flowset(self) -> bytes:
        body = struct.pack("!HH", self.tid, len(self.fields)) + b"".join(struct.pack("!HH", t, l) for t, l in self.fields)
        return struct.pack("!HH", 0, 4 + len(body)) + body


# The routers: the same template as the other labs.
# src addr, dst addr, src port, dst port, protocol, tcp flags, tos, input snmp, output snmp,
# packets, bytes, first switched, last switched, src mask, dst mask
ROUTER_TEMPLATE = Template(256, [(8, 4), (12, 4), (7, 2), (11, 2), (4, 1), (6, 1), (5, 1), (10, 2), (14, 2),
                                 (2, 4), (1, 4), (22, 4), (21, 4), (9, 1), (13, 1)], "!4s4sHHBBBHHIIIIBB",
                           lambda r, up: (socket.inet_aton(r["src"]), socket.inet_aton(r["dst"]), r["sport"],
                                          r["dport"], r["proto"], r["flags"], r["tos"], r["in_if"], r["out_if"],
                                          r["pkts"], r["bytes"], up(r["first"]), up(r["last"]), 24, 24))

# The firewall: PAN-OS template 257, "IPv4 Enterprise", fields in the order Palo Alto's NetFlow
# Templates page lists them. Lengths are the documented defaults where Palo gives one (counters
# 4 bytes, interfaces 2 bytes, App-ID 32, User-ID 64) and the standard v9/IPFIX length otherwise
# (flowId is unsigned64, firewallEvent unsigned8, DIRECTION 1 byte, ICMP_TYPE 2 bytes).
PAN_ENTERPRISE_ID = 25461
PAN_TEMPLATE = Template(257, [
    (1, 4),       # IN_BYTES
    (2, 4),       # IN_PKTS
    (4, 1),       # PROTOCOL
    (5, 1),       # TOS
    (6, 1),       # TCP_FLAGS
    (7, 2),       # L4_SRC_PORT
    (8, 4),       # IPV4_SRC_ADDR
    (10, 2),      # INPUT_SNMP
    (11, 2),      # L4_DST_PORT
    (12, 4),      # IPV4_DST_ADDR
    (14, 2),      # OUTPUT_SNMP
    (21, 4),      # LAST_SWITCHED
    (22, 4),      # FIRST_SWITCHED
    (32, 2),      # ICMP_TYPE (type * 256 + code)
    (61, 1),      # DIRECTION (0 ingress)
    (148, 8),     # flowId = PAN-OS session ID
    (233, 1),     # firewallEvent
    (346, 4),     # privateEnterpriseNumber = 25461
    (56701, 32),  # App-ID
    (56702, 64),  # User-ID
], "!IIBBBH4sHH4sHIIHBQBI32s64s",
    lambda r, up: (r["bytes"], r["pkts"], r["proto"], r["tos"], r["flags"], r["sport"], socket.inet_aton(r["src"]),
                   r["in_if"], r["dport"], socket.inet_aton(r["dst"]), r["out_if"], up(r["last"]), up(r["first"]),
                   0, 0, r["flow_id"], r["event"], PAN_ENTERPRISE_ID, _s(r["app"], 32), _s(r["user"], 64)))

FIELD_NAMES = {1: "bytes", 2: "pkts", 4: "proto", 5: "tos", 6: "flags", 7: "sport", 8: "src", 10: "in_if",
               11: "dport", 12: "dst", 14: "out_if", 21: "last_ms", 22: "first_ms", 32: "icmp", 61: "direction",
               148: "flow_id", 233: "event", 346: "pen", 56701: "app", 56702: "user"}


def encode(t: Template, records: List[Dict], seq: int, boot: float, now: float, source_id: int,
           with_template: bool) -> bytes:
    up = lambda x: max(0, int((x - boot) * 1000)) & 0xFFFFFFFF
    sets = t.flowset() if with_template else b""
    if records:
        body = b"".join(struct.pack(t.fmt, *t.packer(r, up)) for r in records)
        data = _pad(struct.pack("!HH", t.tid, 0) + body)
        sets += struct.pack("!HH", t.tid, len(data)) + data[4:]
    count = len(records) + (1 if with_template else 0)
    return struct.pack("!HHIIII", 9, count, up(now), int(now), seq, source_id) + sets


def decode(pkt: bytes, templates: Dict) -> Tuple[Dict, List[Dict]]:
    """Decode one v9 packet. templates maps (source_id, template id) -> field list, filled as they arrive."""
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
                templates[(sid, tid)] = [struct.unpack("!HH", body[p + 4 + 4 * i:p + 8 + 4 * i]) for i in range(n)]
                p += 4 + 4 * n
        elif fid >= 256 and (sid, fid) in templates:
            fl = templates[(sid, fid)]
            size = sum(l for _, l in fl)
            p = 0
            while p + size <= len(body):
                vals, q = {"template": fid}, p
                for t, l in fl:
                    raw = body[q:q + l]
                    name = FIELD_NAMES.get(t, str(t))
                    if t in (8, 12):
                        vals[name] = socket.inet_ntoa(raw)
                    elif t in (56701, 56702):
                        vals[name] = raw.rstrip(b"\0").decode("ascii", "replace")
                    else:
                        vals[name] = int.from_bytes(raw, "big")
                    q += l
                out.append(vals)
                p += size
        off += ln
    return hdr, out


class Exporter:
    """One fake device: its own UDP socket bound to its sending IP.

    Routers resend their template every 30 seconds. The firewall follows PAN-OS's NetFlow profile:
    the template goes out every `template_packets` export packets or `template_minutes`, whichever
    comes first (PAN-OS defaults: 20 packets, 30 minutes), and always in the first packet.
    """

    def __init__(self, name: str, ip: str, collector: Tuple[str, int], source_id: int, template: Template,
                 bind: bool = True, max_per_packet: int = 30, template_seconds: float = 30.0,
                 template_packets: int = 0):
        self.name, self.ip, self.collector, self.source_id, self.t = name, ip, collector, source_id, template
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if bind:
            self.sock.bind((ip, 0))
        self.boot = time.time() - 86400 * 3
        self.max_per_packet, self.template_seconds, self.template_packets = max_per_packet, template_seconds, template_packets
        self.seq = 0                 # v9: counts export packets
        self.last_template, self.since_template = None, 0
        self.sent_flows = 0

    def _template_due(self, now: float) -> bool:
        if self.last_template is None or now - self.last_template >= self.template_seconds:
            return True
        return bool(self.template_packets) and self.since_template >= self.template_packets

    def send(self, records: List[Dict], now: float) -> None:
        chunks = [records[i:i + self.max_per_packet] for i in range(0, len(records), self.max_per_packet)] or [[]]
        for chunk in chunks:
            tmpl = self._template_due(now)
            if not chunk and not tmpl:
                continue
            self.sock.sendto(encode(self.t, chunk, self.seq, self.boot, now, self.source_id, tmpl), self.collector)
            self.seq += 1
            self.since_template = 0 if tmpl else self.since_template + 1
            if tmpl:
                self.last_template = now
            self.sent_flows += len(chunk)


def make_exporters(collector, bind=True, ips: Optional[Dict[str, str]] = None, pan_template_packets=20,
                   pan_template_minutes=30.0) -> Dict[str, Exporter]:
    out = {}
    for i, (name, (ip, _, _)) in enumerate(DEVICES.items()):
        ip = (ips or {}).get(name, ip)
        if name == FIREWALL:
            out[name] = Exporter(name, ip, collector, i + 1, PAN_TEMPLATE, bind, max_per_packet=9,
                                 template_seconds=pan_template_minutes * 60, template_packets=pan_template_packets)
        else:
            out[name] = Exporter(name, ip, collector, i + 1, ROUTER_TEMPLATE, bind)
    return out


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
        exporters = make_exporters(collector, bind=not args.no_bind, pan_template_packets=args.pan_template_packets,
                                   pan_template_minutes=args.pan_template_minutes)
    except OSError as e:
        print("Can't bind a device IP (%s). Run: sudo python3 %s aliases --apply\n"
              "or add --no-bind to send from this host's own IP (Kentik then sees one device)." % (e, sys.argv[0]),
              file=sys.stderr)
        return 1
    timeline = parse_timeline(args.timeline) if args.timeline else []
    first = timeline[0][0] if timeline else args.phase
    rng = random.Random(args.seed)
    sim = Sim(first, time.time(), rng, active_timeout=args.active_timeout)
    state = {"phase": first, "stop": False}

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
            elif cmd in ("quit", "exit", "q"):
                state["stop"] = True
                return
            elif cmd:
                print("commands: %s, status, quit" % ", ".join(PHASES))

    if not args.no_console and sys.stdin.isatty():
        threading.Thread(target=console, daemon=True).start()
    print("Sending NetFlow v9 to %s:%d from %s" % (args.collector, args.port, ", ".join(
        "%s %s%s" % (n, ip, " (PAN-OS template 257)" if n == FIREWALL else "") for n, (ip, _, _) in DEVICES.items())))
    if timeline:
        print("Timeline: " + ", ".join("%s %gm" % (p, s / 60) for p, s in timeline))
    print("Phase %s: %s" % (first, PHASE_HELP[first]))
    print("Type a phase name (%s), status, or quit." % ", ".join(PHASES))
    started = phase_start = last_report = time.time()
    try:
        while not state["stop"]:
            now = time.time()
            if timeline and now - phase_start >= timeline[0][1]:
                timeline.pop(0)
                phase_start = now
                if timeline:
                    state["phase"] = timeline[0][0]
                    print("-> phase %s: %s" % (state["phase"], PHASE_HELP[state["phase"]]))
            sim.set_phase(state["phase"], now)
            by_dev: Dict[str, List[Dict]] = {n: [] for n in DEVICES}
            for dev, r in sim.tick(args.interval, now):
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
    print("Stopped. Flows sent: %d" % sum(e.sent_flows for e in exporters.values()))
    return 0


def flag_str(f: int) -> str:
    return "".join(c for b, c in ((SYN, "S"), (ACK, "A"), (PSH, "P"), (FIN, "F")) if f & b) or "-"


def fmt_record(ip: str, r: Dict) -> str:
    line = "%-15s %15s:%-5d -> %15s:%-5d %-3s if %d->%d %5d pkts %8d bytes" % (
        ip, r["src"], r["sport"], r["dst"], r["dport"], {6: "tcp", 17: "udp"}.get(r["proto"], r["proto"]),
        r["in_if"], r["out_if"], r["pkts"], r["bytes"])
    if r.get("template") == 257 or "event" in r and "flow_id" in r and "app" in r:
        line += "  %-7s session %d app %s%s" % (EVENT_NAMES.get(r["event"], r["event"]), r["flow_id"], r["app"] or "-",
                                                (" user " + r["user"]) if r.get("user") else "")
    else:
        line += "  flags %s" % flag_str(r["flags"])
    return line


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
                if args.firewall_only and r.get("template") != 257:
                    continue
                n += 1
                print(fmt_record(ip, r))
    except KeyboardInterrupt:
        pass
    return 0


def simulate(phases: List[Tuple[str, float]], interval: float = 5.0, seed: int = 1,
             active_timeout: float = 60.0) -> List[Tuple[str, str, Dict]]:
    """Run the sim offline: [(phase, seconds)] -> [(phase, device, record)]."""
    rng = random.Random(seed)
    t = 100000.0
    sim = Sim(phases[0][0], t, rng, active_timeout=active_timeout)
    out = []
    for phase, secs in phases:
        for _ in range(int(secs / interval)):
            t += interval
            sim.set_phase(phase, t)
            out += [(phase, d, r) for d, r in sim.tick(interval, t)]
    return out


PREVIOUS = {"before": None, "maintenance": "before", "impact": "maintenance", "fix": "impact"}


def cmd_preview(args) -> int:
    lead = [(PREVIOUS[args.phase], 60)] if PREVIOUS[args.phase] else []
    recs = [(d, r) for ph, d, r in simulate(lead + [(args.phase, args.seconds)], seed=args.seed) if ph == args.phase]
    print("Phase %s, %d seconds: %s" % (args.phase, args.seconds, PHASE_HELP[args.phase]))
    for dev in DEVICES:
        mine = [r for d, r in recs if d == dev]
        grid = [r for r in mine if VPN_PORT in (r["sport"], r["dport"]) or KEYX_PORT in (r["sport"], r["dport"])]
        syd = [r for r in grid if SYD_MEMBER in (r["src"], r["dst"])]
        print("  %-14s %4d records, %3d grid (UDP 1194/2114), %3d to or from the Sydney member" % (
            dev, len(mine), len(grid), len(syd)))
    fw = [r for d, r in recs if d == FIREWALL]
    counts: Dict[Tuple, int] = {}
    for r in fw:
        k = (EVENT_NAMES[r["event"]], r["dport"] if r["dport"] in (VPN_PORT, KEYX_PORT, APP_PORT) else r["sport"], r["app"])
        counts[k] = counts.get(k, 0) + 1
    print("  firewall events (event, port, App-ID):")
    for (ev, port, app), n in sorted(counts.items()):
        print("    %-8s %5d  %-15s %4d" % (ev, port, app, n))
    return 0


def _alias_cmds(remove: bool) -> List[List[str]]:
    out = []
    for ip, _, _ in DEVICES.values():
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
DIM_NAMES = ("c_src_gridrole", "c_dst_gridrole")


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
    """The firewall goes in as "Palo Alto Networks Firewall" (subtype paloalto) so Kentik reads its
    firewallEvent, App-ID and User-ID into the Palo Alto dimensions; the routers are plain routers."""
    out = []
    for name, (ip, subtype, ifs) in DEVICES.items():
        d = {"deviceName": name, "deviceSubtype": subtype,
             "deviceDescription": DESCRIPTIONS.get(name) or "grid lab: " + ", ".join("%d %s" % kv for kv in ifs.items()),
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


ROLES = [("Sydney grid member", [SYD_MEMBER + "/32"]), ("London grid member", [LON_MEMBER + "/32"]),
         ("Grid Master (dc1)", [GRID_MASTER + "/32"]), ("Sydney office users", ["10.70.20.0/24"]),
         ("dc1 apps", ["10.20.30.0/24"])]


def dimension_plan() -> List[Dict]:
    """One dimension pair, "Grid lab role", with one populator per value."""
    out = []
    for name, direction, d in ((DIM_NAMES[0], "src", "Src"), (DIM_NAMES[1], "dst", "Dst")):
        out.append({"name": name, "display_name": "%s Grid lab role" % d, "type": "string",
                    "upserts": [{"value": v, "criteria": [{"direction": direction, "addr": a}]} for v, a in ROLES]})
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
        listed = api.call("GET", DEVICE_PATH + "?view=DEVICE_VIEW_BASIC").get("devices", [])
        have = {d["deviceName"]: d["id"] for d in listed if d.get("deviceName")}
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
        listed = api.call("GET", DEVICE_PATH + "?view=DEVICE_VIEW_BASIC").get("devices", [])
    except KentikError as e:
        print("Kentik API error: %s" % e, file=sys.stderr)
        return 1
    got = {d.get("deviceName"): d for d in listed}
    missing = [d["deviceName"] for d in devices if d["deviceName"] not in got]
    if missing:
        print("NOT in Kentik after the call: %s (rerun with -v to see the API's answer)" % ", ".join(missing), file=sys.stderr)
        return 1
    fw_type = got[FIREWALL].get("deviceSubtype")
    if fw_type and fw_type != "paloalto":
        print("Warning: %s is type %r, not paloalto. Set it to Palo Alto Networks Firewall in Settings > "
              "Network Devices, or the firewall event and App-ID dimensions stay empty." % (FIREWALL, fw_type),
              file=sys.stderr)
    print("Verified: all %d devices are in Kentik. Flow from 192.168.254.x lands on them once the lab runs." % len(devices))
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
        resp = api.call("GET", "/customdimensions")   # read back: trust the list, not the batch answer
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

    r = sub.add_parser("run", help="send flow from the three fake devices")
    r.add_argument("--collector", default="127.0.0.1", help="Kentik agent/kproxy address (default 127.0.0.1)")
    r.add_argument("--port", type=int, default=9995)
    r.add_argument("--phase", choices=list(PHASES), default="impact")
    r.add_argument("--timeline", help='phases with minutes, e.g. "before:10,maintenance:3,impact:20,fix:10" (ends on the last)')
    r.add_argument("--interval", type=float, default=5.0, help="seconds between export rounds")
    r.add_argument("--active-timeout", type=float, default=60.0,
                   help="seconds between update records for the grid tunnels (PAN-OS default is 5 minutes)")
    r.add_argument("--pan-template-packets", type=int, default=20, help="firewall template refresh, packets (PAN-OS default 20)")
    r.add_argument("--pan-template-minutes", type=float, default=30.0, help="firewall template refresh, minutes (PAN-OS default 30)")
    r.add_argument("--duration", type=float, default=0, help="stop after N seconds (0 = run until quit)")
    r.add_argument("--seed", type=int, default=None)
    r.add_argument("--no-bind", action="store_true", help="send from this host's IP instead of the device IPs")
    r.add_argument("--no-console", action="store_true")
    r.set_defaults(func=cmd_run)

    a = sub.add_parser("aliases", help="add the device IPs (192.168.254.x) to loopback")
    a.add_argument("--apply", action="store_true")
    a.add_argument("--remove", action="store_true")
    a.set_defaults(func=cmd_aliases)

    l = sub.add_parser("listen", help="decode and print NetFlow v9 arriving on a port, PAN-OS fields included")
    l.add_argument("--host", default="127.0.0.1")
    l.add_argument("--port", type=int, default=9995)
    l.add_argument("--count", type=int, default=0)
    l.add_argument("--firewall-only", action="store_true", help="only print the firewall's records")
    l.set_defaults(func=cmd_listen)

    v = sub.add_parser("preview", help="summarize one phase without sending anything")
    v.add_argument("--phase", choices=list(PHASES), default="impact")
    v.add_argument("--seconds", type=int, default=120)
    v.add_argument("--seed", type=int, default=1)
    v.set_defaults(func=cmd_preview)

    k = sub.add_parser("kentik", help="set up Kentik for the lab")
    ks = k.add_subparsers(dest="kcmd", required=True)
    for name, fn, hlp in (("onboard", cmd_onboard, "create or update the three devices (firewall as paloalto)"),
                          ("dimensions", cmd_dimensions, "create the Grid lab role dimensions")):
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
