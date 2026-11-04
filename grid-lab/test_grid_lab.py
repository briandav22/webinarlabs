import ipaddress, socket, struct, time, unittest
import grid_lab as L

# The eight template flowsets from a capture of a real PAN-OS firewall's NetFlow export (field IDs and
# lengths only, no addresses).
REAL_TEMPLATE_FLOWSETS = (
    "0000004c0100001100010008000200040004000100050001000600010007000200080004000a0004000b0002000c0004"
    "000e0004001500040016000400200002003d00010094000800e900010000005c01040015000100080002000400040001"
    "00050001000600010007000200080004000a0004000b0002000c0004000e0004001500040016000400200002003d0001"
    "0094000800e9000100e1000400e2000400e3000200e400020000004c0102001100010008000200040004000100050001"
    "0006000100070002001b0010000a0004000b0002001c0010000e0004001500040016000400200002003d000100940008"
    "00e900010000005c01060015000100080002000400040001000500010006000100070002001b0010000a0004000b0002"
    "001c0010000e0004001500040016000400200002003d00010094000800e9000101190010011a001000e3000200e40002"
    "000000580101001400010008000200040004000100050001000600010007000200080004000a0004000b0002000c0004"
    "000e0004001500040016000400200002003d00010094000800e90001015a0004dd7d0020dd7e00400000006801050018"
    "00010008000200040004000100050001000600010007000200080004000a0004000b0002000c0004000e000400150004"
    "0016000400200002003d00010094000800e9000100e1000400e2000400e3000200e40002015a0004dd7d0020dd7e0040"
    "0000005801030014000100080002000400040001000500010006000100070002001b0010000a0004000b0002001c0010"
    "000e0004001500040016000400200002003d00010094000800e90001015a0004dd7d0020dd7e00400000006801070018"
    "000100080002000400040001000500010006000100070002001b0010000a0004000b0002001c0010000e000400150004"
    "0016000400200002003d00010094000800e9000101190010011a001000e3000200e40002015a0004dd7d0020dd7e0040"
)


def run(*phases, seed=7):
    """[(phase, seconds)] -> [(phase, device, record)]"""
    return L.simulate(list(phases), seed=seed)


def grid(r):
    return L.VPN_PORT in (r["sport"], r["dport"]) or L.KEYX_PORT in (r["sport"], r["dport"])


def syd(r):
    return L.SYD_MEMBER in (r["src"], r["dst"])


class TestScenario(unittest.TestCase):
    def test_before(self):
        f = [(d, r) for _, d, r in run(("before", 180))]
        fw = [r for d, r in f if d == L.FIREWALL]
        self.assertFalse(any(r["event"] == L.DENIED for r in fw))
        tun = [r for r in fw if grid(r)]
        self.assertTrue(tun and all(r["event"] == L.UPDATED and r["app"] == "openvpn" for r in tun),
                        "tunnels already up: only update events")
        self.assertEqual({r["in_if"] for r in fw if r["src"] == L.SYD_MEMBER}, {3}, "Sydney arrives on the MPLS port")
        self.assertTrue(any(d == "grid_dc_core" and r["src"] == L.SYD_MEMBER and r["dst"] == L.GRID_MASTER for d, r in f))

    def test_maintenance_deletes_the_tunnel_and_sydney_goes_quiet(self):
        f = run(("before", 60), ("maintenance", 120))
        m = [(d, r) for ph, d, r in f if ph == "maintenance"]
        dele = [r for d, r in m if d == L.FIREWALL and r["event"] == L.DELETED]
        self.assertEqual({(r["src"], r["dst"]) for r in dele}, {(L.SYD_MEMBER, L.GRID_MASTER), (L.GRID_MASTER, L.SYD_MEMBER)})
        self.assertTrue(all(r["dport"] == L.VPN_PORT or r["sport"] == L.VPN_PORT for r in dele))
        later = [(d, r) for d, r in m[len(m) // 2:]]
        self.assertFalse(any(syd(r) for d, r in later), "nothing to or from Sydney once the circuit is down")
        self.assertFalse(any(d == "grid_syd_wan" for d, r in later))
        self.assertTrue(any(r["src"] == L.LON_MEMBER for d, r in later), "London keeps its tunnel")

    def test_impact_denied_at_the_firewall(self):
        f = [(d, r) for ph, d, r in run(("maintenance", 30), ("impact", 180)) if ph == "impact"]
        fw_syd = [r for d, r in f if d == L.FIREWALL and r["src"] == L.SYD_MEMBER]
        self.assertTrue(fw_syd)
        self.assertTrue(all(r["event"] == L.DENIED and r["app"] == "not-applicable" for r in fw_syd))
        self.assertEqual({r["dport"] for r in fw_syd}, {1194, 2114})
        self.assertEqual({(r["in_if"], r["out_if"]) for r in fw_syd}, {(4, 0)}, "arrives on ethernet1/4, goes nowhere")
        n = {p: sum(1 for r in fw_syd if r["dport"] == p) for p in (1194, 2114)}
        self.assertEqual(n, {1194: 19, 2114: 7}, "one try right away, then every 10 s on 1194 and every 30 s on 2114")
        self.assertFalse(any(syd(r) for d, r in f if d == "grid_dc_core"), "dc1 never sees the member")
        self.assertFalse(any(r["src"] == L.GRID_MASTER and r["dst"] == L.SYD_MEMBER for _, r in f), "no replies")
        wan = [r for d, r in f if d == "grid_syd_wan" and r["src"] == L.SYD_MEMBER]
        self.assertTrue(wan and all((r["in_if"], r["out_if"]) == (1, 3) for r in wan), "the WAN router forwards it")
        office = [r for d, r in f if d == L.FIREWALL and r["dport"] == L.APP_PORT]
        self.assertTrue(office and all(r["event"] in (L.CREATED, L.DELETED) and r["in_if"] == 4 for r in office),
                        "office users allowed on the new zone")
        self.assertTrue(all(r["user"].startswith("corp\\") for r in office))
        self.assertTrue(any(r["src"] == L.LON_MEMBER and r["event"] == L.UPDATED for d, r in f if d == L.FIREWALL))

    def test_fix(self):
        f = [(d, r) for ph, d, r in run(("impact", 30), ("fix", 300)) if ph == "fix"]
        fw = [r for d, r in f if d == L.FIREWALL and syd(r)]
        self.assertFalse(any(r["event"] == L.DENIED for r in fw))
        ev = [(r["event"], r["dport"] if r["src"] == L.SYD_MEMBER else r["sport"]) for r in fw]
        self.assertEqual(ev[:2], [(L.CREATED, 2114), (L.DELETED, 2114)], "key exchange first")
        self.assertIn((L.CREATED, 1194), ev)
        self.assertTrue(ev.index((L.CREATED, 1194)) > 1)
        self.assertIn((L.UPDATED, 1194), ev)
        self.assertTrue(any(d == "grid_dc_core" and r["dst"] == L.SYD_MEMBER for d, r in f))
        down = [r["bytes"] for r in fw if r["src"] == L.GRID_MASTER and r["event"] == L.UPDATED]
        self.assertGreater(down[0], 5 * down[-1], "catch-up replication burst, then back to normal")

    def test_flow_ids(self):
        f = [r for _, d, r in run(("before", 60), ("impact", 120)) if d == L.FIREWALL]
        denied = [r["flow_id"] for r in f if r["event"] == L.DENIED]
        self.assertEqual(len(denied), len(set(denied)), "each denied attempt is its own session")
        tun = {r["flow_id"] for r in f if r["src"] == L.LON_MEMBER or r["dst"] == L.LON_MEMBER}
        self.assertEqual(len(tun), 1, "both directions of a session share its flowId")

    def test_pan_template_layout(self):
        t = L.PAN_TEMPLATE
        self.assertEqual(t.tid, 257)
        ids = [i for i, _ in t.fields]
        self.assertEqual(ids, [1, 2, 4, 5, 6, 7, 8, 10, 11, 12, 14, 21, 22, 32, 61, 148, 233, 346, 56701, 56702])
        lens = dict(t.fields)
        self.assertEqual((lens[1], lens[10], lens[14]), (8, 4, 4), "as a real firewall sends them")
        self.assertEqual((lens[56701], lens[56702]), (32, 64))
        self.assertEqual(t.size, 155)

    def test_template_packet_matches_real_firewall(self):
        """The eight template flowsets, byte for byte as a PAN-OS firewall sent them in a capture."""
        pkt = L.pan_template_packet(7, 0.0, 1000.0)
        self.assertEqual(len(pkt), 740)
        self.assertEqual(struct.unpack("!HH", pkt[:4]), (9, 8))
        self.assertEqual(struct.unpack("!I", pkt[16:20])[0], 1, "source ID 1")
        self.assertEqual(pkt[20:].hex(), REAL_TEMPLATE_FLOWSETS)
        hdr, _ = L.decode(pkt, {})
        self.assertEqual([ln for _, ln in hdr["flowsets"]], [76, 92, 76, 92, 88, 104, 88, 104])

    def test_data_packets_one_flowset_per_record(self):
        recs = [r for _, d, r in run(("maintenance", 30), ("impact", 120)) if d == L.FIREWALL]
        pkts = L.pan_data_packets(recs, 5, 0.0, 1000.0)
        tm = {}
        L.decode(L.pan_template_packet(4, 0.0, 1000.0), tm)
        out = []
        for i, pkt in enumerate(pkts):
            self.assertLessEqual(len(pkt), 1400)
            hdr, got = L.decode(pkt, tm)
            self.assertEqual(hdr["seq"], 5 + i)
            self.assertEqual(hdr["count"], len(got))
            self.assertTrue(all(fs == (257, 159) for fs in hdr["flowsets"]), "one 159-byte flowset per record, no padding")
            self.assertEqual(len(pkt), 20 + 159 * len(got))
            out += got
        self.assertEqual(len(out), len(recs))
        for a, b in zip(recs, out):
            for k in ("src", "dst", "sport", "dport", "proto", "in_if", "out_if", "pkts", "bytes", "event",
                      "flow_id", "app", "user"):
                self.assertEqual(a[k], b[k], k)
            self.assertEqual(b["pen"], 25461)

    def test_independent_decoder(self):
        """The netflow package (bitkeks/python-netflow-v9-v5-ipfix) reads the same packets."""
        try:
            import netflow
        except ImportError:
            self.skipTest("pip install netflow")
        recs = [r for _, d, r in run(("impact", 60)) if d == L.FIREWALL][:8]
        tm = {"netflow": {}, "ipfix": {}}
        netflow.parse_packet(L.pan_template_packet(1, 0.0, 1000.0), tm)
        p = netflow.parse_packet(L.pan_data_packets(recs, 2, 0.0, 1000.0)[0], tm)
        self.assertEqual(p.header.version, 9)
        flows = [f.data for f in p.flows]
        self.assertEqual(len(flows), 8)
        for a, b in zip(recs, flows):
            self.assertEqual(str(ipaddress.ip_address(b["IPV4_SRC_ADDR"])), a["src"])
            self.assertEqual(b["L4_DST_PORT"], a["dport"])
            self.assertEqual(b["INPUT_SNMP"], a["in_if"])
            self.assertEqual(b["OUTPUT_SNMP"], a["out_if"])
            self.assertEqual(b["IN_BYTES"], a["bytes"])
            self.assertEqual(b["NF_F_FW_EVENT"], a["event"])

    def test_each_device_sends_from_its_own_ip(self):
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind(("127.0.0.1", 0)); rx.settimeout(2)
        ips = {n: "127.0.0.%d" % (61 + i) for i, n in enumerate(L.DEVICES)}
        exs = L.make_exporters(rx.getsockname(), ips=ips)
        by = {n: [] for n in L.DEVICES}
        for _, d, r in run(("impact", 60)):
            by[d].append(r)
        for n, recs in by.items():
            exs[n].send(recs, time.time())
        tm, seen = {}, {}
        try:
            while True:
                pkt, (ip, _) = rx.recvfrom(65535)
                seen.setdefault(ip, []).extend(L.decode(pkt, tm)[1])
        except socket.timeout:
            pass
        self.assertEqual(set(seen), set(ips.values()))
        for n, ip in ips.items():
            self.assertEqual(len(seen[ip]), len(by[n]), n)
            want = 257 if n == L.FIREWALL else 256
            self.assertTrue(all(r["template"] == want for r in seen[ip]), n)
        self.assertTrue(any(r["event"] == L.DENIED for r in seen[ips[L.FIREWALL]]))
        self.assertEqual(exs[L.FIREWALL].sent_flows, len(by[L.FIREWALL]))
        for e in exs.values():
            e.sock.close()
        rx.close()

    def test_pan_template_refresh(self):
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind(("127.0.0.1", 0)); rx.settimeout(1)
        exs = L.make_exporters(rx.getsockname(), ips={n: "127.0.0.1" for n in L.DEVICES})
        ex = exs[L.FIREWALL]
        recs = [r for _, d, r in run(("impact", 300)) if d == L.FIREWALL][:8 * 45]
        ex.send(recs, time.time())
        kinds, seqs = [], []
        try:
            while True:
                pkt, _ = rx.recvfrom(65535)
                kinds.append("T" if struct.unpack("!H", pkt[20:22])[0] == 0 else "D")
                seqs.append(struct.unpack("!I", pkt[12:16])[0])
        except socket.timeout:
            pass
        self.assertEqual(kinds.count("D"), 45)
        self.assertEqual([i for i, k in enumerate(kinds) if k == "T"], [0, 21, 42],
                         "template packet first, then after every 20 data packets")
        self.assertEqual(seqs, list(range(len(kinds))), "v9 sequence counts every export packet")
        for e in exs.values():
            e.sock.close()
        rx.close()

    def test_onboard_payload(self):
        devs = {d["deviceName"]: d for d in L.build_devices(99)}
        self.assertEqual(devs[L.FIREWALL]["deviceSubtype"], "paloalto")
        self.assertEqual({d["deviceSubtype"] for n, d in devs.items() if n != L.FIREWALL}, {"router"})
        self.assertEqual({d["sendingIps"][0] for d in devs.values()},
                         {"192.168.254.11", "192.168.254.21", "192.168.254.31"})
        self.assertTrue(all(d["deviceSampleRate"] == 1 for d in devs.values()))

    def test_dimensions(self):
        plan = L.dimension_plan()
        self.assertEqual([d["name"] for d in plan], ["c_src_gridrole", "c_dst_gridrole"])
        nets = {u["value"]: ipaddress.ip_network(u["criteria"][0]["addr"][0]) for u in plan[0]["upserts"]}
        self.assertIn(ipaddress.ip_address(L.SYD_MEMBER), nets["Sydney grid member"])
        self.assertTrue(all(ipaddress.ip_address(ip) in nets["Sydney office users"] for ip, _ in L.office_hosts()))


class TestKentikLimits(unittest.TestCase):
    def test_device_descriptions_fit(self):
        """Kentik rejects descriptions over 128 characters with HTTP 400."""
        for d in L.build_devices(99):
            self.assertLessEqual(len(d["deviceDescription"]), 128, d["deviceName"])
        self.assertEqual(L.check_devices(L.build_devices(99)), [])
        self.assertTrue(L.check_devices([dict(L.build_devices(99)[0], deviceDescription="x" * 129)]))


if __name__ == "__main__":
    unittest.main()
