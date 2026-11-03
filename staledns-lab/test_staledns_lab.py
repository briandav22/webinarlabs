import json, random, socket, threading, time, unittest
import staledns_lab as L


class TestLab(unittest.TestCase):
    def flows(self, phase, minutes=1):
        rng, out = random.Random(7), []
        for i in range(int(minutes * 60 / 5)):
            out += L.generate(phase, 5, 1000.0 + i * 5, rng)
        return out

    def test_hosts_match_slide(self):
        self.assertEqual([len(L.hosts(g)) for g in L.GROUPS], [22, 12, 4, 31, 9])
        for ip in ("10.41.2.17", "10.41.2.88", "10.52.0.31", "10.20.9.14", "10.60.4.22"):
            self.assertTrue(any(ip in L.hosts(g) for g in L.GROUPS), ip)

    def test_impact_is_slide_9(self):
        f = self.flows("impact", 3)
        to_old = {r["src"] for _, r in f if r["dst"] == L.OLD}
        to_new = {r["src"] for _, r in f if r["dst"] == L.NEW}
        self.assertEqual(len(to_old), 38)
        self.assertEqual(len(to_new), 40)
        self.assertFalse(any(r["src"] == L.OLD for _, r in f), "nothing answers from 10.20.4.15")
        self.assertTrue(all(r["flags"] == L.SYN and r["pkts"] in (3, 6) for _, r in f if r["dst"] == L.OLD))
        self.assertTrue(any(r["src"] == L.NEW for _, r in f), "10.60.1.20 replies")

    def test_fix_and_before(self):
        self.assertFalse(any(L.OLD in (r["src"], r["dst"]) for _, r in self.flows("fix")))
        self.assertFalse(any(L.NEW in (r["src"], r["dst"]) for _, r in self.flows("before")))

    def test_each_flow_exported_by_every_router_on_its_path(self):
        rng = random.Random(1)
        recs = L.conversation("office_east", "10.41.2.17", "old", False, 1000.0, rng)
        self.assertEqual([(d, r["in_if"], r["out_if"]) for d, r in recs], [("edge_office_east", 1, 2), ("core_dc1", 1, 3)])
        recs = L.conversation("aws_east", "10.60.4.22", "new", True, 1000.0, rng)
        self.assertEqual([(d, r["in_if"], r["out_if"]) for d, r in recs], [("hub_aws", 3, 2), ("hub_aws", 2, 3)])

    def test_encode_decode_roundtrip(self):
        recs = [r for _, r in self.flows("impact")][:40]
        pkt = L.encode(recs[:30], 0, 0.0, 1000.0, 3, True)
        tm = {}
        hdr, out = L.decode(pkt, tm)
        self.assertEqual(hdr["count"], 31)
        self.assertEqual(len(out), 30)
        for a, b in zip(recs, out):
            for k in ("src", "dst", "sport", "dport", "flags", "in_if", "out_if", "pkts", "bytes"):
                self.assertEqual(a[k], b[k], k)
        # data-only packet decodes with the remembered template
        _, out2 = L.decode(L.encode(recs[30:], 30, 0.0, 1001.0, 3, False), tm)
        self.assertEqual(len(out2), 10)
        self.assertEqual(len(pkt) % 4, 0)

    def test_udp_export(self):
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind(("127.0.0.1", 0)); rx.settimeout(2)
        ex = L.Exporter("core_dc1", "127.0.0.1", rx.getsockname(), 3, bind=False)
        recs = [r for d, r in self.flows("impact") if d == "core_dc1"]
        ex.send(recs, time.time())
        tm, got = {}, 0
        while got < len(recs):
            _, out = L.decode(rx.recv(65535), tm)
            got += len(out)
        self.assertEqual(got, len(recs))

    def test_dimension_plan(self):
        plan = L.dimension_plan()
        self.assertEqual([d["name"] for d in plan], ["c_src_outage", "c_dst_outage"])
        for d in plan:
            vals = [u["value"] for u in d["upserts"]]
            self.assertEqual(len(vals), len(set(vals)))
            self.assertEqual(len(vals), 7)
            self.assertIn({"direction": d["name"][2:5], "addr": ["10.20.4.15/32"]}, [u["criteria"][0] for u in d["upserts"]])

    def test_onboard_payload(self):
        devs = L.build_devices(1234)
        self.assertEqual({d["sendingIps"][0] for d in devs}, {ip for ip, _ in L.DEVICES.values()})
        self.assertTrue(all(d["deviceSampleRate"] == 1 and d["planId"] == 1234 for d in devs))


if __name__ == "__main__":
    unittest.main()


class TestRealSend(unittest.TestCase):
    def test_each_device_sends_from_its_own_ip(self):
        """Bind each exporter to its own loopback IP (127.0.0.x needs no alias on Linux) and check the senders."""
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind(("127.0.0.1", 0)); rx.settimeout(2)
        ips = {n: "127.0.0.%d" % (11 + i) for i, n in enumerate(L.DEVICES)}
        exs = {n: L.Exporter(n, ip, rx.getsockname(), i + 1, bind=True) for i, (n, ip) in enumerate(ips.items())}
        by_dev = {n: [] for n in L.DEVICES}
        for d, r in TestLab.flows(self, "impact"):
            by_dev[d].append(r)
        for n, recs in by_dev.items():
            exs[n].send(recs, time.time())
        tm, seen = {}, {}
        try:
            while True:
                pkt, (ip, _) = rx.recvfrom(65535)
                _, out = L.decode(pkt, tm)
                seen.setdefault(ip, []).extend(out)
        except socket.timeout:
            pass
        self.assertEqual(set(seen), set(ips.values()))
        core = seen[ips["core_dc1"]]
        self.assertTrue(any(r["dst"] == L.OLD and r["out_if"] == 3 for r in core))
        self.assertFalse(any(r["src"] == L.OLD for recs in seen.values() for r in recs))
        for e in exs.values():
            e.sock.close()
        rx.close()


class TestDns(unittest.TestCase):
    """Real UDP and TCP queries to the fake servers, on 127.0.0.x and a high port."""

    @classmethod
    def setUpClass(cls):
        cls.state = {"phase": "impact"}
        cls.port = 15353
        cls.servers = L.start_dns(lambda: cls.state["phase"], cls.port, ["127.0.0.153", "127.0.0.154"], quiet=True)
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        for s in cls.servers:
            s.close()

    def ask(self, ip, name, qtype=1, tcp=False, edns=False):
        q = struct_query(name, qtype, edns)
        if tcp:
            s = socket.create_connection((ip, self.port), timeout=2)
            s.sendall(len(q).to_bytes(2, "big") + q)
            n = int.from_bytes(s.recv(2), "big")
            data = b""
            while len(data) < n:
                data += s.recv(n - len(data))
            s.close()
            return data
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(q, (ip, self.port))
        data = s.recv(4096)
        s.close()
        return data

    def a(self, data):
        import dns.message
        m = dns.message.from_wire(data)
        return m.rcode(), [(rr.address, rs.ttl) for rs in m.answer for rr in rs], m

    def test_phases(self):
        expect = {"before": ("10.20.4.15", "10.20.4.15"), "impact": ("10.20.4.15", "10.60.1.20"),
                  "change": ("10.20.4.15", "10.60.1.20"), "fix": ("10.60.1.20", "10.60.1.20")}
        for phase, (onprem, cloud) in expect.items():
            self.state["phase"] = phase
            self.assertEqual(self.a(self.ask("127.0.0.153", "orders-api.corp.example"))[1][0][0], onprem, phase)
            self.assertEqual(self.a(self.ask("127.0.0.154", "orders-api.corp.example", tcp=True))[1][0][0], cloud, phase)
        self.state["phase"] = "impact"
        self.assertEqual(self.a(self.ask("127.0.0.153", "orders-api.corp.example"))[1][0][1], 86400)

    def test_other_answers(self):
        import dns.rcode
        rc, ans, _ = self.a(self.ask("127.0.0.153", "payments-db.corp.example"))
        self.assertEqual(ans, [("10.30.8.40", 3600)])
        rc, ans, m = self.a(self.ask("127.0.0.153", "nope.corp.example"))
        self.assertEqual((rc, ans, len(m.authority)), (dns.rcode.NXDOMAIN, [], 1))
        rc, ans, _ = self.a(self.ask("127.0.0.153", "example.com"))
        self.assertEqual(rc, dns.rcode.REFUSED)
        import dns.message
        m = dns.message.from_wire(self.ask("127.0.0.154", "orders-api.corp.example", qtype=28))
        self.assertEqual((m.rcode(), len(m.answer)), (0, 0))   # AAAA: no data, not an error

    def test_edns_and_case(self):
        _, ans, m = self.a(self.ask("127.0.0.154", "ORDERS-API.corp.example.", edns=True))
        self.assertEqual(ans[0][0], "10.60.1.20")
        self.assertEqual(m.edns, 0)


def struct_query(name, qtype=1, edns=False):
    import dns.message
    q = dns.message.make_query(name, qtype, use_edns=0 if edns else False)
    return q.to_wire()
