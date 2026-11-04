import ipaddress, random, socket, time, unittest
import ipam_lab as L


def flows(phase, minutes=2, seed=7):
    rng, out = random.Random(seed), []
    for i in range(int(minutes * 60 / 5)):
        out += L.generate(phase, 5, 1000.0 + i * 5, rng)
    return out


class TestScenario(unittest.TestCase):
    def test_hosts(self):
        self.assertEqual([len(L.hosts(g)) for g in L.GROUPS], [24, 10, 6, 6])
        self.assertEqual(L.hosts("analytics"), ["10.30.8.%d" % i for i in range(101, 107)])
        self.assertIn("10.60.4.22", L.hosts("orders"))

    def test_overlap_facts(self):
        p22, p24 = ipaddress.ip_network("10.30.8.0/22"), ipaddress.ip_network("10.30.8.0/24")
        self.assertTrue(p24.subnet_of(p22))
        self.assertIn(ipaddress.ip_address(L.PAYMENTS), p24)          # breaks
        self.assertNotIn(ipaddress.ip_address(L.REPORTS), p24)        # keeps working
        self.assertIn(ipaddress.ip_address(L.REPORTS), p22)

    def test_impact(self):
        f = flows("impact")
        hub_pay = {r["out_if"] for d, r in f if d == "ipam_transit_hub" and r["dst"] == L.PAYMENTS}
        self.assertEqual(hub_pay, {3}, "hub sends payments-db traffic to the Azure attachment")
        az = [r for d, r in f if d == "ipam_azure_analytics" and r["dst"] == L.PAYMENTS]
        self.assertTrue(az and all(r["flags"] == L.SYN for r in az))
        orders = set(L.hosts("orders"))
        self.assertFalse(any(r["src"] == L.PAYMENTS and r["dst"] in orders for _, r in f), "no replies to orders apps")
        self.assertTrue(any(r["src"] == L.PAYMENTS and r["dst"] in L.hosts("dc1apps") for _, r in f), "dc1 apps fine")
        self.assertTrue(any(r["src"] == L.REPORTS and r["dst"] in orders and r["flags"] == L.FULL for _, r in f), "reports-db fine")

    def test_overlap_replies_go_astray(self):
        f = flows("change")
        ana = set(L.hosts("analytics"))
        back = [(d, r) for d, r in f if r["src"] == L.REPORTS and r["dst"] in ana]
        self.assertTrue(back)
        self.assertTrue(all(d == "ipam_dc1_core" and (r["in_if"], r["out_if"]) == (2, 2) and r["flags"] == L.SYN | L.ACK
                            for d, r in back))
        self.assertTrue(all(r["out_if"] == 1 for d, r in f if d == "ipam_transit_hub" and r["dst"] == L.PAYMENTS))

    def test_before_and_fix(self):
        for ph in ("before", "fix"):
            f = flows(ph)
            self.assertFalse(any(d == "ipam_azure_analytics" and r["dst"] == L.PAYMENTS for d, r in f), ph)
            self.assertFalse(any(r["flags"] in (L.SYN, L.SYN | L.ACK) for _, r in f), ph + ": everything completes")
        self.assertFalse(any(r["src"].startswith("10.30.8.10") for _, r in flows("fix")))

    def test_encode_decode(self):
        recs = [r for _, r in flows("impact")][:30]
        hdr, out = L.decode(L.encode(recs, 0, 0.0, 1000.0, 2, True), {})
        self.assertEqual(len(out), 30)
        for a, b in zip(recs, out):
            for k in ("src", "dst", "sport", "dport", "flags", "in_if", "out_if", "pkts", "bytes"):
                self.assertEqual(a[k], b[k])

    def test_each_device_sends_from_its_own_ip(self):
        rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        rx.bind(("127.0.0.1", 0)); rx.settimeout(2)
        ips = {n: "127.0.0.%d" % (21 + i) for i, n in enumerate(L.DEVICES)}
        exs = {n: L.Exporter(n, ip, rx.getsockname(), i + 1) for i, (n, ip) in enumerate(ips.items())}
        by = {n: [] for n in L.DEVICES}
        for d, r in flows("impact", 1):
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
        self.assertEqual(sum(map(len, seen.values())), sum(map(len, by.values())))
        for e in exs.values():
            e.sock.close()
        rx.close()

    def test_dimensions(self):
        plan = L.dimension_plan()
        self.assertEqual([d["name"] for d in plan], ["c_src_ipamlab", "c_dst_ipamlab", "c_src_ipamowner", "c_dst_ipamowner"])
        lab = plan[0]["upserts"]
        nets = {u["value"]: ipaddress.ip_network(u["criteria"][0]["addr"][0]) for u in lab}
        self.assertNotIn(ipaddress.ip_address(L.PAYMENTS), nets["analytics VNet (overlapping)"])
        self.assertTrue(all(ipaddress.ip_address(h) in nets["analytics VNet (overlapping)"] for h in L.hosts("analytics")))
        owner = {u["value"]: u["criteria"][0]["addr"] for u in plan[2]["upserts"]}
        self.assertEqual(owner["payments (dc1)"], ["10.30.8.0/22"])

    def test_onboard_payload(self):
        devs = L.build_devices(99)
        self.assertEqual({d["sendingIps"][0] for d in devs}, {"192.168.253.21", "192.168.253.31", "192.168.253.41"})
        self.assertTrue(all(d["deviceSampleRate"] == 1 and d["deviceName"].startswith("ipam_") for d in devs))


class TestKentikLimits(unittest.TestCase):
    def test_device_descriptions_fit(self):
        """Kentik rejects descriptions over 128 characters with HTTP 400."""
        for d in L.build_devices(99):
            self.assertLessEqual(len(d["deviceDescription"]), 128, d["deviceName"])
        self.assertEqual(L.check_devices(L.build_devices(99)), [])
        self.assertTrue(L.check_devices([dict(L.build_devices(99)[0], deviceDescription="x" * 129)]))


if __name__ == "__main__":
    unittest.main()
