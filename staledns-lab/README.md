# Stale DNS lab

NetFlow v9 for deck slide 9, "Could you see that in flow data?", sent into your Kentik lab so you can build the same views live in the portal.

One Python file, standard library only. It follows the vxlanlab conventions: loopback aliases, one sending IP per fake router, a console for switching phases, and `kentik onboard` / `kentik dimensions` with the same API calls. It uses 192.168.252.x for its routers, so it can run next to vxlanlab's 192.168.250.x and 192.168.251.x.

## What it sends

| Router | Sending IP | Interfaces (ifIndex) |
|---|---|---|
| `edge_office_east` | 192.168.252.11 | 1 LAN 10.41.2.0/24 · 2 WAN to dc1 |
| `edge_office_west` | 192.168.252.12 | 1 LAN 10.52.0.0/24 · 2 WAN to dc1 |
| `core_dc1` | 192.168.252.21 | 1 WAN office east · 2 WAN office west · 3 server VLAN (old orders-api) · 4 batch VLAN · 5 interconnect |
| `hub_aws` | 192.168.252.31 | 1 interconnect · 2 orders VPC us-east-1 · 3 apps VPC us-east-1 · 4 apps VPC us-west-2 |

The hosts match the slide: 22 in office east (10.41.2.x), 12 in office west (10.52.0.x), 4 batch hosts in dc1 (10.20.9.x), 31 AWS us-east-1 apps (10.60.4.x) and 9 AWS us-west-2 apps (10.61.4.x). The slide's sample addresses are among them: 10.41.2.17, 10.41.2.88, 10.52.0.31, 10.20.9.14 and 10.60.4.22. The old orders-api is 10.20.4.15 and the new one is 10.60.1.20, both on TCP 443.

Every router a flow passes through exports it, with input and output interface, sample rate 1. In a real network the AWS side would come from VPC flow logs; here `hub_aws` stands in as a router.

| Phase | What the network does |
|---|---|
| `before` | Everyone talks to 10.20.4.15 in dc1 and gets replies |
| `change` | Cloud apps have moved to 10.60.1.20. A few overnight office connections to 10.20.4.15 fail |
| `impact` | **Slide 9.** 38 office and batch hosts send SYN-only flows to 10.20.4.15 (3 packets, 180 bytes; batch 6 packets, 360 bytes) and nothing comes back. 40 cloud hosts talk to 10.60.1.20 normally |
| `fix` | Everyone talks to 10.60.1.20. 10.20.4.15 gets nothing |

## Fake DNS for Kentik synthetic tests

`--dns` also starts two DNS servers. They answer for `corp.example`, and their answer for `orders-api.corp.example` follows the phase, like the deck's DNS test:

| Server | Listens on | `before` | `change` / `impact` | `fix` |
|---|---|---|---|---|
| On-prem DNS | 192.168.252.53:53 | 10.20.4.15, TTL 24 h | **10.20.4.15**, TTL 24 h (stale) | 10.60.1.20, TTL 5 min |
| Cloud DNS (private zone) | 192.168.252.54:53 | 10.20.4.15, TTL 5 min | 10.60.1.20, TTL 5 min | 10.60.1.20, TTL 5 min |

Other answers:
- **`payments-db.corp.example`** always answers 10.30.8.40 from both servers, as a healthy control.
- **Other names in `corp.example`** get NXDOMAIN.
- **Names outside `corp.example`** are refused.

Both servers answer over UDP and TCP, and every query is printed as it arrives (`--quiet-dns` turns that off).

Port 53 needs root, so start the lab with `sudo`. The `run` and `dns` commands don't need your Kentik env vars, so plain `sudo` is fine.

```bash
sudo python3 staledns_lab.py aliases --apply      # now also adds .53 and .54
sudo python3 staledns_lab.py run --collector 127.0.0.1 --port 9995 --dns \
     --timeline "before:10,change:10,impact:20,fix:10"
sudo python3 staledns_lab.py dns --phase impact   # DNS only, no flow
```

### Tests to create in Kentik

Run a private synthetic agent on the same droplet, so it can reach 192.168.252.53 and .54 over the loopback aliases. In the Test Control Center, add these tests. The test names are from Kentik's synthetics docs; check field names in your portal:

1. **DNS Server Grid.**
   - Hostname: `orders-api.corp.example`. Servers: `192.168.252.53` and `192.168.252.54`. Record type: A. Agent: your private agent.
   - It shows the two servers giving different answers during `change` and `impact`, and agreeing again after `fix`.
2. **DNS Server Monitor against 192.168.252.53**, with **Allowed DNS Results** set to `10.60.1.20`.
   - It goes critical as soon as the timeline reaches `change`, before any users fail in `impact`. That's the deck's "would have alerted at 20:26, inside the change window".
3. **Optional control: DNS Server Monitor for `payments-db.corp.example`.**
   - It stays healthy throughout, so you can show the test itself isn't broken.

Two setups need extra steps:
- **Agent on a different machine:** start the servers on addresses it can reach, for example `--dns-ips 10.0.0.5,10.0.0.6`, which must be two IPs on the droplet. Open UDP and TCP 53 in the firewall.
- **Something already on port 53:** if a process such as dnsmasq holds `0.0.0.0:53`, the bind fails with a clear message. systemd-resolved only holds 127.0.0.53, so it doesn't get in the way.

## Run it

On the lab droplet, next to your Kentik agent (default `127.0.0.1:9995`):

```bash
# 1. Device IPs on loopback (re-run after a reboot)
sudo python3 staledns_lab.py aliases --apply

# 2. Kentik: the four devices, then the custom dimensions
source ~/.kentik.env          # KENTIK_EMAIL, KENTIK_API_TOKEN, KENTIK_PLAN_ID
python3 staledns_lab.py kentik onboard --dry-run      # look first
python3 staledns_lab.py kentik onboard
python3 staledns_lab.py kentik dimensions --dry-run
python3 staledns_lab.py kentik dimensions

# 3. Send flow
python3 staledns_lab.py run --collector 127.0.0.1 --port 9995 --phase impact
```

While it runs, type `before`, `change`, `impact` or `fix` to switch phases, `status` for counters, `quit` to stop.

To show the change happening on a time series, run a timeline instead. It stays on the last phase when it ends:

```bash
python3 staledns_lab.py run --collector 127.0.0.1 --port 9995 --timeline "before:15,impact:30,fix:15"
```

Useful checks:

```bash
python3 staledns_lab.py preview --phase impact     # what a phase sends over one minute, no network
python3 staledns_lab.py listen --port 9996 &       # decode what's on the wire...
python3 staledns_lab.py run --port 9996 --duration 20 --no-console
python3 -m unittest -v test_staledns_lab           # 13 tests: real sends from four IPs, real DNS queries (needs: pip install dnspython)
```

Notes:
- **Onboarding:** `onboard` creates the devices if they don't exist and updates them if they do, then reads the device list back to confirm.
- **Custom dimensions:** `dimensions` creates `c_src_outage` and `c_dst_outage`, shown as "Src Outage group" and "Dst Outage group". Each one gets one value per group, plus the two orders-api addresses. It uses `replace_all`, so any populators added to those two dimensions by hand are removed.
- **sudo:** sudo drops your environment variables. Use `sudo -E` if you run the Kentik commands under sudo.
- **No SNMP:** the routers don't answer SNMP, so Kentik shows interfaces by number. The interface names are in each device's description.

## Rebuild slide 9 in Kentik

Run `impact` for at least 5 minutes, then in Data Explorer. Dimension and metric names below are from memory, so check them against your portal:

1. **Who's talking to which orders-api (the Sankey on the slide).**
   - Visualization: Sankey.
   - Dimensions: Src Outage group → Destination IP.
   - Filters: destination port 443, destination IP 10.20.4.15 or 10.60.1.20.
   - Metric: unique source IPs, so you get host counts: 22, 12 and 4 to the old address, 31 and 9 to the new one.
   - If you switch the metric to bits/s, filter to one router per path, because every hop exports the flow.
2. **The flow records.**
   - Visualization: table.
   - Dimensions: Source IP, Destination IP, Destination Port, TCP Flags.
   - Filter: destination 10.20.4.15.
   - Every row is SYN only, with 3 packets.
3. **Nothing comes back.**
   - Filter on source IP 10.20.4.15: empty.
   - Filter on source IP 10.60.1.20: replies to 40 hosts.
4. **It isn't routing.**
   - Filter device `core_dc1` and destination 10.20.4.15.
   - Group by output interface: the traffic reaches the router and leaves on interface 3, the server VLAN. It isn't dropped along the way; it's going to the wrong address.
5. **The shift.** With the timeline run, a time series of destination IP shows 10.20.4.15 traffic turning into SYN-only flows, then dropping to zero after `fix`.

### AI Advisor prompts

Open-ended first:
- "Some users can't reach orders-api but the app team says it's healthy. Look at the last 30 minutes of flow and tell me what's different between the hosts that work and the ones that don't."

Then direct:
- "Show a Sankey of Src Outage group to destination IP for traffic to port 443, using unique source IPs."
- "Which hosts are sending to 10.20.4.15 and is anything replying? Show TCP flags."
- "Compare traffic to 10.20.4.15 and 10.60.1.20 over the last hour as a time series."
