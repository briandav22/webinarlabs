# IPAM overlap lab

NetFlow v9 for deck outage 2, "The unannounced IPAM change". A data team builds an Azure network on 10.30.8.0/24, a range that sits inside the payments range 10.30.8.0/22 in dc1. The cloud transit hub prefers the more specific /24, so cloud traffic to payments-db goes to Azure and nothing answers.

It's one Python file, standard library only, in the same style as `staledns-lab`. Its routers use 192.168.253.x and their names start with `ipam_`, so it runs and onboards next to the other labs without clashing.

## What it sends

| Router | Sending IP | Interfaces (ifIndex) |
|---|---|---|
| `ipam_dc1_core` | 192.168.253.21 | 1 interconnect to transit hub · 2 DB VLAN 10.30.8.0/22 · 3 dc1 apps VLAN 10.20.12.0/24 |
| `ipam_transit_hub` | 192.168.253.31 | 1 interconnect to dc1 · 2 AWS orders VPC attachment · 3 Azure analytics VNet attachment |
| `ipam_azure_analytics` | 192.168.253.41 | 1 transit hub attachment · 2 analytics subnet |

The hosts and services:
- **orders apps in AWS:** 24 hosts on 10.60.4.x.
- **dc1 apps:** 10 hosts on 10.20.12.x.
- **analytics VNet in Azure:** 6 hosts on 10.30.8.101–106, which move to 10.44.2.101–106 in the fix.
- **payments-db:** 10.30.8.40, inside the /24, so it breaks.
- **reports-db:** 10.30.10.25. It's in the same /22 but outside the /24, so it keeps working.
- **Database port:** TCP 5432 for both databases.

Every router a flow passes through exports it, with input and output interface, at sample rate 1. In a real network the Azure side would come from VNet flow logs; here `ipam_azure_analytics` stands in as a router.

| Phase | What the network does |
|---|---|
| `before` | Orders apps reach payments-db and reports-db over the interconnect. dc1 apps reach payments-db locally. Everything answers |
| `change` | The analytics VNet appears on 10.30.8.0/24 and is attached to the hub. Its hosts try reports-db. The request crosses the interconnect, but dc1 thinks 10.30.8.0/22 is its own, so the replies (SYN-ACKs) go out the DB VLAN and never get back. Orders traffic is still fine |
| `impact` | **The deck's outage.** The hub sends orders apps' traffic for 10.30.8.40 to the Azure attachment. It arrives in the analytics VNet and nothing answers (SYN only). Traffic to reports-db still works, and dc1 apps never cross the hub, so it looks partial and random |
| `fix` | The VNet is re-addressed to 10.44.2.0/24 from IPAM. Everything answers, including analytics to reports-db |

## Run it

```bash
sudo python3 ipam_lab.py aliases --apply          # 192.168.253.21, .31, .41 on loopback

source ~/.kentik.env                              # same file as the other labs
python3 ipam_lab.py kentik onboard --dry-run
python3 ipam_lab.py kentik onboard
python3 ipam_lab.py kentik dimensions --dry-run
python3 ipam_lab.py kentik dimensions

python3 ipam_lab.py run --collector 127.0.0.1 --port 9995 --timeline "before:10,change:5,impact:20,fix:10"
```

While it runs, type `before`, `change`, `impact` or `fix` to switch phases, `status` for counters, `quit` to stop. Use `--phase impact` instead of `--timeline` to stay on one phase.

Checks:

```bash
python3 ipam_lab.py preview --phase impact        # what a phase sends over one minute, no network
python3 -m unittest -v test_ipam_lab              # 10 tests, including a real send from three IPs
```

`kentik dimensions` creates two pairs, with one populator per value. It uses `replace_all`, so any populators added to these four dimensions by hand are removed.
- **IPAM lab group** (`c_src_ipamlab` / `c_dst_ipamlab`): orders apps, dc1 apps, analytics VNet (overlapping), analytics VNet (re-addressed), payments-db, reports-db.
- **IPAM owner** (`c_src_ipamowner` / `c_dst_ipamowner`): what a pretend IPAM says owns each range. 10.30.8.0/22 is payments (dc1), 10.60.4.0/24 is orders, 10.20.12.0/24 is dc1 apps, and 10.44.2.0/24 is analytics. The overlapping 10.30.8.0/24 was never allocated, so its addresses show up as payments (dc1). That mismatch is the tell.

The routers don't answer SNMP, so Kentik shows interfaces by number. The names are in each device's description and in the table above.

## Show it in Kentik

Run the timeline, give it a few minutes per phase, then use Data Explorer. Dimension and metric names below are from memory, so check them against your portal.

1. **Where did the traffic go?** This is the deck's chart.
   - Visualization: time series, bits/s.
   - Filters: device `ipam_transit_hub`, destination IP 10.30.8.40.
   - Group by: output interface.
   - At `impact`, the traffic flips from interface 1 (interconnect) to interface 3 (Azure attachment), and back after `fix`.
2. **Nothing answers in Azure.**
   - Filters: device `ipam_azure_analytics`, destination IP 10.30.8.40.
   - Group by: source IP and TCP flags.
   - Every flow is SYN only, and filtering on source IP 10.30.8.40 returns nothing.
3. **Why it looks random.**
   - Visualization: Sankey of Src IPAM lab group → Dst IPAM lab group, with metric unique source IPs.
   - During `impact`, orders apps still reach reports-db but not payments-db, and dc1 apps reach payments-db fine.
   - Same /22, different results.
4. **The overlap tell.**
   - Filters: device `ipam_transit_hub`, input interface 3 (Azure attachment).
   - Group by: Src IPAM owner.
   - Addresses that IPAM says belong to payments (dc1) are arriving from Azure.
   - On `ipam_dc1_core`, the SYN-ACKs from reports-db to 10.30.8.10x enter and leave on interface 2: dc1 delivers them locally because it believes it owns the range.
5. **Line it up with the change.** On the time series, the VNet's first flows show up at `change`, and payments-db traffic leaves for Azure at `impact`. That's the deck's "created at 09:12, traffic moved two minutes later".

### AI Advisor prompts

Open-ended first:
- "Cloud apps can't reach payments-db, but DNS is correct and the database is up. What changed in the traffic over the last 30 minutes?"

Then direct:
- "On ipam_transit_hub, show traffic to 10.30.8.40 by output interface as a time series."
- "Which source addresses arriving from the Azure attachment does IPAM owner say belong to payments (dc1)?"
- "Compare orders apps' traffic to 10.30.8.40 and 10.30.10.25: which gets replies?"
