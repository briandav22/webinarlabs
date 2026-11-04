# Grid lab

Flow for the Infoblox grid use case. After network maintenance, the Sydney grid member drops off the grid and the replication queues grow. The cause is a Palo Alto firewall that now denies the grid's traffic: UDP 1194 (the member's VPN tunnel to the Grid Master) and UDP 2114 (the key exchange a member runs when it joins).

The firewall exports flow the way PAN-OS does: NetFlow v9 with Palo's template 257 ("IPv4 Enterprise"), including `firewallEvent`, `flowId`, App-ID and User-ID. Kentik reads these into its Palo Alto Networks Firewall dimensions, so you can filter on **Firewall Event = Flow Denied**. The two routers send plain NetFlow v9 like the other labs.

It's one Python file, standard library only, in the same style as `staledns-lab` and `ipam-lab`. Its devices use 192.168.254.x and their names start with `grid_`, so it runs next to the other labs.

There's an HTML guide with the topology, each phase and the record format: [`guide.html`](guide.html).

## What it sends

| Device | Sending IP | Kentik type | Interfaces (ifIndex) |
|---|---|---|---|
| `grid_syd_wan` | 192.168.254.11 | router | 1 Sydney LAN · 2 APAC MPLS circuit (old) · 3 APAC SD-WAN circuit (new) |
| `grid_pa_dc_fw` | 192.168.254.21 | **Palo Alto Networks Firewall** (`paloalto`) | 1 ethernet1/1 trust (dc1 core) · 2 ethernet1/2 EMEA WAN · 3 ethernet1/3 APAC MPLS, zone `apac-wan` · 4 ethernet1/4 APAC SD-WAN, zone `apac-sdwan` (new) |
| `grid_dc_core` | 192.168.254.31 | router | 1 uplink to firewall · 2 infra VLAN (Grid Master) · 3 apps VLAN |

The hosts and services:
- **Sydney grid member:** 10.70.1.10.
- **London grid member:** 10.80.1.10. It's the control group: it never breaks.
- **Grid Master:** 10.20.1.5 in dc1.
- **Sydney office users:** 18 hosts on 10.70.20.x, each with a User-ID (`corp\jsmith` and so on), using an app at 10.20.30.40 on TCP 443.
- **Grid ports:** UDP 1194 for the tunnel (App-ID `openvpn`) and UDP 2114 for the key exchange (App-ID `unknown-udp`).

| Phase | What the network does | What the firewall exports |
|---|---|---|
| `before` | Both members' tunnels are up. Sydney comes in over MPLS on ethernet1/3 | **update (5)** for each tunnel every active timeout |
| `maintenance` | Sydney's circuit is moved from MPLS to SD-WAN. Nothing leaves Sydney | **deleted (2)** for Sydney's tunnel. London keeps sending updates |
| `impact` | The new circuit is up on ethernet1/4, zone `apac-sdwan`. The office rule was updated for the new zone, so users are fine and the change gets closed. The grid rule wasn't updated | **denied (3)** for every retry from 10.70.1.10: 1194 every 10 seconds, 2114 every 30. App-ID `not-applicable`, output interface 0. Office sessions get created (1) and deleted (2) as normal |
| `fix` | The grid rule gets zone `apac-sdwan` | **created (1)** and **deleted (2)** for the 2114 key exchange, then **created (1)** for a new tunnel, then updates. The Grid Master sends a burst of catch-up replication that fades over four minutes |

In `impact`, the WAN router still exports the member's attempts. The firewall exports them as denied, and `grid_dc_core` never sees them. Nothing comes back.

## The firewall's record format

Template 257, 20 fields and 147 bytes a record, in the order on Palo Alto's [NetFlow Templates](https://docs.paloaltonetworks.com/ngfw/administration/monitoring/netflow-monitoring/netflow-templates) page:

| ID | Field | Bytes | ID | Field | Bytes |
|---|---|---|---|---|---|
| 1 | IN_BYTES | 4 | 21 | LAST_SWITCHED | 4 |
| 2 | IN_PKTS | 4 | 22 | FIRST_SWITCHED | 4 |
| 4 | PROTOCOL | 1 | 32 | ICMP_TYPE | 2 |
| 5 | TOS | 1 | 61 | DIRECTION | 1 |
| 6 | TCP_FLAGS | 1 | 148 | flowId (session ID) | 8 |
| 7 | L4_SRC_PORT | 2 | 233 | firewallEvent | 1 |
| 8 | IPV4_SRC_ADDR | 4 | 346 | privateEnterpriseNumber (25461) | 4 |
| 10 | INPUT_SNMP | 2 | 56701 | App-ID | 32 |
| 11 | L4_DST_PORT | 2 | 56702 | User-ID | 64 |
| 12 | IPV4_DST_ADDR | 4 | | | |
| 14 | OUTPUT_SNMP | 2 | | | |

Template refresh follows the PAN-OS NetFlow profile defaults: the template goes out in the first packet, then every 20 packets or 30 minutes. The v9 sequence number counts export packets.

What's documented and what I chose:
- **Documented by Palo Alto:** the template ID, field IDs and order, the firewallEvent values, the enterprise number, and the default lengths for counters (4), interfaces (2), App-ID (up to 32) and User-ID (up to 64).
- **Chosen by me (Palo doesn't publish them):**
  - The other lengths use the standard sizes: flowId 8, firewallEvent 1, DIRECTION 1, ICMP_TYPE 2. Collectors read records by the template, so a different length on real gear still parses.
  - A denied record carries the first packet, with output interface 0.
  - Short sessions get a created record for the first packet, then deleted records for the rest of each direction.
- **Lab choices:** App-IDs `openvpn`, `unknown-udp` and `not-applicable` for denied sessions, the retry intervals, and the active timeout. The lab uses 1 minute (`--active-timeout 60`), which is a valid PAN-OS setting, so updates show up quickly. The PAN-OS default is 5 minutes.

If you have a real Palo (a VM-Series is enough), capture a minute of its export with `tcpdump -w pan.pcap udp port 2055` and send it to me. I can match the template byte for byte.

## Run it

```bash
sudo python3 grid_lab.py aliases --apply          # 192.168.254.11, .21, .31 on loopback

source ~/.kentik.env                              # same file as the other labs
python3 grid_lab.py kentik onboard --dry-run
python3 grid_lab.py kentik onboard                # the firewall goes in as Palo Alto Networks Firewall
python3 grid_lab.py kentik dimensions --dry-run
python3 grid_lab.py kentik dimensions

python3 grid_lab.py run --collector 127.0.0.1 --port 9995 --timeline "before:10,maintenance:3,impact:20,fix:10"
```

While it runs, type `before`, `maintenance`, `impact` or `fix` to switch phases, `status` for counters, `quit` to stop. Use `--phase impact` instead of `--timeline` to stay on one phase.

Checks:

```bash
python3 grid_lab.py preview --phase impact                        # what a phase sends, no network
python3 grid_lab.py listen --port 9996 --firewall-only &          # decode the firewall's records off the wire
python3 grid_lab.py run --port 9996 --no-bind --no-console --duration 30
python3 -m unittest -v test_grid_lab                              # 13 tests, incl. a real send from three IPs
```

The test suite also decodes the firewall's packets with the [`netflow`](https://pypi.org/project/netflow/) package if it's installed (`pip install netflow`). That package names fields 233, 346, 56701 and 56702 as firewall event and PAN-OS fields.

Notes:
- **Descriptions are capped at 128 characters.** Kentik rejects a longer device description with HTTP 400. `onboard` checks this before calling the API, dry runs included.
- **Device type matters.** Kentik collects device-specific dimensions based on the device type. `onboard` sets the firewall to `paloalto` and warns if Kentik reports a different type after the call. If the Firewall Event and Application ID dimensions are empty, check the type in Settings → Network Devices.
- **Custom dimensions:** `kentik dimensions` creates `c_src_gridrole` and `c_dst_gridrole`, shown as "Src Grid lab role" and "Dst Grid lab role". The values are Sydney grid member, London grid member, Grid Master (dc1), Sydney office users and dc1 apps. It uses `replace_all`, so any populators added to them by hand are removed.
- **No SNMP:** interfaces show by number. The names, including the firewall's ethernet1/x and zones, are in each device's description and in the table above.
- **sudo:** sudo drops your environment variables. Use `sudo -E` if you run the Kentik commands under sudo.

## Show it in Kentik

Run the timeline, then use Data Explorer. The Palo Alto dimension names below are from Kentik's KB ([device-specific dimensions](https://kb.kentik.com/docs/device-specific-dimensions)). The rest are from memory, so check them in your portal.

1. **Where the traffic dies.**
   - Filters: source IP 10.70.1.10, destination IP 10.20.1.5.
   - Group by: Device, Destination Port. Visualization: time series.
   - Before maintenance, all three devices carry the tunnel. After it, `grid_syd_wan` and `grid_pa_dc_fw` still see the member, but `grid_dc_core` doesn't.
2. **The firewall says why.**
   - Filters: device `grid_pa_dc_fw`, source IP 10.70.1.10.
   - Group by: Firewall Event, Destination Port, Application ID, Input Interface. Visualization: table.
   - During `impact`, every row is event 3 (flow denied) on 1194 or 2114, App-ID `not-applicable`, input interface 4.
3. **What the change did.**
   - Filters: device `grid_pa_dc_fw`, Src Grid lab role = Sydney office users.
   - Group by: Input Interface, Firewall Event.
   - Office traffic moves from interface 3 to 4 at maintenance and keeps getting created and deleted events. To the network team, the change worked.
4. **Only Sydney.**
   - Filter: device `grid_pa_dc_fw`, destination port 1194.
   - Group by: Src Grid lab role, Firewall Event.
   - London's tunnel keeps sending updates (5) while Sydney's attempts are denied (3).
5. **The fix and the catch-up.**
   - Filters: source IP 10.20.1.5, destination IP 10.70.1.10, device `grid_pa_dc_fw`. Visualization: time series, bits/s.
   - After `fix`, the Grid Master's catch-up replication peaks around 1 Mbit/s in the first minute against a normal 56 kbit/s, then fades over four minutes. That's the replication queue Victor talks about draining.

### AI Advisor prompts

Open-ended first:
- "Our Sydney Infoblox grid member went offline after last night's network maintenance. Look at flow for 10.70.1.10 over the last hour and tell me where its traffic to the Grid Master stops."

Then direct:
- "On grid_pa_dc_fw, show flows from 10.70.1.10 grouped by firewall event, destination port and application ID."
- "Which sources had flows denied by grid_pa_dc_fw in the last 30 minutes, and on which input interface did they arrive?"
- "Compare firewall events for UDP 1194 between the Sydney and London grid members as a time series."
- "Show traffic from 10.20.1.5 to 10.70.1.10 in bits per second over the last hour."
