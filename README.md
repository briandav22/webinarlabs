# Webinar labs

Small labs that send real telemetry into a Kentik portal, to back up the scenarios in the "When outages cross cloud boundaries" roundtable.

| Lab | What it shows |
|---|---|
| [staledns-lab](staledns-lab/) | The stale DNS record outage (deck slide 9, "Could you see that in flow data?"): NetFlow v9 from four fake routers, fake on-prem and cloud DNS servers for Kentik synthetic tests, plus Kentik onboarding and custom dimensions |
| [ipam-lab](ipam-lab/) | The unannounced IPAM change (deck outage 2): an Azure network on 10.30.8.0/24 overlaps the payments 10.30.8.0/22, and the transit hub sends payments-db traffic to Azure. NetFlow v9 from three fake routers, with "IPAM lab group" and "IPAM owner" custom dimensions |
| [grid-lab](grid-lab/) | The Infoblox grid use case: after a WAN circuit migration, a Palo Alto firewall denies the Sydney grid member's UDP 1194 and 2114. The firewall exports PAN-OS-format NetFlow v9 (template 257, with firewallEvent, App-ID and User-ID) and is onboarded as a Palo Alto Networks Firewall. Includes an HTML guide, [`guide.html`](grid-lab/guide.html) |

Credentials never go in this repo. Put them in `~/.kentik.env` (`chmod 600`) and `source` it.
