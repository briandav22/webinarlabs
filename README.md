# Webinar labs

Small labs that send real telemetry into a Kentik portal, to back up the scenarios in the "When outages cross cloud boundaries" roundtable.

| Lab | What it shows |
|---|---|
| [staledns-lab](staledns-lab/) | The stale DNS record outage (deck slide 9, "Could you see that in flow data?"): NetFlow v9 from four fake routers, fake on-prem and cloud DNS servers for Kentik synthetic tests, plus Kentik onboarding and custom dimensions |
| [ipam-lab](ipam-lab/) | The unannounced IPAM change (deck outage 2): an Azure network on 10.30.8.0/24 overlaps the payments 10.30.8.0/22, and the transit hub sends payments-db traffic to Azure. NetFlow v9 from three fake routers, with "IPAM lab group" and "IPAM owner" custom dimensions |

Credentials never go in this repo. Put them in `~/.kentik.env` (`chmod 600`) and `source` it.
