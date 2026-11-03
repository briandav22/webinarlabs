# Webinar labs

Small labs that send real telemetry into a Kentik portal, to back up the scenarios in the "When outages cross cloud boundaries" roundtable.

| Lab | What it shows |
|---|---|
| [staledns-lab](staledns-lab/) | The stale DNS record outage (deck slide 9, "Could you see that in flow data?"): NetFlow v9 from four fake routers, with Kentik onboarding and custom dimensions |

Credentials never go in this repo. Put them in `~/.kentik.env` (`chmod 600`) and `source` it.
