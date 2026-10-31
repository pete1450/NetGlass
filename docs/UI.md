# How to make the NetGlass UI awesome (and super useful)

This is the product thinking behind the UI in `web/`. The goal is
not "a prettier table" — it is "answer, in one glance, is something
sketchy happening, and if so, what exactly is it?"

## 1. The one-glance sketchy radar (top of the page)

- **Stats cards that are actually questions:** New listeners (24h),
  new destinations (24h), suspicious processes, ghosts in the last
  minute, agents offline. Each card is a filter — click it, the table
  filters to exactly that set. No dead numbers.
- **"What's new since yesterday" baseline diff.** The single most
  useful view for a home server that mostly does the same thing every
  day: show only processes, destinations, and listeners never seen
  before today / this week. Everything else is noise you already
  approved by living with it.
- **Ghost rows, faded, with a countdown.** A connection that just
  closed stays visible for the linger time, fading out. Quick
  phone-home bursts stop being invisible. Pair this with a
  "Recently closed" strip so you can still click into a ghost and
  kill / investigate its process if it is still alive.

## 2. Outgoing vs incoming, as separate mental models

- **Outgoing tab — "What made this?"** Group by process/exe first,
  destination second. For each process: how many distinct
  destinations, first/last seen, total live sockets, and a sparkline
  of socket count over the last hour. A browser with 40 destinations
  is normal; a backup script with 40 new destinations at 3am is not.
- **Incoming tab — "What is being hit?"** Group by local service
  (listening process + port). For each service: distinct remote IPs,
  top remotes, first time each remote appeared, and whether the
  service is exposed to a public IP or only LAN. A new remote from
  an unexpected country talking to SSH is the story here, not the
  individual socket row.
- **Topology graph (high impact, v2).** Agent → process → destination
  nodes, click a node to filter the table to it. This is where a
  compromised container "talking to a process that talks to the
  internet" becomes visible as a chain, not as isolated rows.

## 3. Click a connection, get the whole story (detail drawer)

- Full command line with copy button, parent chain (grandparent
  included — `cron → bash → curl` tells a different story than
  just `curl`), systemd unit with `systemctl status` command,
  container with `docker inspect` / `docker logs` commands, user,
  start time, and "was this process started by a service, a
  container, a cron job, or interactively?"
- **Kill section, not just a kill button:** show the exact shell
  command for that host/OS, the unit/container stop command if
  applicable, and a Kill button that requires confirmation and
  shows the PID-reuse check result. Also show "what will break if
  you kill this" — i.e. its unit/container and sibling processes.
- **Destination dossier:** reverse DNS, public/private, well-known
  port name, first time *this host* ever talked to it, first time
  *any* host talked to it, and how many other processes use it.
  A destination used by one weird process is more suspicious than
  one used by everything.

## 4. Recordings as a time machine

- Start/stop, name, and notes on a recording. Browse events in
  order, scrub a timeline, and jump to "first time X happened".
- **Replay at 1x / 10x / 100x** through a recording, with the live
  table re-populated as it was at that timestamp. Reviewing an
  incident becomes watching it happen, not reading a log.
- Export to CSV/JSON for sharing or for feeding into another tool.
- Auto-recordings: "always record the first 5 minutes after a new
  listener appears" — you get the evidence without remembering to
  press record.

## 5. Patterns, not just alerts (Apprise)

- **Beaconing detection:** same destination at suspiciously regular
  intervals (e.g. every 60s ± 5s) — classic C2 behaviour, and the
  kind of thing a human staring at a table will miss.
- **Burst detection:** N new destinations in M minutes from one
  process, or one process suddenly opening many sockets.
- **Lateral movement hint:** a host that never talked to another
  LAN host suddenly connecting to many LAN ports.
- **Quiet-hours rules:** same connection at 3am that is normal at
  3pm gets a different alert level. Rules should carry a schedule,
  not just a pattern.
- Every alert links back to the exact connection/process/destination
  in the UI, and to the recording covering that time window if one
  exists. An alert without a one-click investigation path is spam.

## 6. Small UX things that compound

- Every column sortable, every filter combinable, search syntax
  like `process:chrome remote:*.example.com port:443 agent:server1`.
- Keyboard: `/` focuses search, `Esc` closes the drawer, `g` toggles
  ghosts, `r` toggles recording.
- Copy buttons on every ID, IP, command, and compose snippet.
- Dark UI by default (you will stare at this at night), with
  colour used sparingly: red only for suspicious, amber for new,
  grey for ghosts. If everything is coloured, nothing is.
- Agent health in the header: last seen, agent version, socket
  count, and a clear "agent offline" state — a silent agent is
  itself a signal.
- Onboarding empty state: if no agents are connected, the page is
  the Add Agent flow, not an empty table. The first run should end
  with a live row in under five minutes.
