# NetGlass architecture

## Components

### Server (`src/NetGlass.Server`, ASP.NET Core, .NET 8)

- Minimal APIs under `/api/*`, SignalR hub `/hubs/live` for future
  push (the React UI currently polls `/api/connections` every 2s,
  which is simpler and robust at home scale; SignalR is wired and
  broadcast on snapshot ingest for the next UI iteration).
- `ConnectionStore`: in-memory live map, keyed by
  `(agent, proto, direction, exe, localPort, remoteIp, remotePort)`.
  Each entry carries `LastSeen`. A row is *live* if it was in the
  latest snapshot, *ghost* if it disappeared within the linger
  window (default 30s, `POST /api/settings/linger`), *expired* after
  that and pruned. Ghosts are what make quick connections visible.
- `RecordingStore`: SQLite (`netglass.db`, `Microsoft.Data.Sqlite`).
  Tables: `agents`, `recordings`, `recording_events` (append-only,
  `seq` per recording, so review is in order), `alerts`, `rules`,
  `settings`, `kill_requests`. No EF migrations — tables are created
  on startup, which keeps the Docker image simple.
- `RuleEngine`: evaluated on every snapshot. Rule types:
  `NewListener`, `NewDestination`, `NewProcess`, `SuspiciousExe`,
  `Frequency` (same key > N in M minutes), `Pattern` (regex over
  exe / remote / local port). Dedupe key = rule + connection key,
  one alert per hour unless the rule says otherwise.
- `AppriseNotifier`: if `apprise` is on PATH, shells out to it;
  else if `APPRISE_API_URL` is set, POSTs `{urls, title, body}` to
  that API. Apprise URLs are stored in the `settings` table, never
  in the repo.
- `ComposeGenerator`: templates the agent compose from agent id,
  token, server URL, and image tag. The UI calls
  `GET /api/agents/{id}/compose?serverUrl=...` and offers download.

### Agent (`src/NetGlass.Agent`, .NET 8 console)

- Config resolution order: CLI args > env vars > `agent.json` next
  to the exe (Windows) / `~/.config/netglass/agent.json` (Linux).
  If no server/token is found, the agent prompts interactively on
  startup and saves the answers — this is the "set server IP/port
  on startup" Windows behaviour, and it works the same on Linux.
- Linux collector: one `/proc/<pid>/net/{tcp,tcp6,udp,udp6}` read per
  network namespace (PIDs grouped by `/proc/<pid>/ns/net`, deduplicated
  by socket inode) — the host namespace alone misses Docker container
  traffic, which lives in each container's own namespace — plus
  `/proc/<pid>/fd` socket-inode mapping + `/proc/<pid>/{stat,cmdline,exe,status,cgroup}`.
  This is a direct port of the SocketWatch prototype logic, in C#.
- Windows collector: `netstat -ano` (TCP + UDP) parsed, enriched
  with `Process.GetProcessById` (exe via `MainModule.FileName`,
  start time via `Process.StartTime`) and parent PID via a WMI
  `Win32_Process` query when available. No driver, no kernel module.
- Sender: `POST /api/agents/{id}/snapshot` every interval (default
  2s, `--interval`). Kill poller: `GET /api/agents/{id}/kill-requests`
  every 5s; on a request, re-read the process, compare exe and
  start time to the request, and only then `Process.Kill()`.
  Result is POSTed back. Agents never listen on a port.

### Web (`web/`, React + Vite + TypeScript)

- No UI framework dependency beyond React itself, so the bundle
  stays small and the build stays boring. All state is fetched
  from `/api/*`; the table is client-sortable on every column.
- Detail drawer (click any row): full command line (copy button),
  parent chain, unit, container, start time, destination info,
  first/last seen, flags, and the kill section (commands + Kill
  button with confirmation).
- Views: All / Outgoing / Incoming. Outgoing groups by process;
  incoming groups by local service (listening process + port) and
  shows distinct remote sources per service. This is the emphasis
  the product is built around: outgoing = "what made this?",
  incoming = "what is being hit?"

## Data model (live connection, JSON)

```json
{
  "agentId": "…", "agentName": "debian-server",
  "direction": "outbound", "proto": "tcp", "state": "ESTABLISHED",
  "local": "192.168.1.50:54321", "remote": "93.184.216.34:443",
  "remoteHost": "example.com",
  "pid": 1234, "process": "curl", "exe": "/usr/bin/curl",
  "cmdline": "curl https://example.com",
  "user": "pete", "ppid": 1200, "parent": "bash", "parentExe": "/bin/bash",
  "unit": "my-job.service", "container": "my-app", "containerId": "abc123…",
  "started": "2026-10-31T14:00:00Z",
  "firstSeen": "2026-10-31T14:01:00Z", "lastSeen": "2026-10-31T14:02:00Z",
  "isGhost": false, "isNew": true, "suspicious": false, "flags": ["NEW"]
}
```

## Scaling notes (honest)

- Home scale (a handful of hosts, hundreds of sockets each) is the
  design target. Polling every 2s + SQLite recordings is fine there.
- At hundreds of hosts or tens of thousands of sockets, move
  recordings to Postgres, add a message queue between agents and
  the server, and switch the UI to SignalR push. The API shapes
  above do not need to change for that migration.
- Ghost/linger is a UI/UX compensation for polling, not a
  replacement for event capture. For true "never miss a 200ms
  connection", the next step is an eBPF collector on Linux
  (trace `tcp_connect`/`accept`/`close`) feeding the same snapshot
  API, plus a Windows ETW collector. That is the planned v2
  collector, behind the same agent interface.

## Docker images (CI)

- `ghcr.io/pete1450/netglass-server:latest` — multi-stage:
  Node builds `web/` → `wwwroot`, .NET builds the server, runtime
  is `mcr.microsoft.com/dotnet/aspnet:8.0`.
- `ghcr.io/pete1450/netglass-agent:latest` — .NET runtime image
  with the agent binary; run with `pid: host` + `/proc` mount
  (see the compose generator output, not a plain `docker run`).
- Windows exe is a GitHub Release asset, not a Docker image:
  `dotnet publish -r win-x64 --self-contained -p:PublishSingleFile=true`.
