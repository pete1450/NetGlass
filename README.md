# NetGlass

Local-first, multi-host process network visibility — no cloud account required.

NetGlass answers, per host, in a web UI:

- **Outgoing:** exactly what process is creating each connection — executable
  path, command line, parent process, systemd unit, Docker container,
  user, and process start time.
- **Incoming:** exactly what is being connected to — the listening
  process, service/unit/container, local port, and every distinct remote
  source talking to it.

It is the production successor to the single-host SocketWatch prototype
(stdlib Python, `/proc` polling). NetGlass keeps that local-only
philosophy, but splits it into a central server, lightweight agents,
a React UI, recordings, and Apprise notifications.

## Quick start — server

```bash
docker compose up -d --build
# open http://<server-lan-ip>:8080
```

The server image is built from `deploy/server.Dockerfile` and published
to `ghcr.io/pete1450/netglass-server` by CI (see `.github/workflows/ci.yml`).

## Quick start — add a Linux host (Docker agent)

In the UI: **Add agent** → give it a name → copy the generated
`docker-compose.yml` → run it on that host:

```bash
docker compose up -d
```

The agent container is privileged on purpose (`pid: host`,
`SYS_PTRACE`, read-only `/proc` and Docker socket). That is what lets
it see host processes. Keep it on LAN/VPN only. There is no login in
v1 — put the server behind a reverse proxy with auth if it will be
reachable beyond your LAN.

## Quick start — add a Windows host

Download the Windows agent from the release assets
(`NetGlass.Agent-win-x64.exe`, single file, self-contained), then run:

```powershell
.\NetGlass.Agent-win-x64.exe --server http://192.168.1.50:8080 --token <token-from-UI>
```

On first run with no arguments it prompts for server URL and token and
saves them next to the exe in `agent.json`, so subsequent starts need
no arguments. See `scripts/publish-windows.ps1`.

## How it works

```
Windows exe / Docker agent (per host)
  collects sockets + process enrichment
  POST /api/agents/{id}/snapshot   every 2s (configurable)
  GET  /api/agents/{id}/kill-requests   polls for kill jobs
        │
        ▼
NetGlass Server (ASP.NET Core, C#)
  live store with configurable ghost/linger time
  recordings (SQLite, in order, exportable)
  alert rules + Apprise notifications
  agent compose generator
  serves the React UI
        │
        ▼
React UI (Vite + TypeScript)
  sortable live table, detail drawer, kill dialog,
  outgoing / incoming views, recordings, rules
```

Agents never accept inbound connections. They only call out to the
server (snapshot POST, kill-request poll). That keeps the firewall
story simple: only the server port (8080) needs to be reachable from
agents, and only from your LAN/VPN.

## Live view vs recordings

- **Live view (default):** current sockets, plus *ghost* rows. When a
  socket disappears, its row stays faded for the configured linger
  time (default 30s, adjustable in the UI) so quick connections are
  still visible, then it expires. This is the "configurable life
  until they disappear" behaviour.
- **Recording session:** Start a recording in the UI and every
  connection event — seen, still-present, closed — is appended to
  SQLite in order, with timestamp, agent, process, and endpoints.
  Stop it and you can browse, filter, and export it (CSV/JSON) for
  review. Recordings are the audit trail; live view is the radar.

## Killing a process (safely)

The detail drawer shows, for that exact process:

- Linux: `kill <pid>`, `kill -9 <pid>`, `systemctl stop <unit>` (if any),
  `docker kill <container>` (if any)
- Windows: `taskkill /PID <pid> /F`

The **Kill** button in the UI does not just send a PID. It sends
PID + executable + process start time. The agent re-checks that the
PID still belongs to that exact executable and start time before
killing, and refuses on mismatch — this is PID-reuse protection.
Every kill request and result is logged as an alert/audit event.
Killing is always a confirmed action in the UI; there is no
auto-kill in v1.

## Notifications with Apprise

Configure Apprise URLs in the UI (Settings → Notifications) or via
`APPRISE_URLS` / `APPRISE_API_URL` env on the server. The server
invokes the `apprise` CLI if present, otherwise POSTs to an Apprise
API server. Rules (Settings → Rules) can notify on:

- new listener, new outbound destination, new process
- suspicious executable (`/tmp`, `/dev/shm`, deleted exe)
- a destination seen more than N times in M minutes (beaconing hint)
- custom exe / remote / port patterns (regex)

Rules are evaluated on snapshot ingest, deduplicated per rule+key
per hour, and stored as alerts you can review in the UI. Apprise
itself is what delivers to Discord, Telegram, email, Gotify, etc. —
NetGlass does not hard-code a single chat service.

## What is v1, what is next

Implemented in this scaffold (server + agent + UI code, CI builds):

- Multi-agent registration with per-agent tokens
- Live + ghost connections, sortable, filterable, detail drawer
- Outgoing / incoming grouped views
- Recording start/stop/browse/export (SQLite, in order)
- Agent compose generator (UI button → downloadable compose)
- Windows agent (config prompt on startup, single-file publish)
- Kill request flow with PID-reuse check
- Apprise notification plumbing + rule types above

Explicitly *not* in v1, and planned (see `docs/ARCHITECTURE.md`):

- Per-flow byte counts and event-level capture (needs eBPF on Linux;
  the current agents poll `/proc` / `netstat`, so sub-poll-interval
  connections can still be missed outside a recording window)
- Authentication / multi-user (currently LAN-trust only)
- ASN / GeoIP enrichment (optional offline database, not bundled)
- TLS payload inspection (never planned — endpoints only, by design)

## Security

- No cloud, no telemetry, no external calls except: reverse-DNS for
  public IPs (your resolver), Apprise URLs you configure, and
  optional GeoIP database downloads you opt into later.
- Agent tokens are per-agent GUIDs, stored server-side in SQLite.
  Rotate by deleting and re-adding the agent in the UI.
- The agent container and Windows agent run privileged by necessity.
  Treat them as high-value: keep them updated, LAN/VPN only.
- Never commit a token, Apprise URL with a secret, or a compose file
  containing a token to a public repo. The compose generator is for
  your hosts, not for git.

## Repo layout

```
src/NetGlass.Server/   ASP.NET Core server, SignalR hub, SQLite stores
src/NetGlass.Agent/    Cross-platform agent (Linux /proc, Windows netstat)
web/                   React + Vite + TypeScript UI
deploy/                Dockerfiles, server docker-compose.yml
scripts/               Windows publish scripts
docs/                  Architecture, UI ideas, agent, notifications
.github/workflows/    CI: build, test, publish images + Windows exe
```
