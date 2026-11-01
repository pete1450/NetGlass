# NetGlass Checks — modular threat detection

No AI. No cloud feed. Every finding is a deterministic rule with a
rule ID, a severity, a score, evidence, and an explanation. A high
score means **investigate**, not confirmed malware.

## How to add a new check (the whole point of the design)

1. Create a class implementing `ICheck` in
   `src/NetGlass.Server/Checks/` — one class per check, grouped
   by category file (`ProcessChecks.cs`, `DestinationChecks.cs`,
   `PortChecks.cs`, `BehaviorChecks.cs`, `ListeningChecks.cs`).
2. Add it to `CheckEngine.All` in `CheckEngine.cs` — one line.
3. Nothing else changes. Scoring, `GET /api/connections`,
   `GET /api/checks`, and the UI Checks view pick it up from the
   registry. There is no if/else chain in Ingest to edit.

A check must never throw on unexpected input. A check that cannot
evaluate (missing exe, weird address, unknown OS) returns null.
A broken check is skipped by the engine so ingest keeps working.

```csharp
public sealed class MyCheck : ICheck
{
    public string Id => "my.category";
    public string Title => "My check";
    public string Category => "Process"; // Process, Destination, PortProtocol, Behavior, Listening, Ghost
    public string Engine => "ThreatIndicators"; // ThreatIndicators, BehavioralAnalysis, ExposureAnalysis
    public string Severity => "Medium"; // Low, Medium, High
    public int Score => 25; // tunable default
    public string Description => "What this looks for, in one sentence.";
    public string? UnavailableReason => null; // or why it cannot run here
    public Finding? Evaluate(CheckContext ctx) => /* Finding or null */;
}
```

## Scoring

Score = sum of finding scores, capped at 100.
Tier: >=70 High, >=40 Medium, >0 Low, 0 None.
Scores are starting defaults, per check, and are meant to be tuned
from real false positives — see "Tuning" below.

Example (illustrative, from the original plan — not a real connection):

> **78 / 100 — High**
> - Unsigned executable — High
> - Running from AppData — Medium
> - Regular 60-second beaconing — High
> - Previously unseen destination — Medium
>
> Why: this executable is unsigned, runs from an unusual location,
> and repeatedly communicates with a previously unseen destination
> at regular intervals.

## Engines (user plan §7, adapted)

- **Threat Indicators** — does this process, destination, or
  connection match known suspicious characteristics?
- **Behavioral Analysis** — is this connection behaving unusually
  for this process/host?
- **Exposure Analysis** — is this host exposing services or
  listeners that should not be accessible?

Categories in the catalogue are the plan's §1–§6:
Process, Destination, PortProtocol, Behavior, Listening, Ghost.

## Baselines — what "normal" means

Two different "new" concepts, do not confuse them:

- **NEW flag (24h):** `seen_keys` — first seen in the last 24 hours.
  This is the old UI "New (24h)" concept.
- **First-ever baseline (persisted):** `baselines` table, via
  `RecordingStore.IsFirstEver`. Once a thing has been seen, it is
  never "first ever" again, even after a restart.

Baseline key formats (must match `Checks/*` and the seeding code
in `RecordingStore.IsFirstEver`):

```
exe:{agent}|{exe}
dest:{agent}|{remoteIp}
dest-global:{remoteIp}
proc-dest:{agent}|{exe}|{remoteIp}
listen-new:{agent}|{exe}|{local}
listen-high:{agent}|{exe}|{local}
proc-port:{agent}|{exe}|{port}
udp:{agent}|{exe}|{ip}|{port}
```

**Seeding on upgrade:** on first use, baselines are seeded from
`seen_keys`, so upgrading NetGlass does *not* flag every existing
exe/destination as first-ever. Only things that appear after the
upgrade fire. Each baseline key is used by exactly one check
(except listen-new / listen-high, which are intentionally distinct
keys for two checks that would otherwise consume each other's
baseline).

## Behavior history — what resets, what does not

`CheckHistory` is in-memory, rolling windows only:

- Session starts: a connection key going from absent to live.
  A persistent connection that stays live is *one* session, not
  a beacon. Beaconing = repeated *new* sessions at regular
  intervals (≥5 sessions, interval 10s–1h, coefficient of
  variation ≤0.25).
- Hour histogram per exe (for off-hours): requires ≥20 prior
  sessions in the current run before it fires.
- PID→exe mapping (for PID reuse): atomic compare-and-update,
  10-minute window.

History resets on server restart. Behavior checks therefore have
a learning period after a restart and will not fire spuriously
from it. Baselines (above) do *not* reset.

## What is NOT implemented, and why (honest gaps)

- **Threat intelligence IP/domain, Tor exit, anonymous proxy:**
  No feed is bundled or fetched. The `dest.threat-list` check
  fires only against a user-supplied file pointed to by
  `NETGLASS_THREAT_LIST` (one IP/domain per line, `#` comments,
  reloaded on file change). Without that file, the check reports
  itself as unavailable in the catalogue. Supplying a Tor exit
  list in that file covers Tor via the same check.
- **Newly registered domain:** requires WHOIS, an external fetch.
  Not implemented; no finding is produced rather than a guess.
- **Unusual country / ASN:** would need GeoIP data. The only
  GeoIP data NetGlass holds is the `ip_info_cache` table, which
  is populated *only* by the on-demand Fetch button, per the
  on-demand rule. A country/ASN check that auto-fetched would
  break that rule, so it is not implemented as an automatic
  check. Fetch an IP first, and its country/ASN are in the drawer.
- **Volume (bytes in/out):** the current `/proc` + `netstat`
  collectors report no per-flow byte counts. No volume finding
  is produced rather than a guessed one. This is Phase 3 (eBPF).
- **Invalid signature:** registered, but no current agent reports
  `invalid`. The Windows agent reports `signed` (Authenticode
  certificate present, via `X509Certificate.CreateFromSignedFile`)
  or `unsigned` (no certificate), and `unknown` otherwise.
  Linux is always `unknown` — the unsigned check skips unknown,
  so Linux connections never get a signature finding.
- **DNS over unusual port, multiple protocols:** covered in part
  by `port.unexpected-udp` and `port.multiple-protocols`. True
  DNS-query attribution (which process queried which hostname)
  needs more collection than socket tables provide.

## Tuning (how to avoid noise)

1. Look at the Checks view: it lists every check, its score,
   and whether it can run here.
2. Disable a noisy check there (persisted in settings,
   `check_enabled:{ruleId}`) — disabling does not delete it.
3. For a known-good destination/process, the long-term answer
   is an allowlist (planned, not yet implemented): a check
   should be suppressible for a specific exe/destination, not
   just globally disabled. Until then, disabling a check is the
   suppression mechanism.
4. Dry-run a new check against recordings before enabling it
   (planned): replay past events through the new check and see
   what would have fired.

## Phases

- **Phase 1 (implemented here):** modular framework, process /
  destination / port / listening / ghost checks from locally
  observable data, behavior checks from session history,
  scoring + tiers, Checks catalogue with enable/disable,
  baselines seeded from history.
- **Phase 2 (planned):** allowlist per exe/destination, dry-run
  against recordings, cross-host correlation (same new
  destination/hash/listener on 2+ hosts = one incident),
  auto-record on High score.
- **Phase 3 (planned):** eBPF collector for per-flow byte counts
  and short-lived connections, which unlocks real volume checks
  and more precise beaconing (with sizes, not just intervals).
