using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.SignalR;
using NetGlass.Server;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSignalR();
builder.Services.AddSingleton<ConnectionStore>();
builder.Services.AddSingleton(sp =>
    new RecordingStore(
        Environment.GetEnvironmentVariable("NETGLASS_DB") ?? "netglass.db"));
builder.Services.AddSingleton<AppriseNotifier>();
builder.Services.AddSingleton<ReverseDnsService>();

var app = builder.Build();
var store = app.Services.GetRequiredService<ConnectionStore>();
var recordings = app.Services.GetRequiredService<RecordingStore>();
var notifier = app.Services.GetRequiredService<AppriseNotifier>();
var dns = app.Services.GetRequiredService<ReverseDnsService>();

// ---- agents (in-memory, backed by SQLite) -------------------------------
var agents = new ConcurrentDictionary<string, AgentInfo>();
using (var conn = recordings.Open())
using (var cmd = conn.CreateCommand())
{
    cmd.CommandText = "SELECT id, name, hostname, os, version, token FROM agents";
    using var reader = cmd.ExecuteReader();
    while (reader.Read())
        agents[reader.GetString(0)] = new AgentInfo(
            reader.GetString(0), reader.GetString(1), reader.GetString(2),
            reader.GetString(3), reader.GetString(4), reader.GetString(5),
            DateTime.UtcNow, 0);
}
var lingerSetting = recordings.GetSetting("linger_seconds");
if (int.TryParse(lingerSetting, out var linger)) store.LingerSeconds = linger;

var ruleLastAlert = new ConcurrentDictionary<string, DateTime>();
var frequencyHits = new ConcurrentDictionary<string, List<DateTime>>();

// Modular checks: enabled by default, toggled via /api/checks.
// Loaded from settings at startup, kept in memory so Ingest does
// not do a DB query per check per connection.
var checkEnabled = new ConcurrentDictionary<string, bool>(
    NetGlass.Server.Checks.CheckEngine.All.ToDictionary(c => c.Id, _ => true));
using (var conn = recordings.Open())
using (var cmd = conn.CreateCommand())
{
    cmd.CommandText = "SELECT key, value FROM settings WHERE key LIKE 'check_enabled:%'";
    using var reader = cmd.ExecuteReader();
    while (reader.Read())
        checkEnabled[reader.GetString(0)["check_enabled:".Length..]] = reader.GetString(1) != "0";
}

AgentInfo? AuthAgent(string id, HttpRequest req)
{
    if (!agents.TryGetValue(id, out var agent)) return null;
    var token = req.Headers["X-Agent-Token"].ToString();
    return token == agent.Token ? agent : null;
}

// Fill RemoteHost from the PTR cache, and kick off a local background
// PTR lookup for any IP not yet cached. Never blocks on DNS: the
// hostname appears on the next poll once cached.
List<ConnectionDto> WithHosts(List<ConnectionDto> conns)
{
    var outList = new List<ConnectionDto>(conns.Count);
    foreach (var c in conns)
    {
        var ip = IpHelpers.ParseIp(c.Remote);
        if (ip is null) { outList.Add(c); continue; }
        var host = dns.GetCached(ip);
        if (host is not null) outList.Add(c with { RemoteHost = host });
        else { dns.EnsureResolved(ip); outList.Add(c); }
    }
    return outList;
}

// ---- agent registration + compose generator -----------------------------
app.MapPost("/api/agents", (JsonElement body) =>
{
    var name = body.GetProperty("name").GetString() ?? "agent";
    var id = Guid.NewGuid().ToString("N");
    var token = Guid.NewGuid().ToString("N");
    var agent = new AgentInfo(id, name, "", "", "", token, DateTime.UtcNow, 0);
    agents[id] = agent;
    using var conn = recordings.Open();
    conn.Execute("INSERT INTO agents VALUES ($id, $n, $h, $o, $v, $t, $l)",
        ("$id", id), ("$n", name), ("$h", ""), ("$o", ""), ("$v", ""),
        ("$t", token), ("$l", DateTime.UtcNow.ToString("O")));
    return Results.Json(new { id, name, token });
});

app.MapGet("/api/agents", () =>
    Results.Json(agents.Values.Select(a => new
        { a.Id, a.Name, a.Hostname, a.Os, a.Version, a.LastSeen, a.SocketCount })));

// Delete an agent: revoke its token, drop its live/ghost rows, and
// remove its SQLite row, pending kill requests, and seen-keys (so a
// re-registered agent's connections show as NEW again). Recordings
// and alerts are audit history and are kept. An agent that is still
// running will get 401 on its next snapshot until it is re-registered.
app.MapDelete("/api/agents/{id}", (string id) =>
{
    if (!agents.TryRemove(id, out _)) return Results.NotFound();
    store.RemoveAgent(id);
    using var conn = recordings.Open();
    conn.Execute("DELETE FROM agents WHERE id = $id", ("$id", id));
    conn.Execute("DELETE FROM kill_requests WHERE agent_id = $id", ("$id", id));
    conn.Execute("DELETE FROM seen_keys WHERE key LIKE $p", ("$p", id + "|%"));
    return Results.Ok(new { deleted = id });
});

app.MapGet("/api/agents/{id}/compose", (string id, string? serverUrl, string? image) =>
{
    if (!agents.TryGetValue(id, out var agent)) return Results.NotFound();
    var url = serverUrl ?? "http://YOUR-SERVER-IP:8080";
    var img = image ?? "ghcr.io/pete1450/netglass-agent:latest";
    var yaml = ComposeGenerator.ForAgent(agent.Id, agent.Name, agent.Token, url, img);
    return Results.Text(yaml, "text/yaml");
});

// ---- snapshot ingest ----------------------------------------------------
app.MapPost("/api/agents/{id}/snapshot", async (string id, SnapshotRequest snap, HttpRequest req,
    IHubContext<LiveHub> hub) =>
{
    var agent = AuthAgent(id, req);
    if (agent is null) return Results.Unauthorized();
    var now = DateTime.UtcNow;
    var before = store.All(now).ToDictionary(ConnectionStore.KeyOf, c => c);
    agent = agent with { LastSeen = now, SocketCount = snap.Connections.Count, Hostname = snap.Hostname, Os = snap.Os, Version = snap.Version };
    agents[id] = agent;

    var (live, closedKeys) = store.Ingest(agent, snap, now,
        (key, t) => recordings.IsNewKey(key, t),
        key => recordings.IsFirstEver(key, now),
        id => checkEnabled.GetValueOrDefault(id, true),
        ip => recordings.GetCachedIpInfo(ip));

    // Recordings: seen + closed events, in order.
    var recordingId = recordings.CurrentRecordingId();
    if (recordingId is not null)
    {
        var previousKeys = before.Keys.ToHashSet();
        foreach (var c in live)
            if (!previousKeys.Contains(ConnectionStore.KeyOf(c)))
                recordings.AppendEvent(recordingId, "seen", c, now);
        foreach (var key in closedKeys)
            if (before.TryGetValue(key, out var closed))
                recordings.AppendEvent(recordingId, "closed", closed, now);
    }

    // Rules -> alerts -> Apprise (deduplicated per rule+key, 1 hour).
    using (var conn = recordings.Open())
    using (var cmd = conn.CreateCommand())
    {
        cmd.CommandText = "SELECT id, name, type, pattern, threshold, window_minutes, enabled FROM rules";
        using var reader = cmd.ExecuteReader();
        var rules = new List<AlertRuleDto>();
        while (reader.Read())
            rules.Add(new AlertRuleDto(reader.GetString(0), reader.GetString(1),
                reader.GetString(2), reader.GetString(3), reader.GetInt32(4),
                reader.GetInt32(5), reader.GetInt32(6) == 1));
        foreach (var rule in rules.Where(r => r.Enabled))
        {
            foreach (var c in live)
            {
                var triggered = rule.Type switch
                {
                    "NewListener" => c.Direction == "listen" && c.IsNew,
                    "NewDestination" => c.Direction == "outbound" && c.IsNew,
                    "SuspiciousExe" => c.Flags.Contains("TMP_EXE") || c.Flags.Contains("DELETED_EXE"),
                    "Pattern" => !string.IsNullOrWhiteSpace(rule.Pattern) &&
                        (Regex.IsMatch(c.Exe, rule.Pattern, RegexOptions.IgnoreCase) ||
                         Regex.IsMatch(c.Remote, rule.Pattern, RegexOptions.IgnoreCase)),
                    "Frequency" => FrequencyTriggered(rule, c, now),
                    _ => false,
                };
                if (!triggered) continue;
                var dedupe = $"{rule.Id}|{c.AgentId}|{c.Exe}|{c.Remote}";
                if (ruleLastAlert.TryGetValue(dedupe, out var last) && now - last < TimeSpan.FromHours(1))
                    continue;
                ruleLastAlert[dedupe] = now;
                var msg = $"[{rule.Name}] {c.Process} ({c.Exe}) on {c.AgentName}: {c.Direction} {c.Remote} ({c.Local})";
                recordings.SaveAlert(rule.Name, msg, c.AgentName, $"{c.Pid} {c.Unit} {c.Container}");
                _ = notifier.NotifyAsync($"NetGlass: {rule.Name}", msg);
            }
        }
    }

    try { await hub.Clients.All.SendAsync("connections", WithHosts(store.All(now))); } catch { }
    return Results.Ok(new { accepted = live.Count });
});

bool FrequencyTriggered(AlertRuleDto rule, ConnectionDto c, DateTime now)
{
    var key = $"{rule.Id}|{c.AgentId}|{c.Exe}|{c.Remote}";
    var hits = frequencyHits.GetOrAdd(key, _ => new List<DateTime>());
    lock (hits)
    {
        hits.Add(now);
        hits.RemoveAll(t => now - t > TimeSpan.FromMinutes(Math.Max(1, rule.WindowMinutes)));
        return hits.Count >= Math.Max(1, rule.Threshold);
    }
}

// ---- live view ----------------------------------------------------------
app.MapGet("/api/connections", (string? agent, string? direction) =>
{
    var all = WithHosts(store.All(DateTime.UtcNow));
    if (!string.IsNullOrWhiteSpace(agent)) all = all.Where(c => c.AgentId == agent).ToList();
    if (!string.IsNullOrWhiteSpace(direction)) all = all.Where(c => c.Direction == direction).ToList();
    return Results.Json(new { generated_at = DateTime.UtcNow, connections = all,
        counts = new
        {
            total = all.Count,
            outbound = all.Count(c => c.Direction == "outbound"),
            inbound = all.Count(c => c.Direction == "inbound"),
            listen = all.Count(c => c.Direction == "listen"),
            local = all.Count(c => c.Direction == "local"),
        }});
});

// ---- kill flow (PID-reuse protected on the agent side) ------------------
app.MapPost("/api/agents/{id}/kill", (string id, JsonElement body) =>
{
    if (!agents.ContainsKey(id)) return Results.NotFound();
    var killId = Guid.NewGuid().ToString("N");
    var pid = body.GetProperty("pid").GetInt32();
    var exe = body.TryGetProperty("exe", out var e) ? e.GetString() ?? "" : "";
    var started = body.TryGetProperty("started", out var s) && s.ValueKind != JsonValueKind.Null
        ? s.GetDateTime().ToString("O") : "";
    var reason = body.TryGetProperty("reason", out var r) ? r.GetString() ?? "" : "";
    using var conn = recordings.Open();
    conn.Execute("INSERT INTO kill_requests VALUES ($id, $a, $p, $x, $s, $r, $st, $t, $res)",
        ("$id", killId), ("$a", id), ("$p", pid), ("$x", exe), ("$s", started),
        ("$r", reason), ("$st", "pending"), ("$t", DateTime.UtcNow.ToString("O")), ("$res", ""));
    return Results.Json(new { killId, status = "pending" });
});

app.MapGet("/api/agents/{id}/kill-requests", (string id, HttpRequest req) =>
{
    var agent = AuthAgent(id, req);
    if (agent is null) return Results.Unauthorized();
    using var conn = recordings.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT id, pid, exe, started, reason FROM kill_requests WHERE agent_id = $a AND status = 'pending'";
    cmd.Parameters.AddWithValue("$a", id);
    using var reader = cmd.ExecuteReader();
    var list = new List<object>();
    while (reader.Read())
        list.Add(new { id = reader.GetString(0), pid = reader.GetInt32(1),
            exe = reader.GetString(2), started = reader.GetString(3), reason = reader.GetString(4) });
    return Results.Json(list);
});

app.MapPost("/api/agents/{id}/kill-result", (string id, JsonElement body, HttpRequest req) =>
{
    var agent = AuthAgent(id, req);
    if (agent is null) return Results.Unauthorized();
    var killId = body.GetProperty("killId").GetString() ?? "";
    var success = body.GetProperty("success").GetBoolean();
    var message = body.TryGetProperty("message", out var m) ? m.GetString() ?? "" : "";
    using var conn = recordings.Open();
    conn.Execute("UPDATE kill_requests SET status = $s, result = $r WHERE id = $id",
        ("$s", success ? "done" : "failed"), ("$r", message), ("$id", killId));
    return Results.Ok();
});

app.MapGet("/api/kill-requests/{killId}", (string killId) =>
{
    using var conn = recordings.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT status, result FROM kill_requests WHERE id = $id";
    cmd.Parameters.AddWithValue("$id", killId);
    using var reader = cmd.ExecuteReader();
    if (!reader.Read()) return Results.NotFound();
    return Results.Json(new { status = reader.GetString(0), result = reader.GetString(1) });
});

// ---- recordings ---------------------------------------------------------
app.MapPost("/api/recordings/start", (JsonElement body) =>
{
    var name = body.TryGetProperty("name", out var n) ? n.GetString() ?? "recording" : "recording";
    return Results.Json(recordings.StartRecording(name));
});
app.MapPost("/api/recordings/{id}/stop", (string id) =>
{
    recordings.EndRecording(id);
    return Results.Ok();
});
app.MapGet("/api/recordings", () => Results.Json(recordings.Recordings()));
app.MapGet("/api/recordings/{id}/events", (string id, int? limit) =>
    Results.Json(recordings.Events(id, limit ?? 1000)));
app.MapGet("/api/recordings/{id}/export", (string id) =>
{
    var events = recordings.Events(id, 100000);
    var csv = "seq,at,event_type,agent,direction,process,exe,local,remote\n" +
        string.Join("\n", events.Select(e =>
            $"{e.Seq},{e.At:O},{e.EventType},{e.AgentName},{e.Direction},{e.Process},{Csv(e.Exe)},{e.Local},{e.Remote}"));
    return Results.Text(csv, "text/csv");
});
string Csv(string s) => "\"" + s.Replace("\"", "\"\"") + "\"";

// ---- rules + settings ---------------------------------------------------
// Modular checks catalogue: every registered check, its category,
// engine, severity, score, description, and whether it can run
// here (threat-list checks report their missing list, etc.).
app.MapGet("/api/checks", () =>
{
    var list = NetGlass.Server.Checks.CheckEngine.All.Select(c => new
    {
        id = c.Id, title = c.Title, category = c.Category, engine = c.Engine,
        severity = c.Severity, score = c.Score, description = c.Description,
        enabled = checkEnabled.GetValueOrDefault(c.Id, true),
        unavailableReason = c.UnavailableReason,
    });
    return Results.Json(list);
});
app.MapPost("/api/checks/{id}/toggle", (string id, JsonElement body) =>
{
    if (!NetGlass.Server.Checks.CheckEngine.All.Any(c => c.Id == id)) return Results.NotFound();
    var enabled = body.TryGetProperty("enabled", out var e) ? e.GetBoolean() : !checkEnabled.GetValueOrDefault(id, true);
    checkEnabled[id] = enabled;
    recordings.SetSetting($"check_enabled:{id}", enabled ? "1" : "0");
    return Results.Json(new { id, enabled });
});
app.MapGet("/api/rules", () =>
{
    using var conn = recordings.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT id, name, type, pattern, threshold, window_minutes, enabled FROM rules";
    using var reader = cmd.ExecuteReader();
    var list = new List<AlertRuleDto>();
    while (reader.Read())
        list.Add(new AlertRuleDto(reader.GetString(0), reader.GetString(1), reader.GetString(2),
            reader.GetString(3), reader.GetInt32(4), reader.GetInt32(5), reader.GetInt32(6) == 1));
    return Results.Json(list);
});
app.MapPost("/api/rules", (JsonElement body) =>
{
    var id = Guid.NewGuid().ToString("N");
    var name = body.GetProperty("name").GetString() ?? "rule";
    var type = body.GetProperty("type").GetString() ?? "Pattern";
    var pattern = body.TryGetProperty("pattern", out var p) ? p.GetString() ?? "" : "";
    var threshold = body.TryGetProperty("threshold", out var t) ? t.GetInt32() : 1;
    var window = body.TryGetProperty("windowMinutes", out var w) ? w.GetInt32() : 10;
    using var conn = recordings.Open();
    conn.Execute("INSERT INTO rules VALUES ($id, $n, $t, $p, $th, $w, 1)",
        ("$id", id), ("$n", name), ("$t", type), ("$p", pattern), ("$th", threshold), ("$w", window));
    return Results.Json(new { id, name, type });
});
app.MapPost("/api/settings/linger", (JsonElement body) =>
{
    var seconds = body.GetProperty("seconds").GetInt32();
    store.LingerSeconds = Math.Clamp(seconds, 0, 3600);
    recordings.SetSetting("linger_seconds", store.LingerSeconds.ToString());
    return Results.Json(new { lingerSeconds = store.LingerSeconds });
});
app.MapPost("/api/settings/apprise", (JsonElement body) =>
{
    var urls = body.TryGetProperty("urls", out var u) ? u.GetString() ?? "" : "";
    var apiUrl = body.TryGetProperty("apiUrl", out var a) ? a.GetString() ?? "" : "";
    recordings.SetSetting("apprise_urls", urls);
    recordings.SetSetting("apprise_api_url", apiUrl);
    return Results.Json(new { saved = true });
});
app.MapGet("/api/alerts", () =>
{
    using var conn = recordings.Open();
    using var cmd = conn.CreateCommand();
    cmd.CommandText = "SELECT at, rule_name, message, agent_name, detail FROM alerts ORDER BY at DESC LIMIT 200";
    using var reader = cmd.ExecuteReader();
    var list = new List<object>();
    while (reader.Read())
        list.Add(new { at = reader.GetString(0), rule = reader.GetString(1),
            message = reader.GetString(2), agent = reader.GetString(3), detail = reader.GetString(4) });
    return Results.Json(list);
});

// ---- IP info (ip-api.com, ON DEMAND only) ------------------------------
// GET returns only what is already cached — it never calls ip-api.
// POST fetches from ip-api, caches for 30 days, and returns the result.
// Private/special IPs are never sent to ip-api. Free tier is 45/min
// over HTTP only, so this keeps a small in-memory window and stops at
// 40/min, leaving headroom. No API key is needed for the free tier.
var ipApiCalls = new List<DateTime>();
var ipApiGate = new object();

app.MapGet("/api/ip-info", (string? ip) =>
{
    if (string.IsNullOrWhiteSpace(ip) || !System.Net.IPAddress.TryParse(ip, out _))
        return Results.BadRequest(new { error = "Provide a valid ?ip=" });
    if (!IpHelpers.IsPublic(ip))
        return Results.Json(new { ip, isPublic = false, cached = false, message = "Private, loopback, or reserved IP — no public enrichment available." });
    var cached = recordings.GetIpInfo(ip);
    if (cached is null || cached.ExpiresAt <= DateTime.UtcNow)
        return Results.Json(new { ip, isPublic = true, cached = false });
    return Results.Json(cached);
});

app.MapPost("/api/ip-info", async (string? ip, bool? force) =>
{
    if (string.IsNullOrWhiteSpace(ip) || !System.Net.IPAddress.TryParse(ip, out _))
        return Results.BadRequest(new { error = "Provide a valid ?ip=" });
    if (!IpHelpers.IsPublic(ip))
        return Results.BadRequest(new { error = "Private, loopback, or reserved IP — no public enrichment available." });
    var now = DateTime.UtcNow;
    var cached = recordings.GetIpInfo(ip);
    if (force != true && cached is not null && cached.ExpiresAt > now)
        return Results.Json(cached);
    lock (ipApiGate)
    {
        ipApiCalls.RemoveAll(t => now - t > TimeSpan.FromMinutes(1));
        if (ipApiCalls.Count >= 40)
            return Results.Json(new { error = "ip-api.com free-tier rate limit reached (40/min guard). Try again in a minute — cached results are still available." }, statusCode: 429);
        ipApiCalls.Add(now);
    }
    // Free tier is HTTP only (HTTPS is a paid feature); this is public
    // IP metadata, not credentials or private traffic.
    var url = $"http://ip-api.com/json/{Uri.EscapeDataString(ip)}?fields=status,message,query,reverse,isp,org,as,country,countryCode,regionName,city,zip,timezone";
    try
    {
        using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        var resp = await http.GetAsync(url);
        if (!resp.IsSuccessStatusCode)
            return Results.Json(new { error = $"ip-api.com returned {(int)resp.StatusCode}." }, statusCode: 502);
        var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        Func<string, string> Str = name => root.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : "";
        if (Str("status") != "success")
            return Results.Json(new { error = $"ip-api.com: {Str("message")}" }, statusCode: 502);
        var info = new IpInfoDto(ip, Str("isp"), Str("org"), Str("as"), Str("country"),
            Str("countryCode"), Str("regionName"), Str("city"), Str("timezone"),
            Str("reverse"), now, now.AddDays(30), false);
        recordings.SetIpInfo(info);
        // ip-api's reverse field is a useful PTR fallback: fill the
        // hostname cache with it, so the table shows it too.
        if (!string.IsNullOrEmpty(info.Reverse))
            recordings.SetDns(ip, info.Reverse, "ip-api", now.AddHours(24));
        return Results.Json(info);
    }
    catch (Exception ex)
    {
        return Results.Json(new { error = $"ip-api.com lookup failed: {ex.Message}" }, statusCode: 502);
    }
});

app.MapHub<LiveHub>("/hubs/live");

var wwwroot = Path.Combine(AppContext.BaseDirectory, "wwwroot");
if (Directory.Exists(wwwroot))
{
    app.UseDefaultFiles();
    app.UseStaticFiles();
    app.MapFallbackToFile("index.html");
}
else
{
    app.MapGet("/", () => Results.Text(
        "NetGlass server is running. Build the React UI (web/) and copy its dist output to wwwroot, or run the web dev server against this API.",
        "text/plain"));
}

app.Run();

public sealed class LiveHub : Hub { }
