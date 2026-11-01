using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text;
using Microsoft.Data.Sqlite;

namespace NetGlass.Server;

/// <summary>
/// Live connection store with ghost/linger semantics.
/// A row is live if it appeared in the agent's latest snapshot,
/// ghost if it disappeared within the linger window, expired after that.
/// </summary>
public sealed class ConnectionStore
{
    private sealed class Entry
    {
        public required ConnectionDto Conn;
        public bool Live;
    }

    private readonly ConcurrentDictionary<string, Entry> _entries = new();
    public int LingerSeconds { get; set; } = 30;

    public static string Key(string agentId, SnapshotConnection c) =>
        $"{agentId}|{c.Proto}|{c.Direction}|{c.Exe}|{c.Local}|{c.Remote}";

    public static string KeyOf(ConnectionDto c) =>
        $"{c.AgentId}|{c.Proto}|{c.Direction}|{c.Exe}|{c.Local}|{c.Remote}";

    public (List<ConnectionDto> Live, List<string> ClosedKeys) Ingest(
        AgentInfo agent, SnapshotRequest snapshot, DateTime now,
        Func<string, DateTime, bool> isNew)
    {
        var seenKeys = new HashSet<string>();
        var live = new List<ConnectionDto>();
        foreach (var c in snapshot.Connections)
        {
            var key = Key(agent.Id, c);
            seenKeys.Add(key);
            var flags = new List<string>();
            if (isNew(key, now)) flags.Add("NEW");
            if (c.Direction == "listen") flags.Add("LISTENER");
            if (c.Exe.StartsWith("/tmp/") || c.Exe.StartsWith("/dev/shm/") || c.Exe.StartsWith("/var/tmp/"))
                flags.Add("TMP_EXE");
            if (c.Exe.EndsWith(" (deleted)")) flags.Add("DELETED_EXE");
            var suspicious = flags.Contains("TMP_EXE") || flags.Contains("DELETED_EXE");
            var dto = new ConnectionDto(
                agent.Id, agent.Name, c.Direction, c.Proto, c.State,
                c.Local, c.Remote, "", c.Pid, c.Process, c.Exe, c.Cmdline, c.User,
                c.Ppid, c.Parent, c.ParentExe, c.Unit, c.Container, c.ContainerId,
                c.Started, now, now, false, flags.Contains("NEW"), suspicious,
                flags.ToArray(), c.Detail ?? "");
            if (_entries.TryGetValue(key, out var existing))
            {
                dto = existing.Conn with
                {
                    LastSeen = now, IsGhost = false, State = c.State,
                    Pid = c.Pid, Process = c.Process, Cmdline = c.Cmdline,
                    Detail = string.IsNullOrEmpty(c.Detail) ? existing.Conn.Detail : c.Detail,
                };
                existing.Conn = dto;
                existing.Live = true;
            }
            else
            {
                _entries[key] = new Entry { Conn = dto, Live = true };
            }
            live.Add(dto);
        }

        var closed = new List<string>();
        foreach (var (key, entry) in _entries)
        {
            if (entry.Conn.AgentId != agent.Id) continue;
            if (seenKeys.Contains(key)) continue;
            if (entry.Live)
            {
                entry.Live = false;
                entry.Conn = entry.Conn with { IsGhost = true };
                closed.Add(key);
            }
        }
        return (live, closed);
    }

    // Delete an agent's live/ghost rows. Recordings and alerts are
    // history and are kept; they store only the agent name, not the id.
    public void RemoveAgent(string agentId)
    {
        foreach (var (key, entry) in _entries)
            if (entry.Conn.AgentId == agentId)
                _entries.TryRemove(key, out _);
    }

    public List<ConnectionDto> All(DateTime now)
    {
        var cutoff = now.AddSeconds(-LingerSeconds);
        var result = new List<ConnectionDto>();
        foreach (var (key, entry) in _entries)
        {
            if (!entry.Live && entry.Conn.LastSeen < cutoff)
            {
                _entries.TryRemove(key, out _);
                continue;
            }
            result.Add(entry.Conn);
        }
        result.Sort((a, b) =>
        {
            var order = new Dictionary<string, int>
                { ["listen"] = 0, ["outbound"] = 1, ["inbound"] = 2, ["local"] = 3 };
            var oa = order.GetValueOrDefault(a.Direction, 9);
            var ob = order.GetValueOrDefault(b.Direction, 9);
            return oa != ob ? oa.CompareTo(ob)
                : string.Compare(a.Process, b.Process, StringComparison.OrdinalIgnoreCase);
        });
        return result;
    }
}

public sealed class RecordingStore
{
    private readonly string _path;
    private readonly object _gate = new();

    public RecordingStore(string path)
    {
        _path = path;
        using var conn = Open();
        conn.Execute(@"
            CREATE TABLE IF NOT EXISTS agents(id TEXT PRIMARY KEY, name TEXT, hostname TEXT, os TEXT, version TEXT, token TEXT, last_seen TEXT);
            CREATE TABLE IF NOT EXISTS recordings(id TEXT PRIMARY KEY, name TEXT, started_at TEXT, ended_at TEXT);
            CREATE TABLE IF NOT EXISTS recording_events(id INTEGER PRIMARY KEY AUTOINCREMENT, recording_id TEXT, seq INTEGER, at TEXT, event_type TEXT, agent_name TEXT, direction TEXT, process TEXT, exe TEXT, local TEXT, remote TEXT);
            CREATE TABLE IF NOT EXISTS alerts(id TEXT PRIMARY KEY, at TEXT, rule_name TEXT, message TEXT, agent_name TEXT, detail TEXT);
            CREATE TABLE IF NOT EXISTS rules(id TEXT PRIMARY KEY, name TEXT, type TEXT, pattern TEXT, threshold INTEGER, window_minutes INTEGER, enabled INTEGER);
            CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE IF NOT EXISTS kill_requests(id TEXT PRIMARY KEY, agent_id TEXT, pid INTEGER, exe TEXT, started TEXT, reason TEXT, status TEXT, created_at TEXT, result TEXT);
            CREATE TABLE IF NOT EXISTS seen_keys(key TEXT PRIMARY KEY, first_seen TEXT);
            CREATE TABLE IF NOT EXISTS dns_cache(ip TEXT PRIMARY KEY, hostname TEXT, source TEXT, resolved_at TEXT, expires_at TEXT);
            CREATE TABLE IF NOT EXISTS ip_info_cache(ip TEXT PRIMARY KEY, isp TEXT, org TEXT, asn TEXT, country TEXT, country_code TEXT, region TEXT, city TEXT, timezone TEXT, reverse TEXT, fetched_at TEXT, expires_at TEXT);");
    }

    public SqliteConnection Open()
    {
        var conn = new SqliteConnection($"Data Source={_path}");
        conn.Open();
        return conn;
    }

    public bool IsNewKey(string key, DateTime now)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT first_seen FROM seen_keys WHERE key = $k";
            cmd.Parameters.AddWithValue("$k", key);
            var existing = cmd.ExecuteScalar() as string;
            if (existing is not null) return DateTime.Parse(existing).AddHours(24) > now;
            using var ins = conn.CreateCommand();
            ins.CommandText = "INSERT INTO seen_keys VALUES ($k, $t)";
            ins.Parameters.AddWithValue("$k", key);
            ins.Parameters.AddWithValue("$t", now.ToString("O"));
            ins.ExecuteNonQuery();
            return true;
        }
    }

    public string? CurrentRecordingId()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id FROM recordings WHERE ended_at IS NULL ORDER BY started_at DESC LIMIT 1";
        return cmd.ExecuteScalar() as string;
    }

    public RecordingDto StartRecording(string name)
    {
        var id = Guid.NewGuid().ToString("N");
        var now = DateTime.UtcNow;
        using var conn = Open();
        conn.Execute("INSERT INTO recordings VALUES ($id, $n, $s, NULL)",
            ("$id", id), ("$n", name), ("$s", now.ToString("O")));
        return new RecordingDto(id, name, now, null, 0);
    }

    public void EndRecording(string id)
    {
        using var conn = Open();
        conn.Execute("UPDATE recordings SET ended_at = $t WHERE id = $id",
            ("$t", DateTime.UtcNow.ToString("O")), ("$id", id));
    }

    public void AppendEvent(string recordingId, string eventType, ConnectionDto c, DateTime now)
    {
        lock (_gate)
        {
            using var conn = Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "SELECT COALESCE(MAX(seq), 0) + 1 FROM recording_events WHERE recording_id = $r";
            cmd.Parameters.AddWithValue("$r", recordingId);
            var seq = Convert.ToInt64(cmd.ExecuteScalar());
            conn.Execute(@"INSERT INTO recording_events
                (recording_id, seq, at, event_type, agent_name, direction, process, exe, local, remote)
                VALUES ($r, $s, $t, $e, $a, $d, $p, $x, $l, $m)",
                ("$r", recordingId), ("$s", seq), ("$t", now.ToString("O")),
                ("$e", eventType), ("$a", c.AgentName), ("$d", c.Direction),
                ("$p", c.Process), ("$x", c.Exe), ("$l", c.Local), ("$m", c.Remote));
        }
    }

    public List<RecordingDto> Recordings()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"SELECT r.id, r.name, r.started_at, r.ended_at,
            (SELECT COUNT(*) FROM recording_events e WHERE e.recording_id = r.id)
            FROM recordings r ORDER BY r.started_at DESC";
        using var reader = cmd.ExecuteReader();
        var list = new List<RecordingDto>();
        while (reader.Read())
        {
            list.Add(new RecordingDto(
                reader.GetString(0), reader.GetString(1),
                DateTime.Parse(reader.GetString(2)),
                reader.IsDBNull(3) ? null : DateTime.Parse(reader.GetString(3)),
                reader.GetInt32(4)));
        }
        return list;
    }

    public List<RecordingEventDto> Events(string recordingId, int limit = 1000)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"SELECT seq, at, event_type, agent_name, direction, process, exe, local, remote
            FROM recording_events WHERE recording_id = $r ORDER BY seq LIMIT $l";
        cmd.Parameters.AddWithValue("$r", recordingId);
        cmd.Parameters.AddWithValue("$l", limit);
        using var reader = cmd.ExecuteReader();
        var list = new List<RecordingEventDto>();
        while (reader.Read())
        {
            list.Add(new RecordingEventDto(reader.GetInt64(0), DateTime.Parse(reader.GetString(1)),
                reader.GetString(2), reader.GetString(3), reader.GetString(4),
                reader.GetString(5), reader.GetString(6), reader.GetString(7), reader.GetString(8)));
        }
        return list;
    }

    public void SaveAlert(string ruleName, string message, string agentName, string detail)
    {
        using var conn = Open();
        conn.Execute("INSERT INTO alerts VALUES ($id, $t, $r, $m, $a, $d)",
            ("$id", Guid.NewGuid().ToString("N")), ("$t", DateTime.UtcNow.ToString("O")),
            ("$r", ruleName), ("$m", message), ("$a", agentName), ("$d", detail));
    }

    public string? GetSetting(string key)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT value FROM settings WHERE key = $k";
        cmd.Parameters.AddWithValue("$k", key);
        return cmd.ExecuteScalar() as string;
    }

    public void SetSetting(string key, string value)
    {
        using var conn = Open();
        conn.Execute("INSERT INTO settings VALUES ($k, $v) ON CONFLICT(key) DO UPDATE SET value = $v",
            ("$k", key), ("$v", value));
    }

    // ---- DNS / IP-info cache -------------------------------------------
    // dns_cache.hostname may be "" for a negative (no PTR) entry; the
    // caller distinguishes that from "no entry" by the expires_at check.
    public (string Hostname, DateTime ExpiresAt)? GetDns(string ip)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT hostname, expires_at FROM dns_cache WHERE ip = $ip";
        cmd.Parameters.AddWithValue("$ip", ip);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        return (reader.GetString(0), DateTime.Parse(reader.GetString(1)));
    }

    public void SetDns(string ip, string hostname, string source, DateTime expiresAt)
    {
        using var conn = Open();
        conn.Execute(@"INSERT INTO dns_cache VALUES ($ip, $h, $s, $r, $e)
            ON CONFLICT(ip) DO UPDATE SET hostname = $h, source = $s, resolved_at = $r, expires_at = $e",
            ("$ip", ip), ("$h", hostname), ("$s", source),
            ("$r", DateTime.UtcNow.ToString("O")), ("$e", expiresAt.ToString("O")));
    }

    public IpInfoDto? GetIpInfo(string ip)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = @"SELECT isp, org, asn, country, country_code, region, city,
            timezone, reverse, fetched_at, expires_at FROM ip_info_cache WHERE ip = $ip";
        cmd.Parameters.AddWithValue("$ip", ip);
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) return null;
        return new IpInfoDto(ip, reader.GetString(0), reader.GetString(1), reader.GetString(2),
            reader.GetString(3), reader.GetString(4), reader.GetString(5), reader.GetString(6),
            reader.GetString(7), reader.GetString(8), DateTime.Parse(reader.GetString(9)),
            DateTime.Parse(reader.GetString(10)), true);
    }

    public void SetIpInfo(IpInfoDto info)
    {
        using var conn = Open();
        conn.Execute(@"INSERT INTO ip_info_cache VALUES
            ($ip, $isp, $org, $asn, $c, $cc, $r, $city, $tz, $rev, $f, $e)
            ON CONFLICT(ip) DO UPDATE SET isp = $isp, org = $org, asn = $asn,
            country = $c, country_code = $cc, region = $r, city = $city,
            timezone = $tz, reverse = $rev, fetched_at = $f, expires_at = $e",
            ("$ip", info.Ip), ("$isp", info.Isp), ("$org", info.Org), ("$asn", info.As),
            ("$c", info.Country), ("$cc", info.CountryCode), ("$r", info.Region),
            ("$city", info.City), ("$tz", info.Timezone), ("$rev", info.Reverse),
            ("$f", info.FetchedAt.ToString("O")), ("$e", info.ExpiresAt.ToString("O")));
    }
}

internal static class SqliteExtensions
{
    public static void Execute(this SqliteConnection conn, string sql, params (string, object?)[] parameters)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (name, value) in parameters)
            cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        cmd.ExecuteNonQuery();
    }
}

/// <summary>
/// Apprise delivery: prefer the `apprise` CLI when present, otherwise
/// POST to an Apprise API server. URLs are never logged.
/// </summary>
public sealed class AppriseNotifier
{
    private readonly RecordingStore _store;
    public AppriseNotifier(RecordingStore store) => _store = store;

    public async Task NotifyAsync(string title, string body)
    {
        var urls = _store.GetSetting("apprise_urls");
        var apiUrl = _store.GetSetting("apprise_api_url")
            ?? Environment.GetEnvironmentVariable("APPRISE_API_URL");
        try
        {
            if (!string.IsNullOrWhiteSpace(apiUrl))
            {
                using var http = new HttpClient();
                var payload = new { urls = urls, title, body };
                await http.PostAsync(apiUrl,
                    new StringContent(System.Text.Json.JsonSerializer.Serialize(payload),
                        Encoding.UTF8, "application/json"));
                return;
            }
            if (string.IsNullOrWhiteSpace(urls)) return;
            var start = new ProcessStartInfo("apprise", $"-t {Quote(title)} -b {Quote(body)} {urls}")
            {
                RedirectStandardOutput = true, RedirectStandardError = true,
                UseShellExecute = false,
            };
            using var proc = Process.Start(start);
            if (proc is not null) await proc.WaitForExitAsync();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[apprise] delivery failed: {ex.Message}");
        }
    }

    private static string Quote(string s) => "\"" + s.Replace("\"", "\\\"") + "\"";
}

public static class ComposeGenerator
{
    public static string ForAgent(string agentId, string agentName, string token, string serverUrl, string image)
    {
        var url = serverUrl.TrimEnd('/');
        return $"""
            # NetGlass agent for {agentName} — generated by the NetGlass server.
            # Run on the host you want to monitor: docker compose up -d
            # Do NOT commit this file to a public repo: it contains an agent token.
            services:
              netglass-agent:
                image: {image}
                container_name: netglass-agent
                restart: unless-stopped
                pid: host
                cap_add:
                  - SYS_PTRACE
                # Docker's default AppArmor profile can block reading
                # other processes' /proc/<pid>/fd and /proc/<pid>/net,
                # which is exactly what the agent does. Without this,
                # host and container processes silently show as (unknown).
                security_opt:
                  - apparmor:unconfined
                environment:
                  - NETGLASS_SERVER={url}
                  - NETGLASS_TOKEN={token}
                  - NETGLASS_AGENT_ID={agentId}
                  - NETGLASS_NAME={agentName}
                  - NETGLASS_INTERVAL=2
                volumes:
                  - /proc:/host/proc:ro
                  - /var/run/docker.sock:/var/run/docker.sock:ro
            """;
    }
}
