namespace NetGlass.Server.Checks;

/// <summary>Connection behavior indicators (user plan §4).
/// All use session starts recorded by CheckHistory: a session
/// starts when a connection key goes from absent to live. A
/// persistent connection that stays live is one session, not
/// a beacon — beaconing is repeated new sessions at regular
/// intervals. Thresholds are starting defaults, tunable in the
/// check classes (Score/Severity are per-check constants).</summary>
public sealed class BeaconingCheck : ICheck
{
    public string Id => "behavior.beaconing";
    public string Title => "Beaconing behavior";
    public string Category => "Behavior";
    public string Engine => "BehavioralAnalysis";
    public string Severity => "High";
    public int Score => 50;
    public string Description => "Repeated new sessions to the same destination at regular intervals.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction == "local" || c.Direction == "listen") return null;
        var rip = CheckHelpers.RemoteIp(c.Remote);
        if (string.IsNullOrEmpty(rip)) return null;
        var starts = ctx.History.SessionStarts(c.AgentId, c.Process, rip, TimeSpan.FromHours(6), ctx.Now);
        if (starts.Count < 5) return null;
        var intervals = new List<double>();
        for (var i = 1; i < starts.Count; i++) intervals.Add((starts[i] - starts[i - 1]).TotalSeconds);
        if (intervals.Count < 4) return null;
        var mean = intervals.Average();
        if (mean < 10 || mean > 3600) return null; // too fast to be a beacon, too slow to tell
        var variance = intervals.Select(x => (x - mean) * (x - mean)).Average();
        var std = Math.Sqrt(variance);
        var cv = mean > 0 ? std / mean : 1;
        if (cv > 0.25) return null; // intervals are irregular, not a beacon
        return CheckHelpers.Make(this,
            $"{c.Process} started {starts.Count} sessions to {rip} in the last 6h, about every {Math.Round(mean)}s (variation {Math.Round(cv * 100)}%).",
            "Regular intervals do not prove command-and-control — updaters and sync tools beacon too — but an unknown executable beaconing to a new destination at a fixed cadence is the classic pattern to investigate first. See the example in docs/CHECKS.md.");
    }
}

public sealed class RepeatedAttemptsCheck : ICheck
{
    public string Id => "behavior.repeated-attempts";
    public string Title => "Repeated connection attempts";
    public string Category => "Behavior";
    public string Engine => "BehavioralAnalysis";
    public string Severity => "Medium";
    public int Score => 30;
    public string Description => "Many new sessions to the same destination in a short window.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction == "local" || c.Direction == "listen") return null;
        var rip = CheckHelpers.RemoteIp(c.Remote);
        if (string.IsNullOrEmpty(rip)) return null;
        var starts = ctx.History.SessionStarts(c.AgentId, c.Process, rip, TimeSpan.FromMinutes(10), ctx.Now);
        if (starts.Count >= 10)
            return CheckHelpers.Make(this, $"{c.Process} started {starts.Count} sessions to {rip} in the last 10 minutes.",
                "Repeated attempts can be a retry loop, a failing service, or automated probing. If most sessions are short-lived and the destination is new, treat it as more concerning.");
        return null;
    }
}

public sealed class RapidDestinationChangesCheck : ICheck
{
    public string Id => "behavior.rapid-destinations";
    public string Title => "Rapid destination changes";
    public string Category => "Behavior";
    public string Engine => "BehavioralAnalysis";
    public string Severity => "Medium";
    public int Score => 35;
    public string Description => "Process contacted many distinct destinations in a short window.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction == "local") return null;
        var n = ctx.History.DistinctDestinations(c.AgentId, c.Process, TimeSpan.FromMinutes(10), ctx.Now);
        if (n >= 20)
            return CheckHelpers.Make(this, $"{c.Process} contacted {n} distinct destinations in the last 10 minutes.",
                "Browsers do this legitimately. For a non-browser process, many destinations in minutes is data collection, a scan, or a peer-to-peer / CDN pattern — check which destinations they are.");
        return null;
    }
}

public sealed class PortScanningCheck : ICheck
{
    public string Id => "behavior.port-scanning";
    public string Title => "Port scanning behavior";
    public string Category => "Behavior";
    public string Engine => "BehavioralAnalysis";
    public string Severity => "High";
    public int Score => 50;
    public string Description => "Process tried many ports on a single host in a short window.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction == "local") return null;
        var rip = CheckHelpers.RemoteIp(c.Remote);
        if (string.IsNullOrEmpty(rip)) return null;
        var n = ctx.History.DistinctPortsToHost(c.AgentId, c.Process, rip, TimeSpan.FromMinutes(10), ctx.Now);
        if (n >= 20)
            return CheckHelpers.Make(this, $"{c.Process} tried {n} distinct ports on {rip} in the last 10 minutes.",
                "Normal clients use one or two ports per host. Many ports per host is the signature of a port scan, whether from a scanner tool or from malware mapping a target.");
        return null;
    }
}

public sealed class HostScanningCheck : ICheck
{
    public string Id => "behavior.host-scanning";
    public string Title => "Network scanning behavior";
    public string Category => "Behavior";
    public string Engine => "BehavioralAnalysis";
    public string Severity => "High";
    public int Score => 50;
    public string Description => "Process contacted many distinct hosts in a short window.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction == "local") return null;
        var n = ctx.History.DistinctHosts(c.AgentId, c.Process, TimeSpan.FromMinutes(10), ctx.Now);
        if (n >= 20)
            return CheckHelpers.Make(this, $"{c.Process} contacted {n} distinct hosts in the last 10 minutes.",
                "Same signal as rapid destination changes, but framed as scanning: for a non-browser, non-updater process, many hosts in minutes is network mapping.");
        return null;
    }
}

public sealed class HighConnectionCountCheck : ICheck
{
    public string Id => "behavior.high-count";
    public string Title => "High connection count";
    public string Category => "Behavior";
    public string Engine => "BehavioralAnalysis";
    public string Severity => "Medium";
    public int Score => 25;
    public string Description => "Process suddenly holds many live sockets.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        var n = ctx.Live.Count(x => x.AgentId == c.AgentId && x.Exe == c.Exe);
        if (n >= 100)
            return CheckHelpers.Make(this, $"{c.Process} holds {n} live sockets on {c.AgentName}.",
                "Browsers and servers hold many sockets legitimately. The signal is a sudden jump for a process that normally holds a few — compare with its group count in the UI.");
        return null;
    }
}

public sealed class FrequentShortLivedCheck : ICheck
{
    public string Id => "behavior.short-lived";
    public string Title => "Frequent short-lived connections";
    public string Category => "Behavior";
    public string Engine => "BehavioralAnalysis";
    public string Severity => "Low";
    public int Score => 15;
    public string Description => "Many sessions for one process in a short window (see RepeatedAttempts for same-destination).";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction == "local") return null;
        var n = ctx.History.SessionsForProcess(c.AgentId, c.Process, TimeSpan.FromMinutes(10), ctx.Now);
        if (n >= 30)
            return CheckHelpers.Make(this, $"{c.Process} started {n} sessions in the last 10 minutes.",
                "Frequent short-lived connections can be automated communication, polling, or data collection. It is Low on its own because polling apps do this by design.");
        return null;
    }
}

public sealed class OffHoursCheck : ICheck
{
    public string Id => "behavior.off-hours";
    public string Title => "Connection outside normal hours";
    public string Category => "Behavior";
    public string Engine => "BehavioralAnalysis";
    public string Severity => "Low";
    public int Score => 15;
    public string Description => "Process connecting in an hour it has rarely or never used before (requires >=20 prior sessions in this run).";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction == "local" || string.IsNullOrEmpty(c.Exe)) return null;
        var (total, thisHour) = ctx.History.HourStats(c.AgentId, c.Exe, ctx.Now);
        if (total < 20) return null; // not enough history to call an hour unusual
        if (thisHour == 0)
            return CheckHelpers.Make(this, $"{c.Process} is connecting at hour {ctx.Now.Hour:00}:00, an hour it has never used in {total} prior sessions in this run.",
                "Off-hours alone is weak — schedules change, timezones shift. It matters when a normally daytime-only process appears at night with other signals.");
        return null;
    }
}

public sealed class LongDurationCheck : ICheck
{
    public string Id => "behavior.long-duration";
    public string Title => "Unusual connection duration";
    public string Category => "Behavior";
    public string Engine => "BehavioralAnalysis";
    public string Severity => "Low";
    public int Score => 10;
    public string Description => "Connection has been live for over 24 hours (server first-seen, not process start).";
    public string? UnavailableReason => "Without byte counts, duration alone cannot distinguish a legitimate long-lived session (SSH, VPN, sync) from exfiltration. This is informational only.";
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.IsGhost) return null;
        var duration = ctx.Now - c.FirstSeen;
        if (duration > TimeSpan.FromHours(24))
            return CheckHelpers.Make(this, $"Connection live for {Math.Round(duration.TotalHours)}h (first seen {c.FirstSeen:yyyy-MM-dd HH:mm} UTC).",
                "Long-lived is normal for SSH, VPN, and sync clients. It is listed so a connection that should have been short-lived stands out when you sort by score.");
        return null;
    }
}
