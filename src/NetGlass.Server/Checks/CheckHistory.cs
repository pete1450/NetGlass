namespace NetGlass.Server.Checks;

/// <summary>
/// Rolling, in-memory history for behavior checks. This is NOT the
/// baseline store (first-ever, persisted in SQLite via
/// RecordingStore.IsFirstEver). History holds only recent windows:
/// session starts (a connection key going from absent to live),
/// per-process hour counts, and last-exe-per-PID for PID-reuse.
/// It resets on server restart, which is safe by design: behavior
/// checks require a minimum number of events in the current run
/// before they fire, so a restart causes a learning period, not
/// a burst of false positives.
/// </summary>
public sealed class CheckHistory
{
    private sealed record Session(DateTime At, string AgentId, string Process, string Exe,
        string Direction, string RemoteIp, int RemotePort, string LocalIp, int LocalPort);

    private readonly object _gate = new();
    private readonly List<Session> _sessions = new();
    private readonly Dictionary<string, int[]> _hours = new(); // process key -> 24 hour counts
    private readonly Dictionary<string, (string Exe, DateTime At)> _pidExe = new();

    public void Record(IReadOnlyList<ConnectionDto> live, IReadOnlySet<string> previousLiveKeys, DateTime now)
    {
        lock (_gate)
        {
            foreach (var c in live)
            {
                var key = ConnectionStore.KeyOf(c);
                if (previousLiveKeys.Contains(key)) continue; // still live, not a new session
                var rip = CheckHelpers.RemoteIp(c.Remote);
                var lip = CheckHelpers.LocalIp(c.Local);
                _sessions.Add(new Session(now, c.AgentId, c.Process, c.Exe, c.Direction,
                    rip, CheckHelpers.RemotePort(c.Remote), lip, CheckHelpers.LocalPort(c.Local)));
                var hkey = $"{c.AgentId}|{c.Exe}";
                if (!_hours.TryGetValue(hkey, out var hours)) { hours = new int[24]; _hours[hkey] = hours; }
                hours[now.Hour]++;
                // NOTE: _pidExe is managed only by CheckPidReuse
                // (atomic compare-and-update). Updating it here on
                // session starts would erase the previous exe before
                // the PID-reuse check could see it.
            }
            // Prune sessions older than 24h; behavior windows are <= 1h,
            // off-hours uses the hour histogram, not raw sessions.
            _sessions.RemoveAll(s => now - s.At > TimeSpan.FromHours(24));
        }
    }

    public IReadOnlyList<DateTime> SessionStarts(string agentId, string process, string remoteIp, TimeSpan window, DateTime now)
    {
        lock (_gate)
            return _sessions.Where(s => s.AgentId == agentId && s.Process == process &&
                s.RemoteIp == remoteIp && now - s.At <= window).Select(s => s.At).ToList();
    }

    public int DistinctDestinations(string agentId, string process, TimeSpan window, DateTime now)
    {
        lock (_gate)
            return _sessions.Where(s => s.AgentId == agentId && s.Process == process &&
                now - s.At <= window).Select(s => s.RemoteIp).Distinct().Count();
    }

    public int DistinctPortsToHost(string agentId, string process, string remoteIp, TimeSpan window, DateTime now)
    {
        lock (_gate)
            return _sessions.Where(s => s.AgentId == agentId && s.Process == process &&
                s.RemoteIp == remoteIp && now - s.At <= window).Select(s => s.RemotePort).Distinct().Count();
    }

    public int DistinctHosts(string agentId, string process, TimeSpan window, DateTime now)
    {
        lock (_gate)
            return _sessions.Where(s => s.AgentId == agentId && s.Process == process &&
                now - s.At <= window).Select(s => s.RemoteIp).Distinct().Count();
    }

    public int SessionsForProcess(string agentId, string process, TimeSpan window, DateTime now)
    {
        lock (_gate)
            return _sessions.Count(s => s.AgentId == agentId && s.Process == process && now - s.At <= window);
    }

    public int DistinctRemotePorts(string agentId, string process, TimeSpan window, DateTime now)
    {
        lock (_gate)
            return _sessions.Where(s => s.AgentId == agentId && s.Process == process &&
                now - s.At <= window).Select(s => s.RemotePort).Distinct().Count();
    }

    public (int Total, int ThisHour) HourStats(string agentId, string exe, DateTime now)
    {
        lock (_gate)
        {
            if (!_hours.TryGetValue($"{agentId}|{exe}", out var hours)) return (0, 0);
            return (hours.Sum(), hours[now.Hour]);
        }
    }

    /// <summary>
    /// PID-reuse detection, atomic: returns the previous exe if this
    /// PID mapped to a different exe within the last 10 minutes,
    /// then updates the mapping to the current exe. First sighting
    /// of a PID returns null (no previous exe to compare with).
    /// </summary>
    public string? CheckPidReuse(string agentId, int pid, string exe, DateTime now)
    {
        lock (_gate)
        {
            var key = $"{agentId}|{pid}";
            string? prev = null;
            if (_pidExe.TryGetValue(key, out var v) && now - v.At <= TimeSpan.FromMinutes(10) &&
                !string.Equals(v.Exe, exe, StringComparison.Ordinal))
                prev = v.Exe;
            _pidExe[key] = (exe, now);
            return prev;
        }
    }

    public string? PreviousExeForPid(string agentId, int pid, DateTime now)
    {
        lock (_gate)
        {
            if (!_pidExe.TryGetValue($"{agentId}|{pid}", out var v)) return null;
            return now - v.At <= TimeSpan.FromMinutes(10) ? v.Exe : null;
        }
    }

    /// <summary>Record a PID->exe mapping without creating a session (used for PID-reuse detection).</summary>
    public void NotePidExe(string agentId, int pid, string exe, DateTime now)
    {
        lock (_gate) _pidExe[$"{agentId}|{pid}"] = (exe, now);
    }
}
