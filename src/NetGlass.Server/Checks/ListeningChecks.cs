namespace NetGlass.Server.Checks;

/// <summary>Listening socket indicators (user plan §5) and
/// ghost/orphan indicators (§6). Listening is ExposureAnalysis:
/// the question is not "is this process bad?" but "is this host
/// exposing something it should not?"</summary>
public sealed class NewListenerCheck : ICheck
{
    public string Id => "listen.new";
    public string Title => "New listening socket";
    public string Category => "Listening";
    public string Engine => "ExposureAnalysis";
    public string Severity => "Medium";
    public int Score => 25;
    public string Description => "Process listening on a socket it has never listened on here before.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction != "listen" || string.IsNullOrEmpty(c.Exe)) return null;
        if (ctx.IsFirstEver($"listen-new:{c.AgentId}|{c.Exe}|{c.Local}"))
            return CheckHelpers.Make(this, $"{c.Process} is listening on {c.Local} for the first time here.",
                "A new listener is how a backdoor or an accidentally exposed service first appears. Check whether this service was meant to listen, and on which interface.");
        return null;
    }
}

public sealed class PublicListenerCheck : ICheck
{
    public string Id => "listen.public";
    public string Title => "Listening on all interfaces";
    public string Category => "Listening";
    public string Engine => "ExposureAnalysis";
    public string Severity => "Medium";
    public int Score => 30;
    public string Description => "Listener bound to 0.0.0.0 or :: instead of localhost.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction != "listen") return null;
        var lip = CheckHelpers.LocalIp(c.Local);
        if (lip == "0.0.0.0" || lip == "::")
            return CheckHelpers.Make(this, $"{c.Process} listening on {c.Local} — reachable from any interface.",
                "Localhost-only listeners are only reachable on the machine itself. All-interfaces listeners are reachable from the LAN (and, if the host is forwarded, from beyond it).");
        return null;
    }
}

public sealed class UnexpectedListenerProcessCheck : ICheck
{
    public string Id => "listen.unexpected-process";
    public string Title => "Unexpected process opening a listening socket";
    public string Category => "Listening";
    public string Engine => "ExposureAnalysis";
    public string Severity => "Medium";
    public int Score => 30;
    public string Description => "A shell, interpreter, or unknown process is listening.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction != "listen") return null;
        var stem = CheckHelpers.BaseName(c.Exe);
        if (stem.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) stem = stem[..^4];
        if (Providers.Interpreters.Any(i => string.Equals(stem, i, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(c.Process, i, StringComparison.OrdinalIgnoreCase)) ||
            string.IsNullOrEmpty(c.Exe) || c.Process == "(unknown)")
            return CheckHelpers.Make(this, $"{c.Process} ({c.Exe}) is listening on {c.Local}.",
                "Servers listen. Shells and interpreters listening — especially on a high port, like the 0.0.0.0:4444 example in the plan — is a classic reverse-shell / backdoor pattern.");
        return null;
    }
}

public sealed class ManyListenersCheck : ICheck
{
    public string Id => "listen.many";
    public string Title => "Multiple listeners on unusual ports";
    public string Category => "Listening";
    public string Engine => "ExposureAnalysis";
    public string Severity => "Low";
    public int Score => 15;
    public string Description => "One process holding many listening sockets.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction != "listen") return null;
        var n = ctx.Live.Count(x => x.AgentId == c.AgentId && x.Exe == c.Exe && x.Direction == "listen");
        if (n >= 5)
            return CheckHelpers.Make(this, $"{c.Process} holds {n} listening sockets on {c.AgentName}.",
                "A web server with several listeners is normal. A desktop app or script with many listeners is not — check what ports they are.");
        return null;
    }
}

public sealed class GhostDeletedExeCheck : ICheck
{
    public string Id => "ghost.deleted-exe";
    public string Title => "Ghost with deleted executable";
    public string Category => "Ghost";
    public string Engine => "ExposureAnalysis";
    public string Severity => "Medium";
    public int Score => 30;
    public string Description => "Closed (ghost) connection whose executable was deleted while running.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (!c.IsGhost) return null;
        if (c.Exe.EndsWith(" (deleted)", StringComparison.Ordinal))
            return CheckHelpers.Make(this, $"Ghost connection from deleted executable {c.Exe}.",
                "Ghosts are normal — they are just recently-closed connections kept visible. A ghost from a deleted binary is not normal: the process removed its own evidence and then closed.");
        return null;
    }
}

public sealed class GhostUnknownCheck : ICheck
{
    public string Id => "ghost.unknown";
    public string Title => "Ghost with incomplete process information";
    public string Category => "Ghost";
    public string Engine => "ExposureAnalysis";
    public string Severity => "Low";
    public int Score => 15;
    public string Description => "Closed connection that could not be attributed to a process.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (!c.IsGhost) return null;
        if (string.IsNullOrEmpty(c.Exe) || c.Process == "(unknown)")
            return CheckHelpers.Make(this, $"Ghost connection with no process attribution ({c.Local} → {c.Remote}).",
                "This can be an agent permissions gap (the agent could not read that process's fd table) or a process that exited before attribution. If it recurs for the same destination, check the agent's privileges.");
        return null;
    }
}

public sealed class PidReuseCheck : ICheck
{
    public string Id => "ghost.pid-reuse";
    public string Title => "PID reused with a different executable";
    public string Category => "Ghost";
    public string Engine => "ExposureAnalysis";
    public string Severity => "Medium";
    public int Score => 30;
    public string Description => "Same PID on the same host now maps to a different executable within 10 minutes.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Pid is null || string.IsNullOrEmpty(c.Exe)) return null;
        var prev = ctx.History.CheckPidReuse(c.AgentId, c.Pid.Value, c.Exe, ctx.Now);
        if (prev is not null)
            return CheckHelpers.Make(this, $"PID {c.Pid} on {c.AgentName} changed from {prev} to {c.Exe}.",
                "PID reuse is normal over long periods, but a PID changing executables within minutes — especially while a connection is still attributed to it — can mean attribution is wrong, or a process replaced another.");
        return null;
    }
}
