namespace NetGlass.Server.Checks;

/// <summary>Port and protocol indicators (user plan §3).
/// Deliberately conservative: a port alone is rarely suspicious.
/// Admin/database ports score low on their own and high only when
/// combined with other findings (score sum) or public exposure.</summary>
public sealed class UnusualOutboundPortCheck : ICheck
{
    public string Id => "port.unusual-outbound";
    public string Title => "Unusual outbound port";
    public string Category => "PortProtocol";
    public string Engine => "ThreatIndicators";
    public string Severity => "Low";
    public int Score => 10;
    public string Description => "Outbound to a port that is not in the well-known list, for a process with no baseline for it.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction != "outbound") return null;
        var port = CheckHelpers.RemotePort(c.Remote);
        if (port == 0 || Providers.WellKnownPorts.Contains(port)) return null;
        // Only fire if this process+port is new for this host (baseline),
        // otherwise every high-port service would fire forever.
        if (ctx.IsFirstEver($"proc-port:{c.AgentId}|{c.Exe}|{port}"))
            return CheckHelpers.Make(this, $"Outbound to port {port} ({c.Remote}) — first time this process uses it here.",
                "High ports are normal for many services (ephemeral, custom apps, games). This fires only the first time a process uses that port on this host.");
        return null;
    }
}

public sealed class AdminPortCheck : ICheck
{
    public string Id => "port.admin";
    public string Title => "Remote administration port";
    public string Category => "PortProtocol";
    public string Engine => "ThreatIndicators";
    public string Severity => "Low";
    public int Score => 10;
    public string Description => "Connection to/from RDP, SSH, VNC, or WinRM ports.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction == "local") return null;
        var port = CheckHelpers.RemotePort(c.Remote);
        if (c.Direction == "listen") port = CheckHelpers.LocalPort(c.Local);
        if (!Providers.AdminPorts.Contains(port)) return null;
        return CheckHelpers.Make(this, $"Administration port {port} ({c.Remote} / {c.Local}).",
            "SSH on 22 is perfectly normal if this machine is an SSH client. This is Low on its own — it matters if the process, host, or direction is unexpected for this machine.");
    }
}

public sealed class DatabasePortExposedCheck : ICheck
{
    public string Id => "port.db-exposed";
    public string Title => "Database port exposed";
    public string Category => "PortProtocol";
    public string Engine => "ExposureAnalysis";
    public string Severity => "High";
    public int Score => 50;
    public string Description => "Listening on a database port on a public interface.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction != "listen") return null;
        var port = CheckHelpers.LocalPort(c.Local);
        if (!Providers.DatabasePorts.Contains(port)) return null;
        var lip = CheckHelpers.LocalIp(c.Local);
        if (lip != "0.0.0.0" && lip != "::" && !string.IsNullOrEmpty(lip)) return null;
        return CheckHelpers.Make(this, $"Database port {port} listening on all interfaces ({c.Local}) by {c.Process}.",
            "A database that accepts connections from any interface is exposed to the whole network. If this was meant to be localhost-only, this is the finding to act on first.");
    }
}

public sealed class DatabasePortOutboundCheck : ICheck
{
    public string Id => "port.db-outbound";
    public string Title => "Database port (outbound client)";
    public string Category => "PortProtocol";
    public string Engine => "ThreatIndicators";
    public string Severity => "Low";
    public int Score => 5;
    public string Description => "Outbound to a database port — normal for a DB client.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction != "outbound") return null;
        var port = CheckHelpers.RemotePort(c.Remote);
        if (!Providers.DatabasePorts.Contains(port)) return null;
        return CheckHelpers.Make(this, $"Outbound to database port {port} ({c.Remote}).",
            "Normal for database clients. Low score on its own; it adds context if the process is unknown or the destination is new.");
    }
}

public sealed class UnusualHighPortListenCheck : ICheck
{
    public string Id => "port.high-listen";
    public string Title => "Unusual high listening port";
    public string Category => "PortProtocol";
    public string Engine => "ExposureAnalysis";
    public string Severity => "Low";
    public int Score => 10;
    public string Description => "Listening on a high port (>1024) that this process has never listened on here before.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction != "listen") return null;
        var port = CheckHelpers.LocalPort(c.Local);
        if (port <= 1024 || Providers.WellKnownPorts.Contains(port)) return null;
        if (ctx.IsFirstEver($"listen-high:{c.AgentId}|{c.Exe}|{c.Local}"))
            return CheckHelpers.Make(this, $"Listening on {c.Local} — first time this process listens here.",
                "High listening ports are common for dev servers and containers. The signal is novelty for this process, not the number itself.");
        return null;
    }
}

public sealed class MultipleProtocolsCheck : ICheck
{
    public string Id => "port.multiple-protocols";
    public string Title => "Multiple protocols / many ports";
    public string Category => "PortProtocol";
    public string Engine => "BehavioralAnalysis";
    public string Severity => "Low";
    public int Score => 15;
    public string Description => "Process used many distinct remote ports in the last hour (behavior window).";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction == "local") return null;
        var n = ctx.History.DistinctRemotePorts(c.AgentId, c.Process, TimeSpan.FromHours(1), ctx.Now);
        if (n >= 10)
            return CheckHelpers.Make(this, $"{c.Process} used {n} distinct remote ports in the last hour.",
                "A normal client usually talks on one or two ports. Many ports can be a scan, a peer-to-peer app, or a service with many backends — check the destination list in the group view.");
        return null;
    }
}

public sealed class UnexpectedUdpCheck : ICheck
{
    public string Id => "port.unexpected-udp";
    public string Title => "Unexpected UDP activity";
    public string Category => "PortProtocol";
    public string Engine => "BehavioralAnalysis";
    public string Severity => "Low";
    public int Score => 10;
    public string Description => "UDP to a public IP on a non-DNS, non-NTP port, first time for this process.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Proto != "udp" || c.Direction != "outbound") return null;
        var port = CheckHelpers.RemotePort(c.Remote);
        if (port == 53 || port == 123) return null;
        var rip = CheckHelpers.RemoteIp(c.Remote);
        if (!CheckHelpers.IsPublicIp(rip)) return null;
        if (ctx.IsFirstEver($"udp:{c.AgentId}|{c.Exe}|{rip}|{port}"))
            return CheckHelpers.Make(this, $"UDP to {c.Remote} — first time this process uses UDP here.",
                "UDP can carry DNS, NTP, QUIC, games, and also tunneling/covert channels. First-time UDP to a public IP is worth noting, not alarming on its own.");
        return null;
    }
}
