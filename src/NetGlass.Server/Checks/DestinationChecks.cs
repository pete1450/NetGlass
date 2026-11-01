namespace NetGlass.Server.Checks;

/// <summary>Remote destination indicators (user plan §2).
/// No external threat feed is bundled or fetched. Checks that
/// need one are provider-based and inactive without a list.</summary>
public sealed class ThreatListCheck : ICheck
{
    public string Id => "dest.threat-list";
    public string Title => "On supplied threat list";
    public string Category => "Destination";
    public string Engine => "ThreatIndicators";
    public string Severity => "High";
    public int Score => 60;
    public string Description => "Remote IP or hostname matches a user-supplied threat list (NETGLASS_THREAT_LIST).";
    public string? UnavailableReason => Providers.ThreatListConfigured()
        ? null : "No threat list configured. Set NETGLASS_THREAT_LIST to a file with one IP/domain per line.";
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        var rip = CheckHelpers.RemoteIp(c.Remote);
        if (ctx.ThreatList.Contains(rip) || (!string.IsNullOrEmpty(c.RemoteHost) && ctx.ThreatList.Contains(c.RemoteHost)))
            return CheckHelpers.Make(this, $"Destination {c.Remote} ({c.RemoteHost}) is on the supplied threat list.",
                "This list is supplied by you, not by NetGlass. A match means the destination is on a list you trust — investigate, and check which list entry matched if you maintain several lists in one file.");
        return null;
    }
}

public sealed class DirectIpCheck : ICheck
{
    public string Id => "dest.direct-ip";
    public string Title => "Direct IP connection";
    public string Category => "Destination";
    public string Engine => "ThreatIndicators";
    public string Severity => "Low";
    public int Score => 10;
    public string Description => "Outbound to a public IP with no reverse hostname on record.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction != "outbound") return null;
        var rip = CheckHelpers.RemoteIp(c.Remote);
        if (!CheckHelpers.IsPublicIp(rip)) return null;
        if (!string.IsNullOrEmpty(c.RemoteHost)) return null;
        return CheckHelpers.Make(this, $"Outbound to {rip} with no hostname (no PTR on record).",
            "Plenty of legitimate software connects by IP. This becomes interesting combined with an unknown executable, an unusual port, or a first-ever destination — which is why it scores low on its own.");
    }
}

public sealed class RareDestinationCheck : ICheck
{
    public string Id => "dest.rare";
    public string Title => "Rare destination";
    public string Category => "Destination";
    public string Engine => "BehavioralAnalysis";
    public string Severity => "Medium";
    public int Score => 20;
    public string Description => "This host has never communicated with this destination before (persisted baseline, seeded from history).";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction == "local" || c.Direction == "listen") return null;
        var rip = CheckHelpers.RemoteIp(c.Remote);
        if (string.IsNullOrEmpty(rip)) return null;
        if (ctx.IsFirstEver($"dest:{c.AgentId}|{rip}"))
            return CheckHelpers.Make(this, $"First communication from {c.AgentName} to {rip}.",
                "A destination that has never appeared for this host before. New is not the same as malicious — but for a host with a stable set of services, a brand-new destination is worth a look.");
        return null;
    }
}

public sealed class NewlyObservedIpCheck : ICheck
{
    public string Id => "dest.newly-observed";
    public string Title => "Newly observed IP in the environment";
    public string Category => "Destination";
    public string Engine => "BehavioralAnalysis";
    public string Severity => "Medium";
    public int Score => 20;
    public string Description => "Destination has never appeared on any monitored host before (persisted baseline).";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction == "local" || c.Direction == "listen") return null;
        var rip = CheckHelpers.RemoteIp(c.Remote);
        if (string.IsNullOrEmpty(rip)) return null;
        if (ctx.IsFirstEver($"dest-global:{rip}"))
            return CheckHelpers.Make(this, $"First time {rip} appears on any monitored host.",
                "Stronger than rare-for-this-host: this IP is new to your whole environment. Combined with a new process, this is a common early indicator.");
        return null;
    }
}

public sealed class NewDestinationForProcessCheck : ICheck
{
    public string Id => "dest.new-for-process";
    public string Title => "New destination for this process";
    public string Category => "Destination";
    public string Engine => "BehavioralAnalysis";
    public string Severity => "Medium";
    public int Score => 15;
    public string Description => "A known process talking to a destination it has never used before.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (c.Direction == "local" || c.Direction == "listen" || string.IsNullOrEmpty(c.Exe)) return null;
        var rip = CheckHelpers.RemoteIp(c.Remote);
        if (string.IsNullOrEmpty(rip)) return null;
        if (ctx.IsFirstEver($"proc-dest:{c.AgentId}|{c.Exe}|{rip}"))
            return CheckHelpers.Make(this, $"{c.Process} ({c.Exe}) has never talked to {rip} before.",
                "The process itself is known, but this destination is not part of its normal set. This is the baseline deviation that matters most for established software.");
        return null;
    }
}

public sealed class DynamicDnsCheck : ICheck
{
    public string Id => "dest.dynamic-dns";
    public string Title => "Dynamic DNS hostname";
    public string Category => "Destination";
    public string Engine => "ThreatIndicators";
    public string Severity => "Medium";
    public int Score => 30;
    public string Description => "Reverse hostname is on a known dynamic-DNS suffix list (local list, no lookup).";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var host = ctx.Conn.RemoteHost ?? "";
        if (string.IsNullOrEmpty(host)) return null;
        if (Providers.DynamicDnsSuffixes.Any(s => host.EndsWith("." + s, StringComparison.OrdinalIgnoreCase) || string.Equals(host, s, StringComparison.OrdinalIgnoreCase)))
            return CheckHelpers.Make(this, $"Reverse hostname {host} is a dynamic-DNS name.",
                "Dynamic DNS lets an attacker re-point a hostname quickly, which is why it is abused for command-and-control. Legitimate remote-access tools also use it — check the process, not just the suffix.");
        return null;
    }
}
