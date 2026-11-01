namespace NetGlass.Server.Checks;

/// <summary>
/// One modular detection. A check is a single, independently testable
/// rule: it looks at one connection (plus history/baselines) and
/// either returns a Finding or returns null.
///
/// To add a new check:
///   1. Create a class implementing ICheck (one file per category,
///      one class per check — see ProcessChecks.cs for examples).
///   2. Add it to CheckEngine.All in CheckEngine.cs.
///   3. Nothing else changes: scoring, the API, and the UI pick it
///      up from the registry. No if/else chain in Ingest to edit.
///
/// A check must never throw on unexpected input (empty exe, weird
/// addresses, unknown OS). A check that cannot evaluate returns
/// null, not a finding. A high score means "investigate", not
/// "confirmed malware".
/// </summary>
public interface ICheck
{
    /// <summary>Stable ID, e.g. "proc.temp-exe". Used for enable/disable and the UI catalogue.</summary>
    string Id { get; }
    string Title { get; }
    /// <summary>Process, Destination, PortProtocol, Behavior, Listening, or Ghost.</summary>
    string Category { get; }
    /// <summary>ThreatIndicators, BehavioralAnalysis, or ExposureAnalysis.</summary>
    string Engine { get; }
    string Severity { get; } // Low, Medium, High
    int Score { get; } // Points added to the connection score when this fires. Tunable defaults.
    string Description { get; }
    /// <summary>Why this check cannot run here, or null if it can. E.g. "requires a user-supplied threat list".</summary>
    string? UnavailableReason { get; }
    Finding? Evaluate(CheckContext ctx);
}

public sealed record Finding(
    string RuleId, string Title, string Category, string Engine,
    string Severity, int Score, string Evidence, string Explanation);

public sealed record CheckContext(
    ConnectionDto Conn,
    DateTime Now,
    CheckHistory History,
    Func<string, bool> IsFirstEver,
    IReadOnlySet<string> ThreatList,
    Func<string, (string Country, string Asn)?> CachedIp,
    IReadOnlyList<ConnectionDto> Live);

public static class CheckHelpers
{
    public static string RemoteIp(string addr)
    {
        if (string.IsNullOrEmpty(addr)) return "";
        var i = addr.LastIndexOf(':');
        if (i < 0) return addr;
        return addr[..i].Trim('[', ']');
    }

    public static int RemotePort(string addr)
    {
        var i = addr.LastIndexOf(':');
        return i >= 0 && int.TryParse(addr[(i + 1)..], out var p) ? p : 0;
    }

    public static string LocalIp(string addr) => RemoteIp(addr);

    public static int LocalPort(string addr) => RemotePort(addr);

    public static bool IsPublicIp(string ip)
    {
        if (!System.Net.IPAddress.TryParse(ip, out var a)) return false;
        var b = a.GetAddressBytes();
        if (a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
        {
            if (b[0] == 10) return false;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
            if (b[0] == 192 && b[1] == 168) return false;
            if (b[0] == 127) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
            if (b[0] == 0 || b[0] >= 224) return false;
            return true;
        }
        // IPv6: loopback, link-local, unique-local, unspecified
        if (a.IsIPv6LinkLocal || a.IsIPv6SiteLocal) return false;
        if (ip == "::1" || ip == "::") return false;
        if (b[0] == 0xfc || b[0] == 0xfd) return false;
        return true;
    }

    public static bool IsPrivateIp(string ip) => !string.IsNullOrEmpty(ip) && !IsPublicIp(ip) &&
        System.Net.IPAddress.TryParse(ip, out _);

    public static string BaseName(string exe)
    {
        if (string.IsNullOrEmpty(exe)) return "";
        var norm = exe.Replace('\\', '/');
        var i = norm.LastIndexOf('/');
        return i >= 0 ? norm[(i + 1)..] : norm;
    }

    public static bool ExeContains(string exe, params string[] parts)
    {
        if (string.IsNullOrEmpty(exe)) return false;
        return parts.Any(p => exe.Contains(p, StringComparison.OrdinalIgnoreCase));
    }

    public static Finding Make(ICheck check, string evidence, string explanation) =>
        new(check.Id, check.Title, check.Category, check.Engine,
            check.Severity, check.Score, evidence, explanation);
}
