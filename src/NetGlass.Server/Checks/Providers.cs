namespace NetGlass.Server.Checks;

/// <summary>
/// External-data providers. All are local-first and opt-in:
/// - Threat list: a user-supplied text file (one IP or domain per
///   line, # comments), pointed to by NETGLASS_THREAT_LIST. No list
///   is bundled, no list is fetched from the internet, and no
///   finding is produced if the file is unset or missing.
/// - Cached IP info: reads only the ip_info_cache table that the
///   on-demand Fetch button populates. It never calls ip-api.
///   Country/ASN findings therefore only fire for IPs the user
///   has already fetched — by design, per the on-demand rule.
/// - Dynamic DNS: a small, hard-coded suffix list. No lookup.
/// </summary>
public static class Providers
{
    public static readonly string[] DynamicDnsSuffixes =
    {
        "duckdns.org", "no-ip.com", "noip.com", "dyndns.org", "dynu.com",
        "ddns.net", "freedns.org", "zapto.org", "hopto.org", "servebeer.com",
        "myvnc.com", "gotdns.ch", "sytes.net", "crabdance.com",
    };

    public static readonly string[] Interpreters =
    {
        "powershell", "pwsh", "wscript", "cscript", "python", "python3", "perl",
        "ruby", "node", "bash", "sh", "zsh", "cmd", "wsl", "php", "lua",
    };

    public static readonly string[] Shells =
    {
        "powershell", "pwsh", "cmd", "bash", "sh", "zsh", "wscript", "cscript",
    };

    // Known system processes and where they should live. A process
    // with one of these names in a different location is masquerading
    // until proven otherwise. Prefix match, case-insensitive.
    public static readonly (string Name, string[] ExpectedPrefixes)[] SystemProcesses =
    {
        ("svchost", new[] { @"C:\Windows\System32\", @"C:\Windows\SysWOW64\" }),
        ("lsass", new[] { @"C:\Windows\System32\" }),
        ("csrss", new[] { @"C:\Windows\System32\" }),
        ("smss", new[] { @"C:\Windows\System32\" }),
        ("wininit", new[] { @"C:\Windows\System32\" }),
        ("explorer", new[] { @"C:\Windows\" }),
        ("sshd", new[] { "/usr/sbin/", "/usr/bin/", "/sbin/" }),
        ("systemd", new[] { "/usr/lib/systemd/", "/lib/systemd/" }),
        ("cron", new[] { "/usr/sbin/", "/usr/bin/" }),
        ("ntpd", new[] { "/usr/sbin/", "/usr/bin/" }),
    };

    public static readonly int[] AdminPorts = { 22, 3389, 5900, 5901, 5985, 5986 };
    public static readonly int[] DatabasePorts = { 1433, 3306, 5432, 6379, 27017, 1521 };

    public static readonly HashSet<int> WellKnownPorts = new()
    {
        21, 22, 23, 25, 53, 80, 110, 123, 143, 389, 443, 445, 465, 587, 993, 995,
        1433, 1521, 1723, 2049, 3306, 3389, 5060, 5432, 5900, 5985, 5986, 6379,
        8000, 8080, 8443, 9000, 9090, 27017,
    };

    private static HashSet<string> _threatList = new(StringComparer.OrdinalIgnoreCase);
    private static DateTime _threatListMtime = DateTime.MinValue;
    private static string _threatListPath = "";

    public static IReadOnlySet<string> ThreatList()
    {
        try
        {
            var path = Environment.GetEnvironmentVariable("NETGLASS_THREAT_LIST") ?? "";
            if (string.IsNullOrEmpty(path) || !File.Exists(path)) return new HashSet<string>();
            var mtime = File.GetLastWriteTimeUtc(path);
            if (path != _threatListPath || mtime != _threatListMtime)
            {
                _threatListPath = path; _threatListMtime = mtime;
                var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var line in File.ReadLines(path))
                {
                    var t = line.Trim();
                    if (t.Length == 0 || t.StartsWith('#')) continue;
                    set.Add(t);
                }
                _threatList = set;
            }
            return _threatList;
        }
        catch { return new HashSet<string>(); }
    }

    public static bool ThreatListConfigured()
    {
        var path = Environment.GetEnvironmentVariable("NETGLASS_THREAT_LIST") ?? "";
        return !string.IsNullOrEmpty(path) && File.Exists(path);
    }
}
