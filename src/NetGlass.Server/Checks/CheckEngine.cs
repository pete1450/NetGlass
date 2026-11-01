namespace NetGlass.Server.Checks;

/// <summary>
/// Registry + scoring. This is the only place a new check is
/// registered: add its class to All, and it flows to scoring,
/// GET /api/connections, GET /api/checks, and the UI catalogue.
/// Checks are evaluated in registry order; a check that throws
/// is skipped (a broken check must not break ingest).
///
/// Scoring (starting defaults, per-check Score is the tunable):
///   score = sum of finding scores, capped at 100.
///   tier:  >=70 High, >=40 Medium, >0 Low, 0 None.
/// A high score means "investigate", not "confirmed malware".
/// Enable/disable is per-check via the settings table
/// (key "check_enabled:{ruleId}" = "0" to disable) and via
/// POST /api/checks/{id}/toggle. Disabled checks are still
/// listed in the catalogue with enabled=false.
/// </summary>
public static class CheckEngine
{
    public static readonly IReadOnlyList<ICheck> All = new ICheck[]
    {
        // Process (§1)
        new UnknownExecutableCheck(), new TempExeCheck(), new AppDataExeCheck(),
        new DeletedExeCheck(), new UnsignedExeCheck(), new InvalidSignatureCheck(),
        new SuspiciousProcessNameCheck(), new ScriptInterpreterCheck(),
        new SuspiciousParentCheck(), new UnexpectedNetworkActivityCheck(),
        // Destination (§2)
        new ThreatListCheck(), new DirectIpCheck(), new RareDestinationCheck(),
        new NewlyObservedIpCheck(), new NewDestinationForProcessCheck(),
        new DynamicDnsCheck(),
        // Port / protocol (§3)
        new UnusualOutboundPortCheck(), new AdminPortCheck(),
        new DatabasePortExposedCheck(), new DatabasePortOutboundCheck(),
        new UnusualHighPortListenCheck(), new MultipleProtocolsCheck(),
        new UnexpectedUdpCheck(),
        // Behavior (§4)
        new BeaconingCheck(), new RepeatedAttemptsCheck(),
        new RapidDestinationChangesCheck(), new PortScanningCheck(),
        new HostScanningCheck(), new HighConnectionCountCheck(),
        new FrequentShortLivedCheck(), new OffHoursCheck(), new LongDurationCheck(),
        // Listening (§5) + Ghost (§6)
        new NewListenerCheck(), new PublicListenerCheck(),
        new UnexpectedListenerProcessCheck(), new ManyListenersCheck(),
        new GhostDeletedExeCheck(), new GhostUnknownCheck(), new PidReuseCheck(),
    };

    public static (int Score, string Tier, List<Finding> Findings) Evaluate(
        ConnectionDto conn, DateTime now, CheckHistory history,
        Func<string, bool> isFirstEver, IReadOnlySet<string> threatList,
        Func<string, (string Country, string Asn)?> cachedIp,
        IReadOnlyList<ConnectionDto> live, Func<string, bool> isEnabled)
    {
        var findings = new List<Finding>();
        var ctx = new CheckContext(conn, now, history, isFirstEver, threatList, cachedIp, live);
        foreach (var check in All)
        {
            if (!isEnabled(check.Id)) continue;
            try
            {
                var f = check.Evaluate(ctx);
                if (f is not null) findings.Add(f);
            }
            catch { /* a broken check must not break ingest */ }
        }
        findings.Sort((a, b) => b.Score.CompareTo(a.Score));
        var score = Math.Min(100, findings.Sum(f => f.Score));
        var tier = score >= 70 ? "High" : score >= 40 ? "Medium" : score > 0 ? "Low" : "None";
        return (score, tier, findings);
    }

    public static string TierFor(int score) =>
        score >= 70 ? "High" : score >= 40 ? "Medium" : score > 0 ? "Low" : "None";
}
