namespace NetGlass.Server.Checks;

/// <summary>Process-related indicators (user plan §1). All use only
/// data the agent already reports: exe, process name, parent,
/// signature (Windows only), and baselines.</summary>
public sealed class UnknownExecutableCheck : ICheck
{
    public string Id => "proc.unknown-exe";
    public string Title => "Unknown executable";
    public string Category => "Process";
    public string Engine => "ThreatIndicators";
    public string Severity => "High";
    public int Score => 40;
    public string Description => "Process cannot be mapped to an executable on disk.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (string.IsNullOrEmpty(c.Exe) || c.Process == "(unknown)")
            return CheckHelpers.Make(this,
                $"Process {c.Process} (PID {c.Pid}) has no executable mapping.",
                "A network connection with no identifiable binary cannot be attributed to an application. This can be a kernel thread, a permissions gap in the agent, or a process trying to hide.");
        return null;
    }
}

public sealed class TempExeCheck : ICheck
{
    public string Id => "proc.temp-exe";
    public string Title => "Executable running from Temp";
    public string Category => "Process";
    public string Engine => "ThreatIndicators";
    public string Severity => "High";
    public int Score => 50;
    public string Description => "Executable lives in a temporary directory.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var exe = ctx.Conn.Exe;
        if (CheckHelpers.ExeContains(exe, "/tmp/", "/dev/shm/", "/var/tmp/", @"\Temp\", @"\Temporary "))
            return CheckHelpers.Make(this, $"Executable: {exe}",
                "Malware frequently runs from temporary directories because they are writable and often excluded from scanning. Legitimate installers also use Temp briefly — the score, not this finding alone, decides.");
        return null;
    }
}

public sealed class AppDataExeCheck : ICheck
{
    public string Id => "proc.appdata-exe";
    public string Title => "Executable running from AppData";
    public string Category => "Process";
    public string Engine => "ThreatIndicators";
    public string Severity => "Medium";
    public int Score => 30;
    public string Description => "Executable lives under a user AppData directory (Windows).";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        if (CheckHelpers.ExeContains(ctx.Conn.Exe, @"\AppData\"))
            return CheckHelpers.Make(this, $"Executable: {ctx.Conn.Exe}",
                "Many legitimate per-user apps install to AppData, but system processes should not run from there. Combined with other signals, AppData is a classic persistence location.");
        return null;
    }
}

public sealed class DeletedExeCheck : ICheck
{
    public string Id => "proc.deleted-exe";
    public string Title => "Deleted executable";
    public string Category => "Process";
    public string Engine => "ThreatIndicators";
    public string Severity => "High";
    public int Score => 50;
    public string Description => "Process runs from a binary that no longer exists on disk.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        if (ctx.Conn.Exe.EndsWith(" (deleted)", StringComparison.Ordinal))
            return CheckHelpers.Make(this, $"Executable: {ctx.Conn.Exe}",
                "The binary was deleted while the process kept running. Legitimate updaters do this briefly; malware does it to remove evidence.");
        return null;
    }
}

public sealed class UnsignedExeCheck : ICheck
{
    public string Id => "proc.unsigned-exe";
    public string Title => "Unsigned executable";
    public string Category => "Process";
    public string Engine => "ThreatIndicators";
    public string Severity => "Medium";
    public int Score => 30;
    public string Description => "Windows executable has no Authenticode certificate. Linux: not applicable.";
    public string? UnavailableReason => "Requires the Windows agent's signature field; Linux connections never produce this finding.";
    public Finding? Evaluate(CheckContext ctx)
    {
        if (ctx.Conn.Signature == "unsigned")
            return CheckHelpers.Make(this, $"Executable: {ctx.Conn.Exe}",
                "No verifiable code signature. Many legitimate open-source tools are unsigned, so this alone is not proof of malware — it matters when combined with an unusual location, parent, or destination.");
        return null;
    }
}

public sealed class InvalidSignatureCheck : ICheck
{
    public string Id => "proc.invalid-signature";
    public string Title => "Invalid signature";
    public string Category => "Process";
    public string Engine => "ThreatIndicators";
    public string Severity => "High";
    public int Score => 60;
    public string Description => "Agent reported an invalid signature. No current agent sets this value yet.";
    public string? UnavailableReason => "No agent currently reports 'invalid'; the check is registered and will fire if a future agent does.";
    public Finding? Evaluate(CheckContext ctx)
    {
        if (ctx.Conn.Signature == "invalid")
            return CheckHelpers.Make(this, $"Executable: {ctx.Conn.Exe}",
                "Signature is present but invalid or untrusted — stronger than unsigned, because something claimed an identity it cannot prove.");
        return null;
    }
}

public sealed class SuspiciousProcessNameCheck : ICheck
{
    public string Id => "proc.suspicious-name";
    public string Title => "Suspicious process name / path";
    public string Category => "Process";
    public string Engine => "ThreatIndicators";
    public string Severity => "High";
    public int Score => 50;
    public string Description => "Process name imitates a system process but lives in the wrong location.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        var baseName = CheckHelpers.BaseName(c.Exe);
        if (string.IsNullOrEmpty(baseName)) return null;
        var stem = baseName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? baseName[..^4] : baseName;
        foreach (var (name, prefixes) in Providers.SystemProcesses)
        {
            if (!string.Equals(stem, name, StringComparison.OrdinalIgnoreCase)) continue;
            if (prefixes.Any(p => c.Exe.StartsWith(p, StringComparison.OrdinalIgnoreCase))) return null;
            return CheckHelpers.Make(this, $"Process {stem} running from {c.Exe} (expected one of: {string.Join(", ", prefixes)})",
                "A system-process name in a user or temp directory is a classic masquerade. The real binary lives in a system directory.");
        }
        return null;
    }
}

public sealed class ScriptInterpreterCheck : ICheck
{
    public string Id => "proc.script-interpreter";
    public string Title => "Script interpreter networking";
    public string Category => "Process";
    public string Engine => "ThreatIndicators";
    public string Severity => "Medium";
    public int Score => 35;
    public string Description => "PowerShell, Python, WScript, shell, etc. making a network connection.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        var stem = CheckHelpers.BaseName(c.Exe);
        if (stem.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) stem = stem[..^4];
        if (c.Direction == "local") return null;
        if (Providers.Interpreters.Any(i => string.Equals(stem, i, StringComparison.OrdinalIgnoreCase) ||
            string.Equals(c.Process, i, StringComparison.OrdinalIgnoreCase)))
            return CheckHelpers.Make(this, $"{c.Process} ({c.Exe}) → {c.Remote}",
                "Interpreters are dual-use: legitimate automation and fileless malware both use them. An interpreter with an unexpected outbound connection deserves a look at its command line in the drawer.");
        return null;
    }
}

public sealed class SuspiciousParentCheck : ICheck
{
    public string Id => "proc.suspicious-parent";
    public string Title => "Suspicious parent process";
    public string Category => "Process";
    public string Engine => "ThreatIndicators";
    public string Severity => "Medium";
    public int Score => 35;
    public string Description => "Network process launched by a shell, script host, or unknown parent.";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (string.IsNullOrEmpty(c.Parent) || c.Direction == "local") return null;
        var parentStem = c.Parent.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? c.Parent[..^4] : c.Parent;
        if (Providers.Shells.Any(s => string.Equals(parentStem, s, StringComparison.OrdinalIgnoreCase)) ||
            c.Parent == "(unknown)")
            return CheckHelpers.Make(this, $"{c.Process} launched by {c.Parent} ({c.ParentExe})",
                "Network-enabled processes are normally launched by a service manager, a desktop shell, or their own application — not by an interactive shell or script host.");
        return null;
    }
}

public sealed class UnexpectedNetworkActivityCheck : ICheck
{
    public string Id => "proc.unexpected-network";
    public string Title => "Unexpected network activity for this process";
    public string Category => "Process";
    public string Engine => "BehavioralAnalysis";
    public string Severity => "Medium";
    public int Score => 25;
    public string Description => "This executable has never been seen with network activity before (first-ever, persisted baseline).";
    public string? UnavailableReason => null;
    public Finding? Evaluate(CheckContext ctx)
    {
        var c = ctx.Conn;
        if (string.IsNullOrEmpty(c.Exe)) return null;
        // First-ever for this exe on this agent. IsFirstEver inserts on
        // first call, so a later snapshot of the same exe will not fire.
        // The first snapshot after a server upgrade will fire for every
        // exe once — that is the baseline learning period, documented
        // in docs/CHECKS.md.
        if (ctx.IsFirstEver($"exe:{c.AgentId}|{c.Exe}"))
            return CheckHelpers.Make(this, $"First network activity seen for {c.Exe} on {c.AgentName}.",
                "This binary has never been observed making a connection on this host before. It may be a new install, an update, or something that should not be networking at all.");
        return null;
    }
}
