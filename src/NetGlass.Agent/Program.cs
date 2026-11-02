// NetGlass Agent — cross-platform, no inbound port.
// Config order: CLI args > env vars > agent.json next to the exe
// (Windows) or ~/.config/netglass/agent.json (Linux).
// If no server/token is configured, it prompts interactively on
// startup and saves the answers, so a Windows exe can be started
// by double-clicking it the first time.
//
// Collectors:
//   Linux:   per-network-namespace /proc/<pid>/net/* + /proc/<pid>/fd
//            (host namespace alone misses Docker container traffic)
//   Windows: netstat -ano parsed + Process enrichment (+ WMI parent, best effort)
// Sender: POST snapshot to the server every interval (default 2s).
// Kill:   polls the server for kill requests, re-verifies PID + exe +
//         start time before killing (PID-reuse protection), posts result.
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

var config = AgentConfig.Load(args);
Console.WriteLine($"[netglass-agent] server={config.Server} agent={config.AgentId} name={config.Name} interval={config.Interval}s");
using var http = new HttpClient { BaseAddress = new Uri(config.Server.TrimEnd('/')) };
http.DefaultRequestHeaders.Add("X-Agent-Token", config.Token);

var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };

_ = Task.Run(() => KillLoop(http, config, cts.Token));
var lastLoggedCount = -1;
var snapshotNo = 0;
while (!cts.IsCancellationRequested)
{
    try
    {
        var snapshot = Collector.Collect();
        snapshotNo++;
        // Log on change, and every 30 snapshots (~60s at 2s), so
        // `docker logs netglass-agent` shows whether the agent is
        // actually seeing traffic, without spamming every poll.
        if (snapshot.Count != lastLoggedCount || snapshotNo % 30 == 0)
        {
            Console.WriteLine($"[netglass-agent] snapshot #{snapshotNo}: {snapshot.Count} connections" + (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? $", {Collector.LastNamespaceCount} net namespaces, {Collector.LastFailedNamespaces} failed namespace reads" : ""));
            lastLoggedCount = snapshot.Count;
        }
        var payload = new
        {
            hostname = Dns.GetHostName(),
            os = RuntimeInformation.OSDescription,
            version = "1.0.0",
            connections = snapshot,
        };
        var json = JsonSerializer.Serialize(payload);
        var resp = await http.PostAsync($"/api/agents/{config.AgentId}/snapshot",
            new StringContent(json, Encoding.UTF8, "application/json"), cts.Token);
        if (!resp.IsSuccessStatusCode)
            Console.WriteLine($"[netglass-agent] snapshot rejected: {(int)resp.StatusCode}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[netglass-agent] snapshot failed: {ex.Message}");
    }
    try { await Task.Delay(TimeSpan.FromSeconds(config.Interval), cts.Token); }
    catch (TaskCanceledException) { break; }
}

static async Task KillLoop(HttpClient http, AgentConfig config, CancellationToken ct)
{
    while (!ct.IsCancellationRequested)
    {
        try
        {
            var resp = await http.GetAsync($"/api/agents/{config.AgentId}/kill-requests", ct);
            if (resp.IsSuccessStatusCode)
            {
                var jobs = JsonSerializer.Deserialize<List<KillJob>>(
                    await resp.Content.ReadAsStringAsync(ct),
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new();
                foreach (var job in jobs)
                {
                    var (ok, message) = KillExecutor.TryKill(job);
                    var result = new { killId = job.Id, success = ok, message };
                    await http.PostAsync($"/api/agents/{config.AgentId}/kill-result",
                        new StringContent(JsonSerializer.Serialize(result), Encoding.UTF8, "application/json"), ct);
                    Console.WriteLine($"[netglass-agent] kill {job.Pid} ({job.Exe}): {(ok ? "done" : "refused: " + message)}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[netglass-agent] kill poll failed: {ex.Message}");
        }
        try { await Task.Delay(TimeSpan.FromSeconds(5), ct); }
        catch (TaskCanceledException) { break; }
    }
}

// ---------------------------------------------------------------- config
sealed class AgentConfig
{
    public string Server { get; set; } = "";
    public string Token { get; set; } = "";
    public string AgentId { get; set; } = "";
    public string Name { get; set; } = "";
    public double Interval { get; set; } = 2;

    public static AgentConfig Load(string[] args)
    {
        var cfg = new AgentConfig();
        var exeDir = AppContext.BaseDirectory;
        var candidates = new[]
        {
            Path.Combine(exeDir, "agent.json"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".config", "netglass", "agent.json"),
        };
        foreach (var path in candidates)
        {
            if (!File.Exists(path)) continue;
            try
            {
                var doc = JsonDocument.Parse(File.ReadAllText(path));
                cfg.Server = Get(doc, "server") ?? cfg.Server;
                cfg.Token = Get(doc, "token") ?? cfg.Token;
                cfg.AgentId = Get(doc, "agentId") ?? cfg.AgentId;
                cfg.Name = Get(doc, "name") ?? cfg.Name;
            }
            catch { }
        }
        cfg.Server = Env("NETGLASS_SERVER", cfg.Server);
        cfg.Token = Env("NETGLASS_TOKEN", cfg.Token);
        cfg.AgentId = Env("NETGLASS_AGENT_ID", cfg.AgentId);
        cfg.Name = Env("NETGLASS_NAME", cfg.Name);
        if (double.TryParse(Environment.GetEnvironmentVariable("NETGLASS_INTERVAL"), out var iv))
            cfg.Interval = iv;
        for (var i = 0; i < args.Length - 1; i++)
        {
            switch (args[i])
            {
                case "--server": cfg.Server = args[i + 1]; break;
                case "--token": cfg.Token = args[i + 1]; break;
                case "--agent-id": cfg.AgentId = args[i + 1]; break;
                case "--name": cfg.Name = args[i + 1]; break;
                case "--interval": if (double.TryParse(args[i + 1], out var v)) cfg.Interval = v; break;
            }
        }
        if (string.IsNullOrWhiteSpace(cfg.Name)) cfg.Name = Dns.GetHostName();
        if (string.IsNullOrWhiteSpace(cfg.Server) || string.IsNullOrWhiteSpace(cfg.Token) ||
            string.IsNullOrWhiteSpace(cfg.AgentId))
        {
            Console.WriteLine("NetGlass agent is not configured yet.");
            if (string.IsNullOrWhiteSpace(cfg.Server))
            {
                Console.Write("Server URL (e.g. http://192.168.1.50:8080): ");
                cfg.Server = Console.ReadLine()?.Trim() ?? "";
            }
            if (string.IsNullOrWhiteSpace(cfg.AgentId))
            {
                Console.Write("Agent ID (from the NetGlass UI, Add agent): ");
                cfg.AgentId = Console.ReadLine()?.Trim() ?? "";
            }
            if (string.IsNullOrWhiteSpace(cfg.Token))
            {
                Console.Write("Agent token (from the NetGlass UI, Add agent): ");
                cfg.Token = Console.ReadLine()?.Trim() ?? "";
            }
            var savePath = candidates[0];
            File.WriteAllText(savePath, JsonSerializer.Serialize(new
            {
                server = cfg.Server, token = cfg.Token, agentId = cfg.AgentId, name = cfg.Name,
            }, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine($"Saved configuration to {savePath}");
        }
        return cfg;

        static string Env(string key, string fallback) =>
            Environment.GetEnvironmentVariable(key) is { Length: > 0 } v ? v : fallback;
        static string? Get(JsonDocument doc, string key) =>
            doc.RootElement.TryGetProperty(key, out var v) ? v.GetString() : null;
    }
}

sealed class KillJob
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("pid")] public int Pid { get; set; }
    [JsonPropertyName("exe")] public string Exe { get; set; } = "";
    [JsonPropertyName("started")] public string Started { get; set; } = "";
    [JsonPropertyName("reason")] public string Reason { get; set; } = "";
}

static class KillExecutor
{
    public static (bool, string) TryKill(KillJob job)
    {
        try
        {
            var proc = Process.GetProcessById(job.Pid);
            var currentExe = "";
            try { currentExe = proc.MainModule?.FileName ?? ""; } catch { }
            // PID-reuse protection: exe must match, and if the server
            // supplied a start time it must match within a few seconds.
            if (!string.IsNullOrWhiteSpace(job.Exe) && !string.IsNullOrWhiteSpace(currentExe) &&
                !string.Equals(currentExe, job.Exe, StringComparison.OrdinalIgnoreCase) &&
                !currentExe.Replace('\\', '/').EndsWith(job.Exe.Replace('\\', '/'), StringComparison.OrdinalIgnoreCase))
                return (false, $"PID {job.Pid} is now {currentExe}, not {job.Exe} — refusing (PID reuse?)");
            if (DateTime.TryParse(job.Started, out var wanted))
            {
                try
                {
                    if (Math.Abs((proc.StartTime.ToUniversalTime() - wanted.ToUniversalTime()).TotalSeconds) > 5)
                        return (false, $"PID {job.Pid} start time does not match — refusing (PID reuse?)");
                }
                catch { }
            }
            proc.Kill(entireProcessTree: false);
            return (true, $"Killed PID {job.Pid} ({currentExe})");
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }
}

// ---------------------------------------------------------------- collectors
static class ContainerNames
{
    private static Dictionary<string, string> _map = new();
    private static List<(string Id, string Name, List<string> Ips, List<(int Public, int Private, string Type)> Ports)> _containers = new();
    private static DateTime _updated = DateTime.MinValue;

    public static void Ensure()
    {
        if (DateTime.UtcNow - _updated > TimeSpan.FromSeconds(30)) Refresh();
    }

    public static string Lookup(string containerId)
    {
        Ensure();
        if (string.IsNullOrEmpty(containerId)) return "";
        return _map.TryGetValue(containerId, out var name) ? name
            : _map.TryGetValue(containerId[..Math.Min(12, containerId.Length)], out name) ? name : "";
    }

    // Container IP (+ optional private port) -> container name. Used for
    // docker-proxy's -container-ip/-container-port and for any socket
    // whose local/remote IP is a container IP.
    public static string ByIpPort(string ip, int privatePort = 0)
    {
        Ensure();
        foreach (var c in _containers)
            if (c.Ips.Contains(ip) && (privatePort == 0 || c.Ports.Any(p => p.Private == privatePort)))
                return c.Name;
        return "";
    }

    public static string ByPublicPort(int publicPort, string proto = "")
    {
        Ensure();
        foreach (var c in _containers)
            if (c.Ports.Any(p => p.Public == publicPort && (string.IsNullOrEmpty(proto) || p.Type == proto)))
                return c.Name;
        return "";
    }

    private static void Refresh()
    {
        _updated = DateTime.UtcNow;
        var sockPath = Environment.GetEnvironmentVariable("DOCKER_SOCK") ?? "/var/run/docker.sock";
        if (!File.Exists(sockPath)) return;
        try
        {
            using var sock = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
            sock.Connect(new UnixDomainSocketEndPoint(sockPath));
            sock.Send(Encoding.ASCII.GetBytes("GET /containers/json HTTP/1.0\r\nHost: localhost\r\n\r\n"));
            var data = new List<byte>();
            var buf = new byte[65536];
            sock.ReceiveTimeout = 2000;
            int n;
            while ((n = sock.Receive(buf)) > 0) data.AddRange(buf[..n]);
            var text = Encoding.UTF8.GetString(data.ToArray());
            var body = text.Contains("\r\n\r\n") ? text[(text.IndexOf("\r\n\r\n") + 4)..] : "";
            if (body.Contains("\r\n") && int.TryParse(body.Split('\r')[0].Trim(), System.Globalization.NumberStyles.HexNumber, null, out _))
            {
                var sb = new StringBuilder();
                var rest = body;
                while (rest.Length > 0)
                {
                    var lineEnd = rest.IndexOf("\r\n");
                    if (lineEnd < 0) break;
                    if (!int.TryParse(rest[..lineEnd].Trim(), System.Globalization.NumberStyles.HexNumber, null, out var size) || size == 0) break;
                    sb.Append(rest[(lineEnd + 2)..Math.Min(rest.Length, lineEnd + 2 + size)]);
                    rest = rest[(lineEnd + 2 + size + 2)..];
                }
                body = sb.ToString();
            }
            var doc = JsonDocument.Parse(body);
            var map = new Dictionary<string, string>();
            var containers = new List<(string, string, List<string>, List<(int, int, string)>)>();
            foreach (var item in doc.RootElement.EnumerateArray())
            {
                var id = item.GetProperty("Id").GetString() ?? "";
                var names = item.GetProperty("Names");
                var name = names.GetArrayLength() > 0 ? names[0].GetString()?.TrimStart('/') ?? "" : "";
                if (!string.IsNullOrEmpty(id)) { map[id] = name; map[id[..12]] = name; }
                var ips = new List<string>();
                if (item.TryGetProperty("NetworkSettings", out var ns) &&
                    ns.TryGetProperty("Networks", out var nets))
                    foreach (var net in nets.EnumerateObject())
                        if (net.Value.TryGetProperty("IPAddress", out var ipEl) &&
                            ipEl.GetString() is string ipStr && !string.IsNullOrEmpty(ipStr))
                            ips.Add(ipStr);
                var ports = new List<(int, int, string)>();
                if (item.TryGetProperty("Ports", out var portsEl))
                    foreach (var p in portsEl.EnumerateArray())
                    {
                        var pub = p.TryGetProperty("PublicPort", out var pp) ? pp.GetInt32() : 0;
                        var priv = p.TryGetProperty("PrivatePort", out var pr) ? pr.GetInt32() : 0;
                        var typ = p.TryGetProperty("Type", out var ty) ? ty.GetString() ?? "" : "";
                        if (priv != 0) ports.Add((pub, priv, typ));
                    }
                containers.Add((id, name, ips, ports));
            }
            _map = map;
            _containers = containers;
        }
        catch { /* container names are best-effort; ids still identify the container */ }
    }
}

sealed record CollectedConnection(
    string Direction, string Proto, string State, string Local, string Remote,
    int? Pid, string Process, string Exe, string Cmdline, string User,
    int? Ppid, string Parent, string ParentExe,
    string Unit, string Container, string ContainerId, DateTime? Started,
    string Detail = "", string Signature = "unknown");

static class Collector
{
    public static int LastNamespaceCount;
    public static int LastFailedNamespaces;

    public static List<CollectedConnection> Collect() =>
        RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? LinuxCollect() : WindowsCollect();

    // Detail for generic host processes. docker-proxy, dockerd and
    // containerd-shim look identical in a table, but their command
    // lines + the Docker API tell you which container they are
    // actually for. ntpd/chronyd are time sync, not a mystery service.
    private static string DetailFor(ProcInfo? info, string proto, string local, string remote)
    {
        if (info is null) return "";
        var name = info.Name;
        var cmd = info.Cmdline ?? "";
        string Flag(string f)
        {
            var parts = cmd.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            for (var i = 0; i + 1 < parts.Length; i++)
                if (parts[i] == f) return parts[i + 1];
            return "";
        }
        string IpOf(string addr)
        {
            try { return addr.Contains(':') ? addr[..addr.LastIndexOf(':')].Trim('[', ']') : ""; }
            catch { return ""; }
        }
        if (name == "docker-proxy")
        {
            var hostIp = Flag("-host-ip");
            var hostPort = Flag("-host-port");
            var contIp = Flag("-container-ip");
            var contPortStr = Flag("-container-port");
            int.TryParse(contPortStr, out var contPort);
            var contName = !string.IsNullOrEmpty(contIp) ? ContainerNames.ByIpPort(contIp, contPort) : "";
            var target = !string.IsNullOrEmpty(contName) ? contName : contIp;
            if (!string.IsNullOrEmpty(hostPort) || !string.IsNullOrEmpty(target))
                return $"Proxies {hostIp}:{hostPort} → {target}:{contPortStr} ({proto})";
            return "Docker published-port proxy (see command line in the drawer)";
        }
        if (name.Contains("containerd-shim"))
        {
            var shimName = ContainerNames.Lookup(Flag("-id"));
            return !string.IsNullOrEmpty(shimName) ? $"Container runtime shim for {shimName}" : "Container runtime shim";
        }
        if (name == "dockerd")
        {
            var localPort = PortOf(local);
            var byPub = localPort > 0 ? ContainerNames.ByPublicPort(localPort, proto) : "";
            if (!string.IsNullOrEmpty(byPub)) return $"Docker daemon — published port {localPort} for {byPub}";
            var rip = IpOf(remote);
            if (!string.IsNullOrEmpty(rip))
            {
                var n = ContainerNames.ByIpPort(rip);
                if (!string.IsNullOrEmpty(n)) return $"Docker daemon — talks to container {n}";
            }
            var lip = IpOf(local);
            if (!string.IsNullOrEmpty(lip))
            {
                var n = ContainerNames.ByIpPort(lip);
                if (!string.IsNullOrEmpty(n)) return $"Docker daemon — container {n}";
            }
            return "";
        }
        if (name is "ntpd" or "chronyd" or "systemd-timesyncd")
            return "Time synchronisation (NTP)";
        var ownContainer = !string.IsNullOrEmpty(info.ContainerId) ? ContainerNames.Lookup(info.ContainerId) : "";
        if (!string.IsNullOrEmpty(ownContainer)) return $"Container {ownContainer}";
        var rIp = IpOf(remote);
        if (!string.IsNullOrEmpty(rIp))
        {
            var n = ContainerNames.ByIpPort(rIp);
            if (!string.IsNullOrEmpty(n)) return $"Talks to container {n}";
        }
        var lIp = IpOf(local);
        if (!string.IsNullOrEmpty(lIp))
        {
            var n = ContainerNames.ByIpPort(lIp);
            if (!string.IsNullOrEmpty(n)) return $"Container {n}";
        }
        return "";
    }

    // ---- Linux: /proc ----
    private static List<CollectedConnection> LinuxCollect()
    {
        ContainerNames.Ensure();
        var procRoot = Environment.GetEnvironmentVariable("PROC_ROOT") ?? "/proc";
        // Network namespaces: each Docker container (unless it uses host
        // networking) has its own net namespace, so /proc/net/* alone only
        // shows the host namespace. That was the v1 bug: container services
        // were invisible. Group PIDs by /proc/<pid>/ns/net, read each
        // namespace once via a representative PID, deduplicate by inode.
        var nsToPid = new Dictionary<string, int>();
        foreach (var dir in Directory.EnumerateDirectories(procRoot).Where(d => int.TryParse(Path.GetFileName(d), out _)))
        {
            try
            {
                var ns = new FileInfo(Path.Combine(dir, "ns", "net")).LinkTarget ?? "";
                if (!string.IsNullOrEmpty(ns) && !nsToPid.ContainsKey(ns))
                    nsToPid[ns] = int.Parse(Path.GetFileName(dir));
            }
            catch { }
        }
        LastNamespaceCount = nsToPid.Count;
        LastFailedNamespaces = 0;
        var rows = new List<(string Namespace, string Proto, string Local, string Remote, string State, int Inode)>();
        var seenSockets = new HashSet<string>();
        void ReadNetDir(string netDir, string ns)
        {
            foreach (var (file, proto) in new[] { ("tcp", "tcp"), ("tcp6", "tcp"), ("udp", "udp"), ("udp6", "udp") })
            {
                var path = Path.Combine(netDir, file);
                if (!File.Exists(path)) continue;
                var isV6 = file.EndsWith("6");
                try
                {
                    foreach (var line in File.ReadLines(path).Skip(1))
                    {
                        var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                        if (parts.Length < 10) continue;
                        if (!int.TryParse(parts[3], System.Globalization.NumberStyles.HexNumber, null, out var stateNo)) continue;
                        if (!int.TryParse(parts[9], out var inode)) continue;
                        if (!seenSockets.Add($"{proto}|{inode}")) continue;
                        var state = proto == "tcp" ? TcpState(stateNo) : stateNo == 1 ? "ESTABLISHED" : "UNCONNECTED";
                        rows.Add((ns, proto, Addr(parts[1], isV6), Addr(parts[2], isV6), state, inode));
                    }
                }
                catch { LastFailedNamespaces++; }
            }
        }
        ReadNetDir(Path.Combine(procRoot, "net"), "host");
        foreach (var (ns, repPid) in nsToPid)
            ReadNetDir(Path.Combine(procRoot, repPid.ToString(), "net"), ns);
        var listenPorts = rows.Where(r => r.State == "LISTEN").Select(r => (r.Namespace, r.Proto, PortOf(r.Local))).ToHashSet();
        var inodeToPid = new Dictionary<int, int>();
        foreach (var dir in Directory.EnumerateDirectories(procRoot).Where(d => int.TryParse(Path.GetFileName(d), out _)))
        {
            var fdDir = Path.Combine(dir, "fd");
            if (!Directory.Exists(fdDir)) continue;
            foreach (var fd in Directory.EnumerateFiles(fdDir))
            {
                string target;
                try { target = new FileInfo(fd).LinkTarget ?? ""; }
                catch { continue; }
                if (target.StartsWith("socket:[") && int.TryParse(target[8..^1], out var inode))
                    inodeToPid.TryAdd(inode, int.Parse(Path.GetFileName(dir)));
            }
        }
        var procCache = new Dictionary<int, ProcInfo?>();
        ProcInfo? Proc(int pid)
        {
            if (!procCache.TryGetValue(pid, out var info))
            {
                info = ReadProc(procRoot, pid);
                procCache[pid] = info;
            }
            return info;
        }
        var result = new List<CollectedConnection>();
        foreach (var r in rows)
        {
            if (r.State is "TIME_WAIT" or "CLOSE") continue;
            inodeToPid.TryGetValue(r.Inode, out var pid);
            var info = pid != 0 ? Proc(pid) : null;
            var localPort = PortOf(r.Local);
            string direction;
            if (r.State == "LISTEN") direction = "listen";
            else if (r.Proto == "udp" && r.Remote.StartsWith("0.0.0.0:") || r.Remote.StartsWith(":::"))
                direction = "listen";
            else if (r.Remote.StartsWith("127.0.0.1:") || r.Remote.StartsWith("[::1]:") || RemoteIp(r.Remote) == LocalIp(r.Local))
                direction = "local";
            else if (listenPorts.Contains((r.Namespace, r.Proto, localPort))) direction = "inbound";
            else direction = "outbound";
            var parent = info is not null && info.Ppid > 0 ? Proc(info.Ppid) : null;
            var containerName = info is not null && !string.IsNullOrEmpty(info.ContainerId)
                ? ContainerNames.Lookup(info.ContainerId) : "";
            var detail = DetailFor(info, r.Proto, r.Local, r.Remote);
            // docker-proxy's container is the one it proxies for, not
            // the host process itself — surface that in the drawer too.
            if (info?.Name == "docker-proxy" && !string.IsNullOrEmpty(detail) && detail.Contains("→"))
            {
                var target = detail.Split('→')[1].Trim().Split(':')[0].Trim();
                if (!string.IsNullOrEmpty(target) && !System.Net.IPAddress.TryParse(target, out _) && target != containerName) containerName = target;
            }
            result.Add(new CollectedConnection(direction, r.Proto, r.State, r.Local, r.Remote,
                pid == 0 ? null : pid, info?.Name ?? "(unknown)", info?.Exe ?? "",
                info?.Cmdline ?? "", info?.User ?? "", info?.Ppid,
                parent?.Name ?? "", parent?.Exe ?? "", info?.Unit ?? "",
                containerName, info?.ContainerId ?? "", info?.Started, detail));
        }
        return result;
    }

    private sealed record ProcInfo(string Name, int Ppid, string Exe, string Cmdline, string User,
        string Unit, string Container, string ContainerId, DateTime? Started);

    private static ProcInfo? ReadProc(string procRoot, int pid)
    {
        var baseDir = Path.Combine(procRoot, pid.ToString());
        try
        {
            var stat = File.ReadAllText(Path.Combine(baseDir, "stat"));
            var l = stat.IndexOf('('); var r = stat.LastIndexOf(')');
            var name = stat[(l + 1)..r];
            var rest = stat[(r + 2)..].Split(' ');
            var ppid = int.Parse(rest[1]);
            var startTicks = long.Parse(rest[19]);
            var btime = 0L;
            foreach (var line in File.ReadLines(Path.Combine(procRoot, "stat")))
                if (line.StartsWith("btime ")) btime = long.Parse(line.Split(' ')[1]);
            var clk = 100L;
            DateTime? started = btime > 0
                ? DateTimeOffset.FromUnixTimeSeconds(btime + startTicks / clk).UtcDateTime
                : null;
            var cmdline = File.Exists(Path.Combine(baseDir, "cmdline"))
                ? File.ReadAllText(Path.Combine(baseDir, "cmdline")).Replace('\0', ' ').Trim()
                : "";
            string exe = "";
            try { exe = new FileInfo(Path.Combine(baseDir, "exe")).LinkTarget ?? ""; } catch { }
            // If LinkTarget is empty (some runtimes), fall back to the
            // resolved path — still useful, though it loses "(deleted)".
            if (string.IsNullOrEmpty(exe))
            {
                try { exe = File.ResolveLinkTarget(Path.Combine(baseDir, "exe"), false)?.FullName ?? ""; } catch { }
            }
            string user = "";
            try
            {
                foreach (var line in File.ReadLines(Path.Combine(baseDir, "status")))
                    if (line.StartsWith("Uid:")) { user = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)[1]; break; }
            }
            catch { }
            string unit = "", container = "", containerId = "";
            try
            {
                var cgroup = File.ReadAllText(Path.Combine(baseDir, "cgroup"));
                var units = System.Text.RegularExpressions.Regex.Matches(cgroup, @"/([^/\s]+\.(?:service|scope))");
                if (units.Count > 0) unit = units[^1].Groups[1].Value;
                var m = System.Text.RegularExpressions.Regex.Match(cgroup, @"([0-9a-f]{64})");
                if (m.Success) containerId = m.Groups[1].Value;
            }
            catch { }
            return new ProcInfo(name, ppid, exe, cmdline, user, unit, container, containerId, started);
        }
        catch { return null; }
    }

    private static string TcpState(int n) => n switch
    {
        1 => "ESTABLISHED", 2 => "SYN_SENT", 3 => "SYN_RECV", 4 => "FIN_WAIT1",
        5 => "FIN_WAIT2", 6 => "TIME_WAIT", 7 => "CLOSE", 8 => "CLOSE_WAIT",
        9 => "LAST_ACK", 10 => "LISTEN", 11 => "CLOSING", _ => $"STATE_{n:X2}",
    };

    private static string Addr(string hexPort, bool isV6)
    {
        var parts = hexPort.Split(':');
        var ipHex = parts[0]; var port = Convert.ToInt32(parts[1], 16);
        try
        {
            if (isV6)
            {
                var bytes = new byte[16];
                for (var i = 0; i < 4; i++)
                {
                    var chunk = Convert.FromHexString(ipHex.Substring(i * 8, 8));
                    Array.Reverse(chunk);
                    Array.Copy(chunk, 0, bytes, i * 4, 4);
                }
                return $"[{new IPAddress(bytes)}]:{port}";
            }
            var b = Convert.FromHexString(ipHex);
            Array.Reverse(b);
            return $"{new IPAddress(b)}:{port}";
        }
        catch { return hexPort; }
    }

    private static int PortOf(string addr) => int.TryParse(addr[(addr.LastIndexOf(':') + 1)..], out var p) ? p : 0;
    private static string LocalIp(string addr) => addr[..addr.LastIndexOf(':')].Trim('[', ']');
    private static string RemoteIp(string addr) => LocalIp(addr);

    // ---- Windows: netstat -ano ----
    private static readonly Dictionary<string, string> _sigCache = new(StringComparer.OrdinalIgnoreCase);
    private static string SignatureFor(string exe)
    {
        // Windows only. Authenticode certificate presence, not full
        // chain validation: CreateFromSignedFile throws
        // CryptographicException when the file has no certificate.
        // Linux never calls this — signature is "unknown" there,
        // and the unsigned check skips unknown.
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || string.IsNullOrEmpty(exe)) return "unknown";
        if (_sigCache.TryGetValue(exe, out var cached)) return cached;
        string result;
        try
        {
            _ = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(exe);
            result = "signed";
        }
        catch (System.Security.Cryptography.CryptographicException) { result = "unsigned"; }
        catch { result = "unknown"; }
        _sigCache[exe] = result;
        return result;
    }

    private static List<CollectedConnection> WindowsCollect()
    {
        var result = new List<CollectedConnection>();
        foreach (var proto in new[] { "TCP", "UDP" })
        {
            var psi = new ProcessStartInfo("netstat", $"-ano -p {proto}")
            {
                RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true,
            };
            string output;
            using (var p = Process.Start(psi)!)
            {
                output = p.StandardOutput.ReadToEnd();
                p.WaitForExit();
            }
            var listenPorts = new HashSet<int>();
            var parsed = new List<(string Local, string Remote, string State, int Pid)>();
            foreach (var line in output.Split('\n'))
            {
                var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 4 || parts[0] != proto) continue;
                var state = proto == "TCP" ? parts[3] : "UNCONNECTED";
                var pidStr = proto == "TCP" ? parts[4] : parts[3];
                if (!int.TryParse(pidStr, out var pid)) continue;
                if (state == "LISTENING") { listenPorts.Add(PortOf(parts[1])); }
                parsed.Add((parts[1], parts[2], state == "LISTENING" ? "LISTEN" : state, pid));
            }
            foreach (var (local, remote, state, pid) in parsed)
            {
                if (state is "TIME_WAIT" or "CLOSE_WAIT" && false) continue;
                string direction;
                if (state == "LISTEN") direction = "listen";
                else if (remote.StartsWith("127.0.0.1:") || remote.StartsWith("[::1]:"))
                    direction = "local";
                else if (listenPorts.Contains(PortOf(local))) direction = "inbound";
                else direction = "outbound";
                string name = "(unknown)", exe = "", parentName = "", parentExe = "";
                int? ppid = null;
                DateTime? started = null;
                // PID 0 is the System Idle Process. Process.GetProcessById
                // cannot open it on Windows, so without this special case
                // its rows arrive as "(unknown)" with no exe — and no
                // usable identity to hide or whitelist them by.
                if (pid == 0) name = "Idle";
                else try
                {
                    var proc = Process.GetProcessById(pid);
                    name = proc.ProcessName;
                    started = proc.StartTime.ToUniversalTime();
                    try { exe = proc.MainModule?.FileName ?? ""; } catch { }
                    // Parent via WMI is best-effort and Windows-only; skip if unavailable.
                }
                catch { }
                result.Add(new CollectedConnection(direction, proto.ToLowerInvariant(), state, local, remote,
                    pid, name, exe, "", "", ppid, parentName, parentExe, "", "", "", started, "", SignatureFor(exe)));
            }
        }
        return result;
    }
}
