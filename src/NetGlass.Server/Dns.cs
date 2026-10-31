using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace NetGlass.Server;

/// <summary>
/// IP parsing + privacy helpers, and the local reverse-DNS service.
///
/// Design, per the user's rule:
/// - Reverse DNS (PTR) is automatic but LOCAL only: it uses the
///   server's own resolver (Dns.GetHostEntryAsync), never a public
///   API, and never for a private IP via an external service.
/// - ip-api.com enrichment is NEVER automatic. It is only fetched
///   from POST /api/ip-info, when the user clicks Fetch for one IP,
///   and the result is cached for 30 days (force refresh bypasses
///   the cache). Private/special IPs are never sent to ip-api.
/// - Both results are cached server-side (SQLite, see RecordingStore),
///   so a snapshot poll every 2s never re-queries the same IP.
/// </summary>
public static class IpHelpers
{
    // "1.2.3.4:443" -> "1.2.3.4"; "[2001:db8::1]:443" -> "2001:db8::1";
    // "0.0.0.0:0" / ":::0" -> null (no real remote).
    public static string? ParseIp(string addr)
    {
        if (string.IsNullOrWhiteSpace(addr)) return null;
        string ip;
        if (addr.StartsWith("["))
        {
            var end = addr.IndexOf(']');
            if (end < 0) return null;
            ip = addr[1..end];
        }
        else
        {
            // IPv6 without brackets has many colons; IPv4:port has one.
            var lastColon = addr.LastIndexOf(':');
            ip = lastColon > 0 && addr.Count(c => c == ':') == 1
                ? addr[..lastColon] : addr;
            if (ip.Contains(':') && !IPAddress.TryParse(ip, out _)) return null;
        }
        if (!IPAddress.TryParse(ip, out var parsed)) return null;
        if (IPAddress.IsLoopback(parsed)) return ip;
        if (parsed.Equals(IPAddress.Any) || parsed.Equals(IPAddress.IPv6Any)) return null;
        return ip;
    }

    public static bool IsPublic(string ip)
    {
        if (!IPAddress.TryParse(ip, out var a)) return false;
        if (IPAddress.IsLoopback(a)) return false;
        if (a.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = a.GetAddressBytes();
            if (b[0] == 10) return false;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return false;
            if (b[0] == 192 && b[1] == 168) return false;
            if (b[0] == 169 && b[1] == 254) return false;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return false;
            if (b[0] >= 224) return false; // multicast + reserved
            if (b[0] == 0) return false;
            return true;
        }
        // IPv6: link-local fe80::/10, unique-local fc00::/7, loopback handled above.
        var bytes = a.GetAddressBytes();
        if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80) return false;
        if (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0xc0) return false; // site-local fec0::/10
        if ((bytes[0] & 0xfe) == 0xfc) return false;
        return !a.IsIPv6LinkLocal;
    }
}

public sealed class ReverseDnsService
{
    private readonly RecordingStore _store;
    private readonly ConcurrentDictionary<string, byte> _inFlight = new();

    public ReverseDnsService(RecordingStore store) => _store = store;

    // Cached hostname, or null if none cached (fresh or not). Does not trigger a lookup.
    public string? GetCached(string ip)
    {
        var entry = _store.GetDns(ip);
        if (entry is null || entry.Value.ExpiresAt <= DateTime.UtcNow) return null;
        return string.IsNullOrEmpty(entry.Value.Hostname) ? null : entry.Value.Hostname;
    }

    // Fire-and-forget from the connections endpoint: resolve in the
    // background if not already cached (fresh) or already in flight.
    // The next 2s poll then shows the hostname.
    public void EnsureResolved(string ip)
    {
        if (string.IsNullOrWhiteSpace(ip)) return;
        var entry = _store.GetDns(ip);
        if (entry is not null && entry.Value.ExpiresAt > DateTime.UtcNow) return;
        if (!_inFlight.TryAdd(ip, 0)) return;
        _ = Task.Run(async () =>
        {
            try
            {
                string hostname = "";
                if (ip == "127.0.0.1" || ip == "::1")
                {
                    hostname = "localhost";
                }
                else
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(3));
                    try
                    {
                        var host = await Dns.GetHostEntryAsync(ip, cts.Token);
                        hostname = host.HostName ?? "";
                        if (hostname == ip) hostname = "";
                    }
                    catch { hostname = ""; }
                }
                // Success (even an empty PTR answer) is cached so we
                // don't re-query every poll: 24h for a name, 1h for
                // "no PTR" (negative cache, retries reasonably soon).
                var ttl = string.IsNullOrEmpty(hostname) ? TimeSpan.FromHours(1) : TimeSpan.FromHours(24);
                _store.SetDns(ip, hostname, "local", DateTime.UtcNow.Add(ttl));
            }
            catch { /* DNS failure must never break the connections view */ }
            finally { _inFlight.TryRemove(ip, out _); }
        });
    }
}
