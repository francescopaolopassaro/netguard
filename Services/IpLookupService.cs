using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using NetGuard.Models;

namespace NetGuard.Services;

/// <summary>
/// IP geolocation lookup using ip-api.com (free, no key required, 45 req/min).
/// Also maintains a static table of well-known dangerous ports.
/// </summary>
public class IpLookupService
{
    private readonly HttpClient _http;
    private readonly Dictionary<string, GeoInfo> _geoCache = new();
    private DateTime _lastCall = DateTime.MinValue;
    private const int MinIntervalMs = 1_400; // 45 req/min = ~1.33 s/req

    public IpLookupService()
    {
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
    }

    // ── Geolocation ───────────────────────────────────────────
    public async Task<GeoInfo?> LookupIpAsync(string ip)
    {
        if (!IsPublicIp(ip)) return null;
        if (_geoCache.TryGetValue(ip, out var cached)) return cached;

        // Rate-limit ip-api.com
        var elapsed = (DateTime.UtcNow - _lastCall).TotalMilliseconds;
        if (elapsed < MinIntervalMs)
            await Task.Delay((int)(MinIntervalMs - elapsed));
        _lastCall = DateTime.UtcNow;

        try
        {
            var url      = $"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,isp,org,as,proxy,hosting,query";
            var response = await _http.GetAsync(url);
            if (!response.IsSuccessStatusCode) return null;

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var root      = doc.RootElement;

            if (root.GetProperty("status").GetString() != "success") return null;

            var info = new GeoInfo
            {
                Ip          = ip,
                Country     = root.TryGetProperty("country",     out var c)  ? c.GetString()  ?? "" : "",
                CountryCode = root.TryGetProperty("countryCode", out var cc) ? cc.GetString() ?? "" : "",
                Region      = root.TryGetProperty("regionName",  out var r)  ? r.GetString()  ?? "" : "",
                City        = root.TryGetProperty("city",        out var ci) ? ci.GetString() ?? "" : "",
                Isp         = root.TryGetProperty("isp",         out var i)  ? i.GetString()  ?? "" : "",
                Org         = root.TryGetProperty("org",         out var o)  ? o.GetString()  ?? "" : "",
                IsProxy     = root.TryGetProperty("proxy",   out var p)  && p.GetBoolean(),
                IsHosting   = root.TryGetProperty("hosting", out var h)  && h.GetBoolean(),
                LookedUpAt  = DateTime.UtcNow
            };

            // Hosting + proxy = extra suspicious
            if (info.IsProxy || info.IsHosting)
                info.RiskNote = "VPN/proxy or hosting provider — elevated risk";

            _geoCache[ip] = info;
            return info;
        }
        catch { return null; }
    }

    // ── Port risk assessment ──────────────────────────────────
    public static PortRisk AssessPort(int port, string protocol = "TCP")
    {
        // Well-known dangerous / abused ports
        var dangerous = new Dictionary<int, string>
        {
            [23]    = "Telnet — plaintext, often used by malware C2",
            [135]   = "MS RPC — common attack surface",
            [139]   = "NetBIOS — frequently exploited",
            [445]   = "SMB — WannaCry/EternalBlue target",
            [1080]  = "SOCKS proxy",
            [1433]  = "MSSQL — database exposure",
            [3389]  = "RDP — frequent brute-force target",
            [4444]  = "Metasploit default listener",
            [4899]  = "Radmin remote admin",
            [5900]  = "VNC — plaintext remote desktop",
            [6666]  = "IRC — historically used by botnets",
            [6667]  = "IRC — historically used by botnets",
            [6668]  = "IRC botnet",
            [6669]  = "IRC botnet",
            [9001]  = "Tor relay default",
            [9050]  = "Tor SOCKS proxy",
            [9150]  = "Tor Browser",
            [31337] = "Back Orifice / elite hacker port",
            [12345] = "NetBus trojan",
            [27374] = "SubSeven trojan",
            [65535] = "Common C2 high port"
        };

        // Safe / expected outbound ports
        var safe = new HashSet<int>
        { 80, 443, 8080, 8443, 53, 853, 22, 25, 587, 993, 995, 143, 110, 21, 20, 123 };

        if (dangerous.TryGetValue(port, out var note))
            return new PortRisk
            {
                Port  = port,
                Level = ThreatLevel.Medium,
                Note  = note
            };

        if (safe.Contains(port))
            return new PortRisk { Port = port, Level = ThreatLevel.Clean, Note = "Common safe port" };

        // High ephemeral ports are usually fine; low uncommon ports are more suspicious
        var level = port switch
        {
            < 1024  => ThreatLevel.Low,
            < 10000 => ThreatLevel.Unknown,
            _       => ThreatLevel.Clean   // high ephemeral
        };

        return new PortRisk { Port = port, Level = level };
    }

    // ── Helpers ───────────────────────────────────────────────
    private static bool IsPublicIp(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr)) return false;
        var bytes = addr.GetAddressBytes();
        if (bytes.Length != 4) return false; // skip IPv6 for now

        return !(bytes[0] == 10
            || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
            || (bytes[0] == 192 && bytes[1] == 168)
            || bytes[0] == 127
            || bytes[0] == 169 && bytes[1] == 254
            || bytes[0] == 0);
    }
}

// ── DTOs ─────────────────────────────────────────────────────
public class GeoInfo
{
    public string   Ip          { get; set; } = "";
    public string   Country     { get; set; } = "";
    public string   CountryCode { get; set; } = "";
    public string   Region      { get; set; } = "";
    public string   City        { get; set; } = "";
    public string   Isp         { get; set; } = "";
    public string   Org         { get; set; } = "";
    public bool     IsProxy     { get; set; }
    public bool     IsHosting   { get; set; }
    public string   RiskNote    { get; set; } = "";
    public DateTime LookedUpAt  { get; set; }

    public string DisplayLocation =>
        string.IsNullOrEmpty(City)
            ? Country
            : $"{City}, {Country} {CountryCode}";
}

public class PortRisk
{
    public int        Port  { get; set; }
    public ThreatLevel Level { get; set; }
    public string      Note  { get; set; } = "";
}
