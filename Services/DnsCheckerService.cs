using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using NetGuard.Models;

namespace NetGuard.Services;

/// <summary>
/// Checks domains and IPs using DNS over HTTPS (DoH).
/// Primary: Quad9 (blocks malicious domains by default).
/// Secondary: Cloudflare / any configured server.
/// </summary>
public class DnsCheckerService
{
    private readonly HttpClient _http;
    private readonly AppSettings _settings;
    private readonly Dictionary<string, DnsCheckResult> _cache = new();

    private const string Quad9DoH      = "https://dns.quad9.net/dns-query";
    private const string CloudflareDoH = "https://cloudflare-dns.com/dns-query";

    public DnsCheckerService(AppSettings settings)
    {
        _settings = settings;
        _http = new HttpClient();
        _http.DefaultRequestHeaders.Add("Accept", "application/dns-json");
        _http.Timeout = TimeSpan.FromSeconds(5);
    }

    // ── Public API ────────────────────────────────────────────

    /// <summary>
    /// Resolves a domain via the configured DoH server.
    /// Returns null IPs if Quad9 has blocked the domain (NXDOMAIN response).
    /// </summary>
    public async Task<DnsCheckResult> CheckDomainAsync(string domain)
    {
        domain = domain.ToLowerInvariant().TrimEnd('.');
        if (_cache.TryGetValue(domain, out var cached)
            && DateTime.UtcNow - cached.CheckedAt < TimeSpan.FromMinutes(15))
            return cached;

        var result = new DnsCheckResult { Domain = domain };

        // ── Primary: Quad9 (malware-blocking DNS) ─────────────
        try
        {
            var q9 = await QueryDoHAsync(Quad9DoH, domain, "A");
            result.Quad9Blocked = q9.Status == 3; // NXDOMAIN = blocked by Quad9
            result.Quad9Ips     = q9.Answers;
        }
        catch (Exception ex) { result.Quad9Error = ex.Message; }

        // ── Secondary: Cloudflare (no filtering — get real IPs) ─
        try
        {
            var cf = await QueryDoHAsync(CloudflareDoH, domain, "A");
            result.CloudflareIps = cf.Answers;
        }
        catch (Exception ex) { result.CloudflareError = ex.Message; }

        // ── Threat Assessment ─────────────────────────────────
        if (result.Quad9Blocked)
        {
            result.ThreatLevel = ThreatLevel.High;
            result.Detail      = "Domain blocked by Quad9 malware-filtering DNS";
        }
        else if (result.Quad9Ips.Count == 0 && result.CloudflareIps.Count > 0)
        {
            // Quad9 returned SERVFAIL or no answer while CF resolved fine — suspicious
            result.ThreatLevel = ThreatLevel.Medium;
            result.Detail      = "Quad9 returned no answer — possible filtering";
        }
        else
        {
            result.ThreatLevel = ThreatLevel.Clean;
        }

        result.CheckedAt = DateTime.UtcNow;
        _cache[domain] = result;
        return result;
    }

    /// <summary>
    /// Checks whether an IP is known-malicious via reverse PTR + Quad9 check.
    /// </summary>
    public async Task<DnsCheckResult> CheckIpAsync(string ip)
    {
        if (_cache.TryGetValue(ip, out var cached)
            && DateTime.UtcNow - cached.CheckedAt < TimeSpan.FromMinutes(15))
            return cached;

        var result = new DnsCheckResult { Domain = ip };

        try
        {
            // Check PTR record via Quad9 DoH
            var arpaName = BuildArpaName(ip);
            if (arpaName != null)
            {
                var ptr = await QueryDoHAsync(Quad9DoH, arpaName, "PTR");
                result.Quad9Blocked = ptr.Status == 3;
                result.PtrRecord    = ptr.Answers.FirstOrDefault() ?? "";
            }
        }
        catch (Exception ex) { result.Quad9Error = ex.Message; }

        result.ThreatLevel = result.Quad9Blocked ? ThreatLevel.High : ThreatLevel.Unknown;
        result.CheckedAt   = DateTime.UtcNow;
        _cache[ip] = result;
        return result;
    }

    // ── DoH Query ────────────────────────────────────────────
    private async Task<DoHResponse> QueryDoHAsync(string server, string name, string type)
    {
        var url      = $"{server}?name={Uri.EscapeDataString(name)}&type={type}";
        var response = await _http.GetAsync(url);
        if (!response.IsSuccessStatusCode)
            return new DoHResponse { Status = -1 };

        using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = doc.RootElement;

        var status  = root.GetProperty("Status").GetInt32();
        var answers = new List<string>();

        if (root.TryGetProperty("Answer", out var answerArr))
            foreach (var a in answerArr.EnumerateArray())
                if (a.TryGetProperty("data", out var data))
                    answers.Add(data.GetString() ?? "");

        return new DoHResponse { Status = status, Answers = answers };
    }

    // ── Helpers ───────────────────────────────────────────────
    private static string? BuildArpaName(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr)) return null;
        var bytes = addr.GetAddressBytes();
        return string.Join(".", bytes.Reverse()) + ".in-addr.arpa";
    }

    private record DoHResponse
    {
        public int          Status  { get; init; }
        public List<string> Answers { get; init; } = new();
    }
}

public class DnsCheckResult
{
    public string      Domain          { get; set; } = "";
    public bool        Quad9Blocked    { get; set; }
    public List<string>Quad9Ips       { get; set; } = new();
    public List<string>CloudflareIps  { get; set; } = new();
    public string      PtrRecord       { get; set; } = "";
    public string?     Quad9Error      { get; set; }
    public string?     CloudflareError { get; set; }
    public ThreatLevel ThreatLevel     { get; set; } = ThreatLevel.Unknown;
    public string      Detail          { get; set; } = "";
    public DateTime    CheckedAt       { get; set; }
}
