using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using NetGuard.Models;

namespace NetGuard.Services;

/// <summary>
/// Aggregates results from multiple threat intelligence sources:
///   • VirusTotal v3 API  — file hash + URL scan
///   • MalwareBazaar       — SHA-256 hash lookup (no API key required)
///   • AbuseIPDB           — IP reputation check
/// Results are cached in SQLite (24h TTL).
/// </summary>
public class ThreatIntelService
{
    private readonly HttpClient    _http;
    private readonly DatabaseService _db;
    private AppSettings _settings;

    // Rate-limit: VirusTotal free tier = 4 requests/min
    private readonly SemaphoreSlim _vtLimiter = new(1, 1);
    private DateTime _lastVtCall = DateTime.MinValue;
    private const int VtMinIntervalMs = 15_500; // ~4 req/min with margin

    public ThreatIntelService(DatabaseService db, AppSettings settings)
    {
        _db       = db;
        _settings = settings;
        _http     = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
    }

    public void UpdateSettings(AppSettings s) => _settings = s;

    // ── Public API ────────────────────────────────────────────

    /// <summary>
    /// Checks a SHA-256 file hash against MalwareBazaar and VirusTotal.
    /// Returns the most severe result found.
    /// </summary>
    public async Task<ThreatResult> CheckHashAsync(string sha256)
    {
        if (string.IsNullOrEmpty(sha256))
            return new ThreatResult { Level = ThreatLevel.Unknown };

        // Check local cache first
        var cached = await _db.GetCachedThreatAsync(sha256);
        if (cached != null) return cached;

        // MalwareBazaar first (no API key, fast)
        var mbResult = await CheckMalwareBazaarAsync(sha256);

        // VirusTotal if we have an API key and MB didn't find it malicious
        ThreatResult? vtResult = null;
        if (!string.IsNullOrEmpty(_settings.VirusTotalApiKey)
            && mbResult.Level < ThreatLevel.High)
            vtResult = await CheckVirusTotalHashAsync(sha256);

        // Return worst result
        var best = vtResult != null && vtResult.Level > mbResult.Level
            ? vtResult : mbResult;

        await _db.CacheThreatAsync(best);
        return best;
    }

    /// <summary>
    /// Checks an IP address against AbuseIPDB and VirusTotal.
    /// </summary>
    public async Task<ThreatResult> CheckIpAsync(string ip)
    {
        if (string.IsNullOrEmpty(ip))
            return new ThreatResult { Level = ThreatLevel.Unknown };

        var cached = await _db.GetCachedThreatAsync(ip);
        if (cached != null) return cached;

        var result = await CheckAbuseIpDbAsync(ip);
        await _db.CacheThreatAsync(result);
        return result;
    }

    /// <summary>
    /// Checks a domain or URL against VirusTotal.
    /// </summary>
    public async Task<ThreatResult> CheckUrlAsync(string url)
    {
        if (string.IsNullOrEmpty(_settings.VirusTotalApiKey))
            return new ThreatResult { Level = ThreatLevel.Unknown, Detail = "No VirusTotal API key configured" };

        var cached = await _db.GetCachedThreatAsync(url);
        if (cached != null) return cached;

        var result = await CheckVirusTotalUrlAsync(url);
        await _db.CacheThreatAsync(result);
        return result;
    }

    // ── MalwareBazaar ─────────────────────────────────────────
    private async Task<ThreatResult> CheckMalwareBazaarAsync(string sha256)
    {
        var result = new ThreatResult
        {
            Query  = sha256,
            Source = "MalwareBazaar"
        };
        try
        {
            var content = new StringContent(
                $"query=get_info&hash={sha256}",
                Encoding.UTF8,
                "application/x-www-form-urlencoded");

            var response = await _http.PostAsync(
                "https://mb-api.abuse.ch/api/v1/", content);

            if (!response.IsSuccessStatusCode)
            {
                result.Level = ThreatLevel.Unknown;
                return result;
            }

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var root      = doc.RootElement;
            var status    = root.GetProperty("query_status").GetString();

            if (status == "hash_not_found")
            {
                result.Level = ThreatLevel.Unknown; // not in DB, can't confirm clean
                return result;
            }

            if (status == "ok" && root.TryGetProperty("data", out var data))
            {
                var first    = data[0];
                var malware  = first.TryGetProperty("signature", out var sig)
                    ? sig.GetString() ?? ""
                    : "";
                var tags     = first.TryGetProperty("tags", out var tagsEl)
                    ? string.Join(", ", tagsEl.EnumerateArray().Select(t => t.GetString()))
                    : "";

                result.Level       = ThreatLevel.High;
                result.MalwareName = malware;
                result.Detail      = $"MalwareBazaar: {malware} [{tags}]";
                result.Permalink   = $"https://bazaar.abuse.ch/sample/{sha256}";
            }
        }
        catch (Exception ex)
        {
            result.Level  = ThreatLevel.Unknown;
            result.Detail = $"MalwareBazaar error: {ex.Message}";
        }
        return result;
    }

    // ── VirusTotal — File Hash ────────────────────────────────
    private async Task<ThreatResult> CheckVirusTotalHashAsync(string sha256)
    {
        await ThrottleVirusTotalAsync();
        var result = new ThreatResult
        {
            Query  = sha256,
            Source = "VirusTotal"
        };
        try
        {
            _http.DefaultRequestHeaders.Remove("x-apikey");
            _http.DefaultRequestHeaders.Add("x-apikey", _settings.VirusTotalApiKey);

            var response = await _http.GetAsync(
                $"https://www.virustotal.com/api/v3/files/{sha256}");

            if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                result.Level = ThreatLevel.Unknown;
                return result;
            }
            if (!response.IsSuccessStatusCode)
            {
                result.Level = ThreatLevel.Unknown;
                return result;
            }

            return ParseVirusTotalFileResponse(
                await response.Content.ReadAsStringAsync(), sha256);
        }
        catch (Exception ex)
        {
            result.Level  = ThreatLevel.Unknown;
            result.Detail = $"VirusTotal error: {ex.Message}";
            return result;
        }
    }

    // ── VirusTotal — URL/Domain ───────────────────────────────
    private async Task<ThreatResult> CheckVirusTotalUrlAsync(string url)
    {
        await ThrottleVirusTotalAsync();
        var result = new ThreatResult { Query = url, Source = "VirusTotal" };
        try
        {
            _http.DefaultRequestHeaders.Remove("x-apikey");
            _http.DefaultRequestHeaders.Add("x-apikey", _settings.VirusTotalApiKey);

            // URL ID = base64url(url) without padding
            var urlId = Convert.ToBase64String(Encoding.UTF8.GetBytes(url))
                .TrimEnd('=').Replace('+', '-').Replace('/', '_');

            var response = await _http.GetAsync(
                $"https://www.virustotal.com/api/v3/urls/{urlId}");

            if (!response.IsSuccessStatusCode)
            {
                result.Level = ThreatLevel.Unknown;
                return result;
            }

            using var doc  = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var stats      = doc.RootElement
                .GetProperty("data")
                .GetProperty("attributes")
                .GetProperty("last_analysis_stats");

            result.Detections   = stats.GetProperty("malicious").GetInt32();
            result.TotalEngines = result.Detections
                + stats.GetProperty("harmless").GetInt32()
                + stats.GetProperty("suspicious").GetInt32()
                + stats.GetProperty("undetected").GetInt32();

            result.Level = ClassifyDetections(result.Detections, result.TotalEngines);
            result.Permalink = $"https://www.virustotal.com/gui/url/{urlId}";
        }
        catch (Exception ex)
        {
            result.Level  = ThreatLevel.Unknown;
            result.Detail = ex.Message;
        }
        return result;
    }

    // ── AbuseIPDB ─────────────────────────────────────────────
    private async Task<ThreatResult> CheckAbuseIpDbAsync(string ip)
    {
        var result = new ThreatResult { Query = ip, Source = "AbuseIPDB" };

        if (string.IsNullOrEmpty(_settings.AbuseIpDbApiKey))
        {
            result.Level  = ThreatLevel.Unknown;
            result.Detail = "No AbuseIPDB API key configured";
            return result;
        }

        try
        {
            _http.DefaultRequestHeaders.Remove("Key");
            _http.DefaultRequestHeaders.Remove("Accept");
            _http.DefaultRequestHeaders.Add("Key",    _settings.AbuseIpDbApiKey);
            _http.DefaultRequestHeaders.Add("Accept", "application/json");

            var response = await _http.GetAsync(
                $"https://api.abuseipdb.com/api/v2/check?ipAddress={Uri.EscapeDataString(ip)}&maxAgeInDays=90");

            if (!response.IsSuccessStatusCode)
            {
                result.Level = ThreatLevel.Unknown;
                return result;
            }

            using var doc = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            var data      = doc.RootElement.GetProperty("data");

            var score     = data.GetProperty("abuseConfidenceScore").GetInt32();
            var reports   = data.GetProperty("totalReports").GetInt32();
            var country   = data.TryGetProperty("countryCode", out var cc) ? cc.GetString() : "";

            result.Detail      = $"Abuse score: {score}/100, Reports: {reports}, Country: {country}";
            result.Detections  = reports;
            result.Level = score switch
            {
                >= 75 => ThreatLevel.High,
                >= 40 => ThreatLevel.Medium,
                >= 10 => ThreatLevel.Low,
                _     => ThreatLevel.Clean
            };
            result.Permalink   = $"https://www.abuseipdb.com/check/{ip}";
        }
        catch (Exception ex)
        {
            result.Level  = ThreatLevel.Unknown;
            result.Detail = ex.Message;
        }
        return result;
    }

    // ── Helpers ───────────────────────────────────────────────

    private static ThreatResult ParseVirusTotalFileResponse(string json, string sha256)
    {
        using var doc = JsonDocument.Parse(json);
        var attrs     = doc.RootElement.GetProperty("data").GetProperty("attributes");
        var stats     = attrs.GetProperty("last_analysis_stats");
        var malicious = stats.GetProperty("malicious").GetInt32();
        var total     = malicious
            + stats.GetProperty("harmless").GetInt32()
            + stats.GetProperty("suspicious").GetInt32()
            + stats.GetProperty("undetected").GetInt32();

        var name = "";
        if (attrs.TryGetProperty("meaningful_name", out var mn)) name = mn.GetString() ?? "";

        return new ThreatResult
        {
            Query        = sha256,
            Source       = "VirusTotal",
            Detections   = malicious,
            TotalEngines = total,
            MalwareName  = name,
            Level        = ClassifyDetections(malicious, total),
            Permalink    = $"https://www.virustotal.com/gui/file/{sha256}"
        };
    }

    private static ThreatLevel ClassifyDetections(int detections, int total)
    {
        if (total == 0)     return ThreatLevel.Unknown;
        double ratio = (double)detections / total;
        return detections switch
        {
            0       => ThreatLevel.Clean,
            <= 2    => ThreatLevel.Low,
            <= 5    => ThreatLevel.Medium,
            _       => ThreatLevel.High
        };
    }

    private async Task ThrottleVirusTotalAsync()
    {
        await _vtLimiter.WaitAsync();
        try
        {
            var elapsed = (DateTime.UtcNow - _lastVtCall).TotalMilliseconds;
            if (elapsed < VtMinIntervalMs)
                await Task.Delay((int)(VtMinIntervalMs - elapsed));
            _lastVtCall = DateTime.UtcNow;
        }
        finally { _vtLimiter.Release(); }
    }
}
