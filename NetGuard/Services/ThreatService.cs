using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using NetGuard.Models;

namespace NetGuard.Services;

public class ThreatService
{
    private readonly HttpClient _http;
    private AppSettings _cfg;
    private readonly string _dbPath;
    private DateTime _lastVt = DateTime.MinValue;
    private const int VtDelay = 16_000; // 4 req/min

    public ThreatService(AppSettings cfg)
    {
        _cfg  = cfg;
        _http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
        _http.DefaultRequestHeaders.Add("Accept", "application/dns-json");

        _dbPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "NetGuard", "threats.db");
        Directory.CreateDirectory(Path.GetDirectoryName(_dbPath)!);
        InitDb();
    }

    public void UpdateConfig(AppSettings cfg) => _cfg = cfg;

    // ── Hash (MalwareBazaar + VirusTotal) ────────────────────────────────

    public async Task<(ThreatLevel Level, string Detail)> CheckHashAsync(string sha256)
    {
        if (string.IsNullOrEmpty(sha256)) return (ThreatLevel.Unknown, "");

        // 1. SQLite cache (24h)
        var cached = GetCached(sha256);
        if (cached.HasValue) return cached.Value;

        // 2. MalwareBazaar (free, no key)
        var mb = await QueryMalwareBazaarAsync(sha256);
        if (mb.Level >= ThreatLevel.High) { Cache(sha256, mb); return mb; }

        // 3. VirusTotal (if API key configured)
        if (!string.IsNullOrEmpty(_cfg.VirusTotalApiKey))
        {
            var vt = await QueryVirusTotalHashAsync(sha256);
            if (vt.Level > mb.Level) { Cache(sha256, vt); return vt; }
        }

        Cache(sha256, mb);
        return mb;
    }

    // ── IP reputation (AbuseIPDB) ─────────────────────────────────────────

    public async Task<(ThreatLevel Level, string Detail)> CheckIpAsync(string ip)
    {
        if (string.IsNullOrEmpty(ip) || string.IsNullOrEmpty(_cfg.AbuseIpDbApiKey))
            return (ThreatLevel.Unknown, "");

        var cached = GetCached(ip);
        if (cached.HasValue) return cached.Value;

        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get,
                $"https://api.abuseipdb.com/api/v2/check?ipAddress={Uri.EscapeDataString(ip)}&maxAgeInDays=90");
            req.Headers.Add("Key", _cfg.AbuseIpDbApiKey);
            req.Headers.Add("Accept", "application/json");

            var resp = await _http.SendAsync(req);
            if (!resp.IsSuccessStatusCode) return (ThreatLevel.Unknown, "AbuseIPDB error");

            using var doc  = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            var data       = doc.RootElement.GetProperty("data");
            var score      = data.GetProperty("abuseConfidenceScore").GetInt32();
            var reports    = data.GetProperty("totalReports").GetInt32();
            var country    = data.TryGetProperty("countryCode", out var cc) ? cc.GetString() : "";

            var level  = score >= 75 ? ThreatLevel.High
                       : score >= 40 ? ThreatLevel.Medium
                       : score >= 10 ? ThreatLevel.Low
                                     : ThreatLevel.Clean;
            var detail = $"AbuseIPDB score {score}/100 · {reports} reports · {country}";
            var result = (level, detail);
            Cache(ip, result);
            return result;
        }
        catch (Exception ex) { return (ThreatLevel.Unknown, ex.Message); }
    }

    // ── DNS reputation (Quad9 DoH) ────────────────────────────────────────

    public async Task<(bool Blocked, string Detail)> CheckDomainAsync(string domain)
    {
        if (string.IsNullOrEmpty(domain)) return (false, "");

        // Funzione locale "blindata"
        async Task<(bool Success, bool Blocked, string Detail)> TryQueryDoHAsync(string url, string providerName)
        {
            try
            {
                // CREA UNA NUOVA RICHIESTA PER EVITARE COLLISIONI DI HEADER
                using var request = new HttpRequestMessage(HttpMethod.Get, url);

                // Aggiungi gli header solo a questa specifica richiesta
                request.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/dns-json"));
                request.Headers.UserAgent.ParseAdd("NetGuard/1.0 (+https://example)");

                // Invia la richiesta specifica (non usare GetAsync(url) che usa DefaultRequestHeaders)
                var resp = await _http.SendAsync(request);

                if (resp == null) return (false, false, $"Nessuna risposta da {providerName}");
                if (!resp.IsSuccessStatusCode)
                    return (false, false, $"{providerName} status: {(int)resp.StatusCode}");

                var text = await resp.Content.ReadAsStringAsync();
                if (string.IsNullOrWhiteSpace(text)) return (false, false, "Empty body");

                using var doc = JsonDocument.Parse(text);
                var root = doc.RootElement;

                int? status = null;
                if (root.TryGetProperty("Status", out var st1)) status = st1.GetInt32();
                else if (root.TryGetProperty("status", out var st2)) status = st2.GetInt32();

                if (status == 3) // NXDOMAIN
                {
                    string msg = providerName == "Quad9" ? "Bloccato da Quad9 (Malware)" : "Non esistente (Google)";
                    return (true, true, msg);
                }

                return (true, false, $"OK su {providerName}");
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Fallimento {providerName}: {ex.Message}");
                return (false, false, ex.Message);
            }
        }

        // 1. Tenta prima Google (per vedere se esiste)
        var googleResult = await TryQueryDoHAsync($"https://8.8.8.8/resolve?name={Uri.EscapeDataString(domain)}&type=A", "Google DNS");
        if (googleResult.Success) return (googleResult.Blocked, googleResult.Detail);

        // 2. Fallback su Quad9
        var q9Result = await TryQueryDoHAsync($"https://dns.quad9.net/dns-query?name={Uri.EscapeDataString(domain)}&type=A", "Quad9");
        if (q9Result.Success) return (q9Result.Blocked, q9Result.Detail);

        return (false, "Sorgenti DNS non raggiungibili");
    }

    // ── MalwareBazaar ─────────────────────────────────────────────────────

    private async Task<(ThreatLevel Level, string Detail)> QueryMalwareBazaarAsync(string sha256)
    {
        try
        {
            var content  = new StringContent(
                $"query=get_info&hash={sha256}",
                Encoding.UTF8, "application/x-www-form-urlencoded");
            var resp = await _http.PostAsync("https://mb-api.abuse.ch/api/v1/", content);
            if (!resp.IsSuccessStatusCode) return (ThreatLevel.Unknown, "");

            using var doc  = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            var status     = doc.RootElement.GetProperty("query_status").GetString();
            if (status == "hash_not_found") return (ThreatLevel.Unknown, "Not in MalwareBazaar");
            if (status != "ok")             return (ThreatLevel.Unknown, status ?? "");

            var first   = doc.RootElement.GetProperty("data")[0];
            var malware = first.TryGetProperty("signature", out var s) ? s.GetString() ?? "" : "";
            var tags    = first.TryGetProperty("tags", out var t)
                ? string.Join(", ", t.EnumerateArray().Select(x => x.GetString()))
                : "";
            return (ThreatLevel.High, $"MalwareBazaar: {malware} [{tags}]");
        }
        catch { return (ThreatLevel.Unknown, ""); }
    }

    // ── VirusTotal ─────────────────────────────────────────────────────────

    private async Task<(ThreatLevel Level, string Detail)> QueryVirusTotalHashAsync(string sha256)
    {
        // Throttle to 4 req/min
        var wait = VtDelay - (int)(DateTime.UtcNow - _lastVt).TotalMilliseconds;
        if (wait > 0) await Task.Delay(wait);
        _lastVt = DateTime.UtcNow;

        try
        {
            _http.DefaultRequestHeaders.Remove("x-apikey");
            _http.DefaultRequestHeaders.Add("x-apikey", _cfg.VirusTotalApiKey);

            var resp = await _http.GetAsync($"https://www.virustotal.com/api/v3/files/{sha256}");
            if (resp.StatusCode == System.Net.HttpStatusCode.NotFound)
                return (ThreatLevel.Unknown, "Not in VirusTotal");
            if (!resp.IsSuccessStatusCode) return (ThreatLevel.Unknown, "VT error");

            using var doc   = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            var stats        = doc.RootElement
                .GetProperty("data").GetProperty("attributes")
                .GetProperty("last_analysis_stats");
            var malicious    = stats.GetProperty("malicious").GetInt32();
            var total        = malicious
                + stats.GetProperty("harmless").GetInt32()
                + stats.GetProperty("suspicious").GetInt32()
                + stats.GetProperty("undetected").GetInt32();

            var level  = malicious == 0    ? ThreatLevel.Clean
                       : malicious <= 2    ? ThreatLevel.Low
                       : malicious <= 5    ? ThreatLevel.Medium
                       : malicious <= 15   ? ThreatLevel.High
                                           : ThreatLevel.Critical;
            return (level, $"VirusTotal {malicious}/{total} engines");
        }
        catch { return (ThreatLevel.Unknown, ""); }
    }

    // ── SQLite cache ──────────────────────────────────────────────────────

    private void InitDb()
    {
        using var conn = Open();
        using var cmd  = conn.CreateCommand();
        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS cache (
                key        TEXT PRIMARY KEY,
                level      INTEGER,
                detail     TEXT,
                checked_at TEXT
            )
            """;
        cmd.ExecuteNonQuery();
    }

    private (ThreatLevel Level, string Detail)? GetCached(string key)
    {
        try
        {
            using var conn = Open();
            using var cmd  = conn.CreateCommand();
            cmd.CommandText = "SELECT level,detail,checked_at FROM cache WHERE key=@k";
            cmd.Parameters.AddWithValue("@k", key);
            using var r = cmd.ExecuteReader();
            if (!r.Read()) return null;
            if (DateTime.UtcNow - DateTime.Parse(r.GetString(2)) > TimeSpan.FromHours(24))
                return null;
            return ((ThreatLevel)r.GetInt32(0), r.GetString(1));
        }
        catch { return null; }
    }

    private void Cache(string key, (ThreatLevel Level, string Detail) result)
    {
        try
        {
            using var conn = Open();
            using var cmd  = conn.CreateCommand();
            cmd.CommandText = """
                INSERT OR REPLACE INTO cache (key,level,detail,checked_at)
                VALUES (@k,@l,@d,@t)
                """;
            cmd.Parameters.AddWithValue("@k", key);
            cmd.Parameters.AddWithValue("@l", (int)result.Level);
            cmd.Parameters.AddWithValue("@d", result.Detail);
            cmd.Parameters.AddWithValue("@t", DateTime.UtcNow.ToString("O"));
            cmd.ExecuteNonQuery();
        }
        catch { }
    }

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection($"Data Source={_dbPath}");
        conn.Open();
        return conn;
    }
}
