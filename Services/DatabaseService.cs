using Microsoft.Data.Sqlite;
using NetGuard.Models;

namespace NetGuard.Services;

/// <summary>
/// Manages SQLite persistence for whitelist rules, alerts and settings.
/// </summary>
public class DatabaseService
{
    private readonly string _dbPath;

    public DatabaseService()
    {
        var folder = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "NetGuard");
        Directory.CreateDirectory(folder);
        _dbPath = Path.Combine(folder, "netguard.db");
        InitializeAsync().GetAwaiter().GetResult();
    }

    private SqliteConnection OpenConnection()
        => new($"Data Source={_dbPath}");

    // ── Schema ────────────────────────────────────────────────
    private async Task InitializeAsync()
    {
        using var conn = OpenConnection();
        await conn.OpenAsync();

        await ExecAsync(conn, """
            CREATE TABLE IF NOT EXISTS whitelist_rules (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern     TEXT NOT NULL,
                type        INTEGER NOT NULL,
                description TEXT,
                is_enabled  INTEGER NOT NULL DEFAULT 1,
                created_at  TEXT NOT NULL
            );
            """);

        await ExecAsync(conn, """
            CREATE TABLE IF NOT EXISTS alerts (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                type     INTEGER NOT NULL,
                severity INTEGER NOT NULL,
                title    TEXT NOT NULL,
                detail   TEXT,
                source   TEXT,
                at       TEXT NOT NULL,
                is_read  INTEGER NOT NULL DEFAULT 0
            );
            """);

        await ExecAsync(conn, """
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """);

        await ExecAsync(conn, """
            CREATE TABLE IF NOT EXISTS threat_cache (
                query      TEXT PRIMARY KEY,
                level      INTEGER NOT NULL,
                source     TEXT,
                detail     TEXT,
                checked_at TEXT NOT NULL
            );
            """);

        // Seed default whitelist rules if empty
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM whitelist_rules";
        var count = (long)(await cmd.ExecuteScalarAsync() ?? 0L);
        if (count == 0) await SeedDefaultRulesAsync(conn);
    }

    // ── Whitelist Rules ───────────────────────────────────────
    public async Task<List<WhitelistRule>> GetRulesAsync()
    {
        using var conn = OpenConnection();
        await conn.OpenAsync();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id,pattern,type,description,is_enabled,created_at FROM whitelist_rules ORDER BY id";
        using var reader = await cmd.ExecuteReaderAsync();
        var rules = new List<WhitelistRule>();
        while (await reader.ReadAsync())
            rules.Add(new WhitelistRule
            {
                Id          = reader.GetInt32(0),
                Pattern     = reader.GetString(1),
                Type        = (RuleType)reader.GetInt32(2),
                Description = reader.IsDBNull(3) ? "" : reader.GetString(3),
                IsEnabled   = reader.GetInt32(4) == 1,
                CreatedAt   = DateTime.Parse(reader.GetString(5))
            });
        return rules;
    }

    public async Task<int> AddRuleAsync(WhitelistRule rule)
    {
        using var conn = OpenConnection();
        await conn.OpenAsync();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO whitelist_rules (pattern,type,description,is_enabled,created_at)
            VALUES ($p,$t,$d,$e,$c);
            SELECT last_insert_rowid();
            """;
        cmd.Parameters.AddWithValue("$p", rule.Pattern);
        cmd.Parameters.AddWithValue("$t", (int)rule.Type);
        cmd.Parameters.AddWithValue("$d", rule.Description ?? "");
        cmd.Parameters.AddWithValue("$e", rule.IsEnabled ? 1 : 0);
        cmd.Parameters.AddWithValue("$c", rule.CreatedAt.ToString("O"));
        return Convert.ToInt32(await cmd.ExecuteScalarAsync());
    }

    public async Task UpdateRuleAsync(WhitelistRule rule)
    {
        using var conn = OpenConnection();
        await conn.OpenAsync();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            UPDATE whitelist_rules
            SET pattern=$p, type=$t, description=$d, is_enabled=$e
            WHERE id=$id
            """;
        cmd.Parameters.AddWithValue("$p",  rule.Pattern);
        cmd.Parameters.AddWithValue("$t",  (int)rule.Type);
        cmd.Parameters.AddWithValue("$d",  rule.Description ?? "");
        cmd.Parameters.AddWithValue("$e",  rule.IsEnabled ? 1 : 0);
        cmd.Parameters.AddWithValue("$id", rule.Id);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task DeleteRuleAsync(int id)
    {
        using var conn = OpenConnection();
        await conn.OpenAsync();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "DELETE FROM whitelist_rules WHERE id=$id";
        cmd.Parameters.AddWithValue("$id", id);
        await cmd.ExecuteNonQueryAsync();
    }

    // ── Alerts ────────────────────────────────────────────────
    public async Task SaveAlertAsync(Alert alert)
    {
        using var conn = OpenConnection();
        await conn.OpenAsync();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO alerts (type,severity,title,detail,source,at,is_read)
            VALUES ($type,$sev,$title,$detail,$src,$at,$read)
            """;
        cmd.Parameters.AddWithValue("$type",   (int)alert.Type);
        cmd.Parameters.AddWithValue("$sev",    (int)alert.Severity);
        cmd.Parameters.AddWithValue("$title",  alert.Title);
        cmd.Parameters.AddWithValue("$detail", alert.Detail ?? "");
        cmd.Parameters.AddWithValue("$src",    alert.Source ?? "");
        cmd.Parameters.AddWithValue("$at",     alert.At.ToString("O"));
        cmd.Parameters.AddWithValue("$read",   alert.IsRead ? 1 : 0);
    }

    public async Task<List<Alert>> GetAlertsAsync(int limit = 100)
    {
        using var conn = OpenConnection();
        await conn.OpenAsync();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT id,type,severity,title,detail,source,at,is_read FROM alerts ORDER BY at DESC LIMIT {limit}";
        using var reader = await cmd.ExecuteReaderAsync();
        var alerts = new List<Alert>();
        while (await reader.ReadAsync())
            alerts.Add(new Alert
            {
                Id       = reader.GetInt32(0),
                Type     = (AlertType)reader.GetInt32(1),
                Severity = (ThreatLevel)reader.GetInt32(2),
                Title    = reader.GetString(3),
                Detail   = reader.IsDBNull(4) ? "" : reader.GetString(4),
                Source   = reader.IsDBNull(5) ? "" : reader.GetString(5),
                At       = DateTime.Parse(reader.GetString(6)),
                IsRead   = reader.GetInt32(7) == 1
            });
        return alerts;
    }

    // ── Threat Cache ──────────────────────────────────────────
    public async Task<ThreatResult?> GetCachedThreatAsync(string query)
    {
        using var conn = OpenConnection();
        await conn.OpenAsync();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT level,source,detail,checked_at FROM threat_cache WHERE query=$q";
        cmd.Parameters.AddWithValue("$q", query);
        using var reader = await cmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync()) return null;
        var checkedAt = DateTime.Parse(reader.GetString(3));
        if (DateTime.UtcNow - checkedAt > TimeSpan.FromHours(24)) return null; // stale
        return new ThreatResult
        {
            Query     = query,
            Level     = (ThreatLevel)reader.GetInt32(0),
            Source    = reader.IsDBNull(1) ? "" : reader.GetString(1),
            Detail    = reader.IsDBNull(2) ? "" : reader.GetString(2),
            CheckedAt = checkedAt
        };
    }

    public async Task CacheThreatAsync(ThreatResult result)
    {
        using var conn = OpenConnection();
        await conn.OpenAsync();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT OR REPLACE INTO threat_cache (query,level,source,detail,checked_at)
            VALUES ($q,$l,$s,$d,$at)
            """;
        cmd.Parameters.AddWithValue("$q",  result.Query);
        cmd.Parameters.AddWithValue("$l",  (int)result.Level);
        cmd.Parameters.AddWithValue("$s",  result.Source);
        cmd.Parameters.AddWithValue("$d",  result.Detail);
        cmd.Parameters.AddWithValue("$at", result.CheckedAt.ToString("O"));
        await cmd.ExecuteNonQueryAsync();
    }

    // ── Settings ──────────────────────────────────────────────
    public async Task<AppSettings> LoadSettingsAsync()
    {
        using var conn = OpenConnection();
        await conn.OpenAsync();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT key,value FROM settings";
        using var reader = await cmd.ExecuteReaderAsync();
        var dict = new Dictionary<string, string>();
        while (await reader.ReadAsync())
            dict[reader.GetString(0)] = reader.GetString(1);

        return new AppSettings
        {
            VirusTotalApiKey   = dict.GetValueOrDefault("vt_key", ""),
            AbuseIpDbApiKey    = dict.GetValueOrDefault("abdb_key", ""),
            PrimaryDnsServer   = dict.GetValueOrDefault("dns_primary", "9.9.9.9"),
            FallbackDnsServer  = dict.GetValueOrDefault("dns_fallback", "1.1.1.1"),
            UseDnsOverHttps    = dict.GetValueOrDefault("doh", "true") == "true",
            ScanIntervalSec    = int.Parse(dict.GetValueOrDefault("scan_interval", "30")),
            AutoBlockMalicious = dict.GetValueOrDefault("auto_block", "false") == "true",
            NotifyOnThreat     = dict.GetValueOrDefault("notify", "true") == "true"
        };
    }

    public async Task SaveSettingsAsync(AppSettings s)
    {
        using var conn = OpenConnection();
        await conn.OpenAsync();
        var pairs = new Dictionary<string, string>
        {
            ["vt_key"]       = s.VirusTotalApiKey,
            ["abdb_key"]     = s.AbuseIpDbApiKey,
            ["dns_primary"]  = s.PrimaryDnsServer,
            ["dns_fallback"] = s.FallbackDnsServer,
            ["doh"]          = s.UseDnsOverHttps ? "true" : "false",
            ["scan_interval"]= s.ScanIntervalSec.ToString(),
            ["auto_block"]   = s.AutoBlockMalicious ? "true" : "false",
            ["notify"]       = s.NotifyOnThreat ? "true" : "false"
        };
        foreach (var (k, v) in pairs)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "INSERT OR REPLACE INTO settings (key,value) VALUES ($k,$v)";
            cmd.Parameters.AddWithValue("$k", k);
            cmd.Parameters.AddWithValue("$v", v);
            await cmd.ExecuteNonQueryAsync();
        }
    }

    // ── Helpers ───────────────────────────────────────────────
    private static async Task ExecAsync(SqliteConnection conn, string sql)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        await cmd.ExecuteNonQueryAsync();
    }

    private static async Task SeedDefaultRulesAsync(SqliteConnection conn)
    {
        var defaults = new[]
        {
            ("*.google.com",      RuleType.Domain, "Google services"),
            ("*.googleapis.com",  RuleType.Domain, "Google APIs"),
            ("*.microsoft.com",   RuleType.Domain, "Microsoft services"),
            ("*.windows.com",     RuleType.Domain, "Windows Update"),
            ("*.apple.com",       RuleType.Domain, "Apple services"),
            ("*.ubuntu.com",      RuleType.Domain, "Ubuntu repos"),
            ("*.debian.org",      RuleType.Domain, "Debian repos"),
            ("8.8.8.8",           RuleType.Ip,     "Google DNS"),
            ("8.8.4.4",           RuleType.Ip,     "Google DNS secondary"),
            ("1.1.1.1",           RuleType.Ip,     "Cloudflare DNS"),
        };
        foreach (var (p, t, d) in defaults)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO whitelist_rules (pattern,type,description,is_enabled,created_at)
                VALUES ($p,$t,$d,1,$c)
                """;
            cmd.Parameters.AddWithValue("$p", p);
            cmd.Parameters.AddWithValue("$t", (int)t);
            cmd.Parameters.AddWithValue("$d", d);
            cmd.Parameters.AddWithValue("$c", DateTime.UtcNow.ToString("O"));
            await cmd.ExecuteNonQueryAsync();
        }
    }
}
