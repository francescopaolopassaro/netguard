using Microsoft.Data.Sqlite;
using NetGuard.Models;

namespace NetGuard.Services;

// ── Whitelist ──────────────────────────────────────────────────────────────

public class WhitelistService
{
    private List<WhitelistRule> _rules = new();
    private readonly DatabaseService _db;

    public WhitelistService(DatabaseService db)
    {
        _db = db;
        _ = LoadAsync();
    }

    public async Task LoadAsync()
        => _rules = await _db.GetRulesAsync();

    public Task<bool> IsDomainWhitelistedAsync(string domain) =>
        Task.FromResult(_rules.Where(r => r.Type == RuleType.Domain && r.IsEnabled)
            .Any(r => r.Matches(domain)));

    public Task<bool> IsIpWhitelistedAsync(string ip) =>
        Task.FromResult(_rules.Where(r => r.Type == RuleType.Ip && r.IsEnabled)
            .Any(r => r.Matches(ip)));

    public Task<bool> IsProcessWhitelistedAsync(string name) =>
        Task.FromResult(_rules.Where(r => r.Type == RuleType.ProcessName && r.IsEnabled)
            .Any(r => r.Matches(name)));

    public List<WhitelistRule> AllRules => _rules.ToList();

    public async Task AddAsync(WhitelistRule r)
    {
        r.Id = await _db.AddRuleAsync(r);
        _rules.Add(r);
    }

    public async Task RemoveAsync(int id)
    {
        await _db.DeleteRuleAsync(id);
        _rules.RemoveAll(r => r.Id == id);
    }

    public async Task ToggleAsync(WhitelistRule r)
    {
        r.IsEnabled = !r.IsEnabled;
        await _db.UpdateRuleAsync(r);
    }
}

// ── Database ───────────────────────────────────────────────────────────────

public class DatabaseService
{
    private readonly string _path;

    public DatabaseService()
    {
        var dir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "NetGuard");
        Directory.CreateDirectory(dir);
        _path = Path.Combine(dir, "netguard.db");
        InitSync();
    }

    private SqliteConnection Open()
    {
        var c = new SqliteConnection($"Data Source={_path}");
        c.Open();
        return c;
    }

    private void InitSync()
    {
        using var conn = Open();

        // Drop e ricrea le tabelle critiche per evitare problemi di schema vecchio
        Exec(conn, """
        DROP TABLE IF EXISTS settings;
        DROP TABLE IF EXISTS threat_cache;

        CREATE TABLE IF NOT EXISTS whitelist (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern     TEXT NOT NULL,
            type        INTEGER NOT NULL DEFAULT 0,
            description TEXT DEFAULT '',
            is_enabled  INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            type        INTEGER,
            severity    INTEGER,
            title       TEXT,
            detail      TEXT,
            source      TEXT,
            at          TEXT,
            is_read     INTEGER DEFAULT 0,
            was_blocked INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            val TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS threat_cache (
            key        TEXT PRIMARY KEY,
            level      INTEGER NOT NULL,
            detail     TEXT,
            checked_at TEXT NOT NULL
        );
        """);

        // Seed defaults se la tabella whitelist è vuota
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM whitelist";
        if ((long)(cmd.ExecuteScalar() ?? 0L) == 0)
        {
            SeedDefaults(conn);
        }

        // Inserisci impostazioni di default se la tabella settings è vuota
        cmd.CommandText = "SELECT COUNT(*) FROM settings";
        if ((long)(cmd.ExecuteScalar() ?? 0L) == 0)
        {
            InsertDefaultSettings(conn);
        }
    }
    private static void InsertDefaultSettings(SqliteConnection conn)
    {
        var defaults = new[]
        {
        ("vt", ""),
        ("abdb", ""),
        ("ab_proc", "false"),
        ("ab_dns", "false"),
        ("ab_ip", "false"),
        ("interval", "5"),
        ("threshold", "High"),
        ("dns_primary", "9.9.9.9"),
        ("dns_fallback", "1.1.1.1"),
        ("doh", "true"),
        ("notify", "true")
    };

        foreach (var (key, value) in defaults)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "INSERT OR REPLACE INTO settings (key, val) VALUES (@k, @v)";
            cmd.Parameters.AddWithValue("@k", key);
            cmd.Parameters.AddWithValue("@v", value);
            cmd.ExecuteNonQuery();
        }
    }
    // ── Whitelist CRUD ────────────────────────────────────────────────────

    public async Task<List<WhitelistRule>> GetRulesAsync()
    {
        return await Task.Run(() =>
        {
            using var conn = Open();
            using var cmd  = conn.CreateCommand();
            cmd.CommandText = "SELECT id,pattern,type,description,is_enabled,created_at FROM whitelist ORDER BY id";
            using var r = cmd.ExecuteReader();
            var list = new List<WhitelistRule>();
            while (r.Read())
                list.Add(new WhitelistRule
                {
                    Id          = r.GetInt32(0),
                    Pattern     = r.GetString(1),
                    Type        = (RuleType)r.GetInt32(2),
                    Description = r.IsDBNull(3) ? "" : r.GetString(3),
                    IsEnabled   = r.GetInt32(4) == 1,
                    CreatedAt   = DateTime.Parse(r.GetString(5))
                });
            return list;
        });
    }

    public async Task<int> AddRuleAsync(WhitelistRule rule)
    {
        return await Task.Run(() =>
        {
            using var conn = Open();
            using var cmd  = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO whitelist (pattern,type,description,is_enabled,created_at)
                VALUES (@p,@t,@d,@e,@c);
                SELECT last_insert_rowid();
                """;
            cmd.Parameters.AddWithValue("@p", rule.Pattern);
            cmd.Parameters.AddWithValue("@t", (int)rule.Type);
            cmd.Parameters.AddWithValue("@d", rule.Description);
            cmd.Parameters.AddWithValue("@e", rule.IsEnabled ? 1 : 0);
            cmd.Parameters.AddWithValue("@c", rule.CreatedAt.ToString("O"));
            return Convert.ToInt32(cmd.ExecuteScalar());
        });
    }

    public async Task UpdateRuleAsync(WhitelistRule rule)
    {
        await Task.Run(() =>
        {
            using var conn = Open();
            using var cmd  = conn.CreateCommand();
            cmd.CommandText = "UPDATE whitelist SET is_enabled=@e WHERE id=@id";
            cmd.Parameters.AddWithValue("@e",  rule.IsEnabled ? 1 : 0);
            cmd.Parameters.AddWithValue("@id", rule.Id);
            cmd.ExecuteNonQuery();
        });
    }

    public async Task DeleteRuleAsync(int id)
    {
        await Task.Run(() =>
        {
            using var conn = Open();
            using var cmd  = conn.CreateCommand();
            cmd.CommandText = "DELETE FROM whitelist WHERE id=@id";
            cmd.Parameters.AddWithValue("@id", id);
            cmd.ExecuteNonQuery();
        });
    }

    // ── Alerts ────────────────────────────────────────────────────────────

    public async Task SaveAlertAsync(ThreatAlert a)
    {
        await Task.Run(() =>
        {
            using var conn = Open();
            using var cmd  = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO alerts (type,severity,title,detail,source,at,was_blocked)
                VALUES (@t,@s,@ti,@d,@src,@at,@wb)
                """;
            cmd.Parameters.AddWithValue("@t",   (int)a.Type);
            cmd.Parameters.AddWithValue("@s",   (int)a.Severity);
            cmd.Parameters.AddWithValue("@ti",  a.Title);
            cmd.Parameters.AddWithValue("@d",   a.Detail);
            cmd.Parameters.AddWithValue("@src", a.Source);
            cmd.Parameters.AddWithValue("@at",  a.At.ToString("O"));
            cmd.Parameters.AddWithValue("@wb",  a.WasBlocked ? 1 : 0);
            cmd.ExecuteNonQuery();
        });
    }

    public async Task<List<Alert>> GetAlertsAsync(int limit = 200)
    {
        return await Task.Run(() =>
        {
            using var conn = Open();
            using var cmd  = conn.CreateCommand();
            cmd.CommandText = $"SELECT id,type,severity,title,detail,source,at,is_read,was_blocked FROM alerts ORDER BY at DESC LIMIT {limit}";
            using var r = cmd.ExecuteReader();
            var list = new List<Alert>();
            while (r.Read())
                list.Add(new Alert
                {
                    Id         = r.GetInt32(0),
                    Type       = (AlertType)r.GetInt32(1),
                    Severity   = (ThreatLevel)r.GetInt32(2),
                    Title      = r.GetString(3),
                    Detail     = r.IsDBNull(4) ? "" : r.GetString(4),
                    Source     = r.IsDBNull(5) ? "" : r.GetString(5),
                    At         = DateTime.Parse(r.GetString(6)),
                    IsRead     = r.GetInt32(7) == 1,
                    WasBlocked = r.GetInt32(8) == 1
                });
            return list;
        });
    }

    // ── Settings ──────────────────────────────────────────────────────────

    public async Task<AppSettings> LoadSettingsAsync()
    {
        return await Task.Run(() =>
        {
            using var conn = Open();
            using var cmd  = conn.CreateCommand();
            cmd.CommandText = "SELECT key,val FROM settings";
            using var r = cmd.ExecuteReader();
            var d = new Dictionary<string, string>();
            while (r.Read()) d[r.GetString(0)] = r.GetString(1);

            return new AppSettings
            {
                VirusTotalApiKey   = d.GetValueOrDefault("vt", ""),
                AbuseIpDbApiKey    = d.GetValueOrDefault("abdb", ""),
                AutoBlockProcesses = d.GetValueOrDefault("ab_proc","false") == "true",
                AutoBlockDomains   = d.GetValueOrDefault("ab_dns","false") == "true",
                AutoBlockIps       = d.GetValueOrDefault("ab_ip","false") == "true",
                ScanIntervalSec    = int.Parse(d.GetValueOrDefault("interval","5")),
                BlockThreshold     = Enum.Parse<ThreatLevel>(d.GetValueOrDefault("threshold","High")),
                PrimaryDnsServer   = d.GetValueOrDefault("dns_primary", "9.9.9.9"),
                FallbackDnsServer  = d.GetValueOrDefault("dns_fallback", "1.1.1.1"),
                UseDnsOverHttps    = d.GetValueOrDefault("doh","true") == "true",
                NotifyOnThreat     = d.GetValueOrDefault("notify","true") == "true"
            };
        });
    }

    public async Task SaveSettingsAsync(AppSettings s)
    {
        await Task.Run(() =>
        {
            using var conn = Open();
            var pairs = new Dictionary<string, string>
            {
                ["vt"]        = s.VirusTotalApiKey,
                ["abdb"]      = s.AbuseIpDbApiKey,
                ["ab_proc"]   = s.AutoBlockProcesses ? "true" : "false",
                ["ab_dns"]    = s.AutoBlockDomains ? "true" : "false",
                ["ab_ip"]     = s.AutoBlockIps ? "true" : "false",
                ["interval"]   = s.ScanIntervalSec.ToString(),
                ["threshold"]  = s.BlockThreshold.ToString(),
                ["dns_primary"]= s.PrimaryDnsServer,
                ["dns_fallback"]= s.FallbackDnsServer,
                ["doh"]        = s.UseDnsOverHttps ? "true" : "false",
                ["notify"]     = s.NotifyOnThreat ? "true" : "false"
            };
            foreach (var (k, v) in pairs)
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "INSERT OR REPLACE INTO settings (key,val) VALUES (@k,@v)";
                cmd.Parameters.AddWithValue("@k", k);
                cmd.Parameters.AddWithValue("@v", v);
                cmd.ExecuteNonQuery();
            }
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private static void Exec(SqliteConnection conn, string sql)
    {
        foreach (var stmt in sql.Split(';', StringSplitOptions.RemoveEmptyEntries))
        {
            var s = stmt.Trim();
            if (string.IsNullOrEmpty(s)) continue;
            using var cmd = conn.CreateCommand();
            cmd.CommandText = s;
            cmd.ExecuteNonQuery();
        }
    }

    private static void SeedDefaults(SqliteConnection conn)
    {
        var defaults = new[]
        {
            ("*.google.com",     RuleType.Domain,      "Google"),
            ("*.googleapis.com", RuleType.Domain,      "Google APIs"),
            ("*.microsoft.com",  RuleType.Domain,      "Microsoft"),
            ("*.windows.com",    RuleType.Domain,      "Windows Update"),
            ("*.apple.com",      RuleType.Domain,      "Apple"),
            ("*.ubuntu.com",     RuleType.Domain,      "Ubuntu"),
            ("*.debian.org",     RuleType.Domain,      "Debian"),
            ("*.cloudflare.com", RuleType.Domain,      "Cloudflare"),
            ("8.8.8.8",          RuleType.Ip,          "Google DNS"),
            ("1.1.1.1",          RuleType.Ip,          "Cloudflare DNS"),
            ("9.9.9.9",          RuleType.Ip,          "Quad9 DNS"),
            ("svchost",          RuleType.ProcessName, "Windows service host"),
            ("systemd",          RuleType.ProcessName, "Linux systemd"),
        };
        foreach (var (pattern, type, desc) in defaults)
        {
            using var cmd = conn.CreateCommand();
            cmd.CommandText = """
                INSERT INTO whitelist (pattern,type,description,is_enabled,created_at)
                VALUES (@p,@t,@d,1,@c)
                """;
            cmd.Parameters.AddWithValue("@p", pattern);
            cmd.Parameters.AddWithValue("@t", (int)type);
            cmd.Parameters.AddWithValue("@d", desc);
            cmd.Parameters.AddWithValue("@c", DateTime.UtcNow.ToString("O"));
            cmd.ExecuteNonQuery();
        }
    }
    // ── Threat cache (used by ThreatIntelService) ─────────────────────────

    public async Task<ThreatResult?> GetCachedThreatAsync(string query)
    {
        return await Task.Run(() =>
        {
            try
            {
                using var conn = Open();
                using var cmd  = conn.CreateCommand();
                cmd.CommandText = """
                    SELECT level, detail, checked_at
                    FROM   threat_cache
                    WHERE  key = @q
                    """;
                cmd.Parameters.AddWithValue("@q", query);
                using var r = cmd.ExecuteReader();
                if (!r.Read()) return null;

                var checkedAt = DateTime.Parse(r.GetString(2));
                if (DateTime.UtcNow - checkedAt > TimeSpan.FromHours(24))
                    return null; // stale

                return new ThreatResult
                {
                    Query     = query,
                    Level     = (ThreatLevel)r.GetInt32(0),
                    Detail    = r.IsDBNull(1) ? "" : r.GetString(1),
                    CheckedAt = checkedAt
                };
            }
            catch { return null; }
        });
    }

    public async Task CacheThreatAsync(ThreatResult result)
    {
        await Task.Run(() =>
        {
            try
            {
                using var conn = Open();
                // Ensure table exists (created lazily)
                using var ensure = conn.CreateCommand();
                ensure.CommandText = """
                    CREATE TABLE IF NOT EXISTS threat_cache (
                        key        TEXT PRIMARY KEY,
                        level      INTEGER NOT NULL,
                        detail     TEXT,
                        checked_at TEXT NOT NULL
                    )
                    """;
                ensure.ExecuteNonQuery();

                using var cmd = conn.CreateCommand();
                cmd.CommandText = """
                    INSERT OR REPLACE INTO threat_cache (key, level, detail, checked_at)
                    VALUES (@q, @l, @d, @t)
                    """;
                cmd.Parameters.AddWithValue("@q", result.Query);
                cmd.Parameters.AddWithValue("@l", (int)result.Level);
                cmd.Parameters.AddWithValue("@d", result.Detail ?? "");
                cmd.Parameters.AddWithValue("@t", result.CheckedAt.ToString("O"));
                cmd.ExecuteNonQuery();
            }
            catch { }
        });
    }

        }
 