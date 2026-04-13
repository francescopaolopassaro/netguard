namespace NetGuard.Models;

// ─────────────────────────────────────────────────────────────
//  NetworkConnection
// ─────────────────────────────────────────────────────────────
public class NetworkConnection
{
    public string Protocol      { get; set; } = "TCP";
    public string LocalAddress  { get; set; } = string.Empty;
    public int    LocalPort     { get; set; }
    public string RemoteAddress { get; set; } = string.Empty;
    public int    RemotePort    { get; set; }
    public string State         { get; set; } = string.Empty;
    public int    ProcessId     { get; set; }
    public string ProcessName   { get; set; } = string.Empty;
    public string Domain        { get; set; } = string.Empty;   // resolved via reverse-DNS
    public DateTime FirstSeen   { get; set; } = DateTime.UtcNow;
    public ThreatLevel Threat   { get; set; } = ThreatLevel.Unknown;

    public string DisplayAddress => string.IsNullOrEmpty(Domain)
        ? RemoteAddress
        : $"{Domain} ({RemoteAddress})";
}

// ─────────────────────────────────────────────────────────────
//  ProcessInfo
// ─────────────────────────────────────────────────────────────
public class ProcessInfo
{
    public int      Pid          { get; set; }
    public string   Name         { get; set; } = string.Empty;
    public string   Path         { get; set; } = string.Empty;
    public string   Hash         { get; set; } = string.Empty;   // SHA-256
    public long     MemoryKb     { get; set; }
    public double   CpuPercent   { get; set; }
    public DateTime StartTime    { get; set; }
    public ThreatLevel Threat    { get; set; } = ThreatLevel.Unknown;
    public string   ThreatDetail { get; set; } = string.Empty;
    public bool     IsScanned    { get; set; }
    public string   Publisher    { get; set; } = string.Empty;   // from digital signature
    public bool     IsSigned     { get; set; }
}

// ─────────────────────────────────────────────────────────────
//  ThreatResult (unified result from any threat intel source)
// ─────────────────────────────────────────────────────────────
public class ThreatResult
{
    public string   Query        { get; set; } = string.Empty;   // hash, IP, or domain
    public ThreatLevel Level     { get; set; } = ThreatLevel.Unknown;
    public string   Source       { get; set; } = string.Empty;   // "VirusTotal", "MalwareBazaar"…
    public int      Detections   { get; set; }                   // engine hits
    public int      TotalEngines { get; set; }
    public string   MalwareName  { get; set; } = string.Empty;
    public string   Detail       { get; set; } = string.Empty;
    public DateTime CheckedAt    { get; set; } = DateTime.UtcNow;
    public string   Permalink    { get; set; } = string.Empty;

    public string Summary => Level switch
    {
        ThreatLevel.Clean   => "Clean",
        ThreatLevel.Low     => $"Low risk — {Detections}/{TotalEngines} engines",
        ThreatLevel.Medium  => $"Suspicious — {Detections}/{TotalEngines} ({MalwareName})",
        ThreatLevel.High    => $"MALICIOUS — {MalwareName} ({Detections}/{TotalEngines})",
        _                   => "Not checked"
    };
}

// ─────────────────────────────────────────────────────────────
//  WhitelistRule
// ─────────────────────────────────────────────────────────────
public class WhitelistRule
{
    public int     Id          { get; set; }
    public string  Pattern     { get; set; } = string.Empty;  // e.g. "*.google.com", "8.8.8.8"
    public RuleType Type       { get; set; } = RuleType.Domain;
    public string  Description { get; set; } = string.Empty;
    public bool    IsEnabled   { get; set; } = true;
    public DateTime CreatedAt  { get; set; } = DateTime.UtcNow;

    public bool Matches(string value)
    {
        if (!IsEnabled) return false;
        if (Pattern == "*") return true;
        if (Pattern.StartsWith("*."))
        {
            var suffix = Pattern[2..];
            return value.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)
                || value.Equals(suffix, StringComparison.OrdinalIgnoreCase);
        }
        return value.Equals(Pattern, StringComparison.OrdinalIgnoreCase);
    }
}

// ─────────────────────────────────────────────────────────────
//  Alert
// ─────────────────────────────────────────────────────────────
public class Alert
{
    public int        Id        { get; set; }
    public AlertType  Type      { get; set; }
    public ThreatLevel Severity { get; set; }
    public string     Title     { get; set; } = string.Empty;
    public string     Detail    { get; set; } = string.Empty;
    public string     Source    { get; set; } = string.Empty;   // process name or IP
    public DateTime   At        { get; set; } = DateTime.UtcNow;
    public bool       IsRead    { get; set; }

    public string SeverityColor => Severity switch
    {
        ThreatLevel.High   => "#E53E3E",
        ThreatLevel.Medium => "#D97706",
        ThreatLevel.Low    => "#2B6CB0",
        _                  => "#718096"
    };

    public string Icon => Type switch
    {
        AlertType.MaliciousProcess => "⚠",
        AlertType.MaliciousDomain  => "🌐",
        AlertType.BlacklistedIp    => "🔒",
        AlertType.SuspiciousPort   => "⚡",
        _                          => "ℹ"
    };
}

// ─────────────────────────────────────────────────────────────
//  Enums
// ─────────────────────────────────────────────────────────────
public enum ThreatLevel { Unknown, Clean, Low, Medium, High }

public enum RuleType { Domain, Ip, IpRange, ProcessName }

public enum AlertType
{
    MaliciousProcess,
    MaliciousDomain,
    BlacklistedIp,
    SuspiciousPort,
    Info
}

// ─────────────────────────────────────────────────────────────
//  AppSettings  (persisted to SQLite)
// ─────────────────────────────────────────────────────────────
public class AppSettings
{
    public string VirusTotalApiKey  { get; set; } = string.Empty;
    public string AbuseIpDbApiKey   { get; set; } = string.Empty;
    public string PrimaryDnsServer  { get; set; } = "9.9.9.9";      // Quad9
    public string FallbackDnsServer { get; set; } = "1.1.1.1";
    public bool   UseDnsOverHttps   { get; set; } = true;
    public int    ScanIntervalSec   { get; set; } = 30;
    public bool   AutoBlockMalicious{ get; set; } = false;
    public bool   NotifyOnThreat    { get; set; } = true;
}
