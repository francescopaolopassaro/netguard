using System.Net;

namespace NetGuard.Models;

// ── Enums ──────────────────────────────────────────────────────────────────
public enum ThreatLevel  { Unknown, Clean, Low, Medium, High, Critical }
public enum BlockReason  { None, MaliciousHash, BlacklistedIp, BlockedDomain, SuspiciousPort, UserDefined }
public enum RuleType     { Domain, Ip, IpRange, ProcessName }
public enum AlertType    { Process, Network, Dns, System, MaliciousProcess, MaliciousDomain, BlacklistedIp, Info }
public enum BlockAction  { Killed, FirewallBlocked, DnsBlocked, HostsBlocked }

// ── Process ────────────────────────────────────────────────────────────────
public class ProcessEntry
{
    public int        Pid          { get; set; }
    public string     Name         { get; set; } = "";
    public string     Path         { get; set; } = "";
    public string     CommandLine  { get; set; } = "";
    public string     Hash         { get; set; } = "";
    public string     Publisher    { get; set; } = "";
    public bool       IsSigned     { get; set; }
    public long       MemoryKb     { get; set; }
    public double     CpuPercent   { get; set; }
    public int        Threads      { get; set; }
    public DateTime   StartTime    { get; set; }
    public ThreatLevel Threat      { get; set; } = ThreatLevel.Unknown;
    public string     ThreatDetail { get; set; } = "";
    public bool       IsScanned    { get; set; }
    public bool       IsBlocked    { get; set; }
    public string     User         { get; set; } = "";

    public string ThreatIcon => Threat switch
    {
        ThreatLevel.Critical => "☠",
        ThreatLevel.High     => "⛔",
        ThreatLevel.Medium   => "⚠",
        ThreatLevel.Low      => "⚡",
        ThreatLevel.Clean    => "✅",
        _                    => "⏳"
    };

    public Color ThreatColor => Threat switch
    {
        ThreatLevel.Critical => Color.FromArgb("#FF0040"),
        ThreatLevel.High     => Color.FromArgb("#FF4444"),
        ThreatLevel.Medium   => Color.FromArgb("#FF9500"),
        ThreatLevel.Low      => Color.FromArgb("#FFD60A"),
        ThreatLevel.Clean    => Color.FromArgb("#30D158"),
        _                    => Color.FromArgb("#636366")
    };
}

// ── Network Connection ─────────────────────────────────────────────────────
public class NetConnection
{
    public string     Protocol      { get; set; } = "TCP";
    public string     LocalAddress  { get; set; } = "";
    public int        LocalPort     { get; set; }
    public string     RemoteAddress { get; set; } = "";
    public int        RemotePort    { get; set; }
    public string     Domain        { get; set; } = "";
    public string     State         { get; set; } = "";
    public int        Pid           { get; set; }
    public string     ProcessName   { get; set; } = "";
    public string     Country       { get; set; } = "";
    public string     CountryCode   { get; set; } = "";
    public ThreatLevel Threat       { get; set; } = ThreatLevel.Unknown;
    public bool       IsBlocked     { get; set; }
    public DateTime   FirstSeen     { get; set; } = DateTime.UtcNow;
    public long       BytesSent     { get; set; }
    public long       BytesReceived { get; set; }

    public string Display => string.IsNullOrEmpty(Domain) ? RemoteAddress : $"{Domain}";
    public string Flag   => CountryCode switch
    {
        "US" => "🇺🇸", "RU" => "🇷🇺", "CN" => "🇨🇳", "DE" => "🇩🇪",
        "FR" => "🇫🇷", "GB" => "🇬🇧", "NL" => "🇳🇱", "IT" => "🇮🇹",
        "JP" => "🇯🇵", "KR" => "🇰🇷", "IR" => "🇮🇷", "KP" => "🇰🇵",
        _    => "🌐"
    };
}

// ── Alert ──────────────────────────────────────────────────────────────────
public class ThreatAlert
{
    public int        Id          { get; set; }
    public AlertType  Type        { get; set; }
    public ThreatLevel Severity   { get; set; }
    public string     Title       { get; set; } = "";
    public string     Detail      { get; set; } = "";
    public string     Source      { get; set; } = "";
    public DateTime   At          { get; set; } = DateTime.UtcNow;
    public bool       IsRead      { get; set; }
    public bool       WasBlocked  { get; set; }
    public BlockAction? Action    { get; set; }

    public string TimeAgo
    {
        get
        {
            var diff = DateTime.UtcNow - At;
            if (diff.TotalSeconds < 60)  return $"{(int)diff.TotalSeconds}s ago";
            if (diff.TotalMinutes < 60)  return $"{(int)diff.TotalMinutes}m ago";
            if (diff.TotalHours < 24)    return $"{(int)diff.TotalHours}h ago";
            return At.ToLocalTime().ToString("MM-dd HH:mm");
        }
    }
}

// ── Whitelist Rule ─────────────────────────────────────────────────────────
public class WhitelistRule
{
    public int      Id          { get; set; }
    public string   Pattern     { get; set; } = "";
    public RuleType Type        { get; set; }
    public string   Description { get; set; } = "";
    public bool     IsEnabled   { get; set; } = true;
    public DateTime CreatedAt   { get; set; } = DateTime.UtcNow;

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

// ── Settings ───────────────────────────────────────────────────────────────
public class AppSettings
{
    public string VirusTotalApiKey   { get; set; } = "";
    public string AbuseIpDbApiKey    { get; set; } = "";
    public bool   AutoBlockProcesses { get; set; } = false;
    public bool   AutoBlockDomains   { get; set; } = false;
    public bool   AutoBlockIps       { get; set; } = false;
    public int    ScanIntervalSec    { get; set; } = 5;
    public bool   NotifyOnThreat     { get; set; } = true;
    public string PrimaryDnsServer   { get; set; } = "9.9.9.9";
    public string FallbackDnsServer  { get; set; } = "1.1.1.1";
    public bool   UseDnsOverHttps    { get; set; } = true;
    public bool   DarkMode           { get; set; } = true;
    public ThreatLevel BlockThreshold { get; set; } = ThreatLevel.High;
}

// ── Stats ──────────────────────────────────────────────────────────────────
public class SystemStats
{
    public int    TotalProcesses       { get; set; }
    public int    ScannedProcesses     { get; set; }
    public int    MaliciousProcesses   { get; set; }
    public int    BlockedProcesses     { get; set; }
    public int    TotalConnections     { get; set; }
    public int    BlockedConnections   { get; set; }
    public int    ThreatAlerts         { get; set; }
    public bool   IsElevated           { get; set; }
    public double CpuUsage             { get; set; }
    public long   MemoryUsedMb         { get; set; }
    public int    NetworkBytesPerSec   { get; set; }
}


// ═══════════════════════════════════════════════════════════════════════════
//  COMPATIBILITY ALIASES — bridge old names → new names without touching
//  any file the user has already edited.
// ═══════════════════════════════════════════════════════════════════════════


/// <summary>
/// Old name for ProcessEntry — keeps legacy services/views compiling.
/// </summary>
public class ProcessInfo : ProcessEntry { }

/// <summary>
/// Old name for NetConnection — adds ProcessId alias for Pid.
/// </summary>
public class NetworkConnection : NetConnection
{
    /// <summary>Alias for Pid — used by NetworkMonitorService and legacy views.</summary>
    public new int ProcessId
    {
        get => Pid;
        set => Pid = value;
    }
}

/// <summary>
/// ThreatResult — used by ThreatIntelService (old version).
/// </summary>
public class ThreatResult
{
    public string     Query        { get; set; } = "";
    public ThreatLevel Level       { get; set; } = ThreatLevel.Unknown;
    public string     Source       { get; set; } = "";
    public int        Detections   { get; set; }
    public int        TotalEngines { get; set; }
    public string     MalwareName  { get; set; } = "";
    public string     Detail       { get; set; } = "";
    public DateTime   CheckedAt    { get; set; } = DateTime.UtcNow;
    public string     Permalink    { get; set; } = "";

    public string Summary => Level switch
    {
        ThreatLevel.Clean    => "Clean",
        ThreatLevel.Low      => $"Low risk — {Detections}/{TotalEngines} engines",
        ThreatLevel.Medium   => $"Suspicious — {Detections}/{TotalEngines} ({MalwareName})",
        ThreatLevel.High     => $"MALICIOUS — {MalwareName} ({Detections}/{TotalEngines})",
        ThreatLevel.Critical => $"CRITICAL — {MalwareName} ({Detections}/{TotalEngines})",
        _                    => "Not checked"
    };
}

/// <summary>
/// Old name for ThreatAlert — adds Icon and SeverityColor used by AlertDetailPage.
/// </summary>
public class Alert : ThreatAlert
{
    public string Icon => Type switch
    {
        AlertType.MaliciousProcess => "⚙",
        AlertType.MaliciousDomain  => "🌐",
        AlertType.BlacklistedIp    => "🔒",
        AlertType.Process          => "⚙",
        AlertType.Network          => "🌐",
        AlertType.Dns              => "🔒",
        _                          => "ℹ"
    };

    public string SeverityColor => Severity switch
    {
        ThreatLevel.Critical => "#FF0040",
        ThreatLevel.High     => "#FF4444",
        ThreatLevel.Medium   => "#FF9500",
        ThreatLevel.Low      => "#FFD60A",
        _                    => "#636366"
    };
}
