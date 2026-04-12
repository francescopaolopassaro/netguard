using NetGuard.Models;

namespace NetGuard.Services;

/// <summary>
/// Orchestrates the full threat analysis pipeline:
///   1. Whitelist check     → skip if whitelisted
///   2. DNS check           → Quad9 domain reputation
///   3. IP reputation       → AbuseIPDB
///   4. File hash           → MalwareBazaar + VirusTotal
/// Emits Alert objects and raises events for the UI.
/// </summary>
public class ThreatAnalysisPipeline
{
    private readonly WhitelistEngine     _whitelist;
    private readonly DnsCheckerService   _dns;
    private readonly ThreatIntelService  _intel;
    private readonly DatabaseService     _db;
    private readonly ProcessScannerService _scanner;

    // Seen-set to avoid duplicate alerts within a session
    private readonly HashSet<string> _alertedKeys = new();

    public event EventHandler<Alert>? AlertRaised;

    public ThreatAnalysisPipeline(
        WhitelistEngine     whitelist,
        DnsCheckerService   dns,
        ThreatIntelService  intel,
        DatabaseService     db,
        ProcessScannerService scanner)
    {
        _whitelist = whitelist;
        _dns       = dns;
        _intel     = intel;
        _db        = db;
        _scanner   = scanner;
    }

    // ── Analyse a single connection ───────────────────────────

    public async Task<ThreatLevel> AnalyzeConnectionAsync(NetworkConnection conn)
    {
        var maxLevel = ThreatLevel.Unknown;

        // ── Step 1: Whitelist ─────────────────────────────────
        if (!string.IsNullOrEmpty(conn.Domain)
            && await _whitelist.IsDomainWhitelistedAsync(conn.Domain))
        {
            conn.Threat = ThreatLevel.Clean;
            return ThreatLevel.Clean;
        }
        if (await _whitelist.IsIpWhitelistedAsync(conn.RemoteAddress))
        {
            conn.Threat = ThreatLevel.Clean;
            return ThreatLevel.Clean;
        }

        // ── Step 2: DNS check ─────────────────────────────────
        if (!string.IsNullOrEmpty(conn.Domain))
        {
            var dnsResult = await _dns.CheckDomainAsync(conn.Domain);
            if (dnsResult.ThreatLevel > maxLevel) maxLevel = dnsResult.ThreatLevel;
            if (dnsResult.ThreatLevel >= ThreatLevel.Medium)
                await RaiseAlertAsync(new Alert
                {
                    Type     = AlertType.MaliciousDomain,
                    Severity = dnsResult.ThreatLevel,
                    Title    = $"Malicious domain: {conn.Domain}",
                    Detail   = dnsResult.Detail,
                    Source   = conn.Domain,
                    At       = DateTime.UtcNow
                }, $"domain:{conn.Domain}");
        }

        // ── Step 3: IP reputation ─────────────────────────────
        if (!string.IsNullOrEmpty(conn.RemoteAddress))
        {
            var ipResult = await _intel.CheckIpAsync(conn.RemoteAddress);
            if (ipResult.Level > maxLevel) maxLevel = ipResult.Level;
            if (ipResult.Level >= ThreatLevel.Medium)
                await RaiseAlertAsync(new Alert
                {
                    Type     = AlertType.BlacklistedIp,
                    Severity = ipResult.Level,
                    Title    = $"Suspicious IP: {conn.RemoteAddress}",
                    Detail   = ipResult.Detail,
                    Source   = conn.RemoteAddress,
                    At       = DateTime.UtcNow
                }, $"ip:{conn.RemoteAddress}");
        }

        conn.Threat = maxLevel;
        return maxLevel;
    }

    // ── Analyse a single process ──────────────────────────────

    public async Task<ThreatLevel> AnalyzeProcessAsync(ProcessInfo proc)
    {
        if (string.IsNullOrEmpty(proc.Hash))
        {
            proc.IsScanned = true;
            return ThreatLevel.Unknown;
        }

        // ── Step 1: Process whitelist ─────────────────────────
        if (await _whitelist.IsProcessWhitelistedAsync(proc.Name))
        {
            proc.Threat    = ThreatLevel.Clean;
            proc.IsScanned = true;
            return ThreatLevel.Clean;
        }

        // ── Step 2: Hash check (MB + VT) ─────────────────────
        var hashResult = await _intel.CheckHashAsync(proc.Hash);
        proc.Threat      = hashResult.Level;
        proc.ThreatDetail= hashResult.Summary;
        proc.IsScanned   = true;

        if (hashResult.Level >= ThreatLevel.Medium)
            await RaiseAlertAsync(new Alert
            {
                Type     = AlertType.MaliciousProcess,
                Severity = hashResult.Level,
                Title    = $"Malicious process: {proc.Name}",
                Detail   = $"{hashResult.Summary} — {proc.Path}",
                Source   = proc.Name,
                At       = DateTime.UtcNow
            }, $"proc:{proc.Hash}");

        return hashResult.Level;
    }

    // ── Batch scan all connections ────────────────────────────

    public async Task ScanConnectionsAsync(IEnumerable<NetworkConnection> connections)
    {
        // Analyse in parallel, max 4 concurrent to respect API rate limits
        var semaphore = new SemaphoreSlim(4, 4);
        var tasks = connections
            .Where(c => c.Threat == ThreatLevel.Unknown)
            .Select(async c =>
            {
                await semaphore.WaitAsync();
                try { await AnalyzeConnectionAsync(c); }
                finally { semaphore.Release(); }
            });
        await Task.WhenAll(tasks);
    }

    // ── Batch scan all processes ──────────────────────────────

    public async Task ScanProcessesAsync(IEnumerable<ProcessInfo> processes)
    {
        var semaphore = new SemaphoreSlim(2, 2); // be gentle with VT rate limits
        var tasks = processes
            .Where(p => !p.IsScanned && !string.IsNullOrEmpty(p.Hash))
            .Select(async p =>
            {
                await semaphore.WaitAsync();
                try { await AnalyzeProcessAsync(p); }
                finally { semaphore.Release(); }
            });
        await Task.WhenAll(tasks);
    }

    // ── Helpers ───────────────────────────────────────────────

    private async Task RaiseAlertAsync(Alert alert, string dedupeKey)
    {
        if (!_alertedKeys.Add(dedupeKey)) return; // already alerted
        await _db.SaveAlertAsync(alert);
        AlertRaised?.Invoke(this, alert);
    }
}
