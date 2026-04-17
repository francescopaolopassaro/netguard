using NetGuard.Models;

namespace NetGuard.Services;

/// <summary>
/// Central real-time monitoring engine.
/// Runs continuous scan loops, auto-blocks threats, raises events.
/// </summary>
public class MonitoringEngine : IDisposable
{
    private readonly ProcessService  _proc;
    private readonly NetworkService  _net;
    private readonly ThreatService   _threat;
    private readonly BlockingService _block;
    private readonly WhitelistService _wl;

    private CancellationTokenSource _cts = new();
    private Task?  _procLoop;
    private Task?  _netLoop;
    private bool   _running;

    // ── Events (raised on background thread — dispatch to MainThread in handlers) ──
    public event Action<List<ProcessEntry>>  ProcessesUpdated  = delegate { };
    public event Action<List<NetConnection>>  ConnectionsUpdated = delegate { };
    public event Action<ThreatAlert>          ThreatDetected     = delegate { };
    public event Action<SystemStats>          StatsUpdated       = delegate { };

    public AppSettings Settings { get; set; } = new();

    // Current snapshots
    public List<ProcessEntry>  Processes   { get; private set; } = new();
    public List<NetConnection> Connections { get; private set; } = new();
    public SystemStats         Stats       { get; private set; } = new();

    // Track what we've already alerted on to avoid spam
    private readonly HashSet<string> _alertedHashes = new();
    private readonly HashSet<string> _alertedIps    = new();
    private readonly HashSet<string> _alertedDomains = new();

    public MonitoringEngine(
     ProcessService proc,      // ← deve essere ProcessService (non ProcessScannerService)
     NetworkService net,
     ThreatService threat,    // o ThreatIntelService se lo usi
     BlockingService block,
     WhitelistService wl)        // o WhitelistEngine
    {
        _proc = proc;
        _net = net;
        _threat = threat;
        _block = block;
        _wl = wl;
    }

    // ── Start / Stop ──────────────────────────────────────────────────────

    public void Start()
    {
        if (_running) return;
        _running = true;
        _cts     = new CancellationTokenSource();
        _procLoop = Task.Run(() => ProcessLoopAsync(_cts.Token));
        _netLoop  = Task.Run(() => NetworkLoopAsync(_cts.Token));
    }

    public void Stop()
    {
        _running = false;
        _cts.Cancel();
    }

    // ── Process loop ──────────────────────────────────────────────────────

    private async Task ProcessLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var procs = await _proc.GetAllAsync();

                // Parallel threat scan (cap at 4 concurrent)
                var sem   = new SemaphoreSlim(4, 4);
                var tasks = procs
                    .Where(p => !p.IsScanned && !string.IsNullOrEmpty(p.Hash))
                    .Select(async p =>
                    {
                        await sem.WaitAsync(ct);
                        try { await ScanProcessAsync(p); }
                        finally { sem.Release(); }
                    });
                await Task.WhenAll(tasks);

                Processes = procs;
                ProcessesUpdated.Invoke(procs);
                UpdateStats();
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[ProcLoop] {ex.Message}"); }

            await Task.Delay(TimeSpan.FromSeconds(Settings.ScanIntervalSec), ct)
                .ContinueWith(_ => { }); // Swallow cancellation
        }
    }

    private async Task ScanProcessAsync(ProcessEntry p)
    {
        // Skip if hash already seen and clean
        if (_alertedHashes.TryGetValue(p.Hash, out _) == false
            && await _wl.IsProcessWhitelistedAsync(p.Name))
        {
            p.Threat   = ThreatLevel.Clean;
            p.IsScanned= true;
            return;
        }

        var (level, detail) = await _threat.CheckHashAsync(p.Hash);
        p.Threat       = level;
        p.ThreatDetail = detail;
        p.IsScanned    = true;

        if (level < ThreatLevel.Medium) return;
        if (_alertedHashes.Contains(p.Hash)) return;
        _alertedHashes.Add(p.Hash);

        var alert = new ThreatAlert
        {
            Type     = AlertType.Process,
            Severity = level,
            Title    = $"Malicious process: {p.Name}",
            Detail   = $"{detail} — PID {p.Pid} — {p.Path}",
            Source   = p.Name,
            At       = DateTime.UtcNow
        };

        // Auto-block
        if (Settings.AutoBlockProcesses && level >= Settings.BlockThreshold)
        {
            var ok = await _block.BlockProcessAsync(p, _proc);
            alert.WasBlocked = ok;
            alert.Action     = ok ? BlockAction.Killed : null;
            p.IsBlocked      = ok;
        }

        ThreatDetected.Invoke(alert);
    }

    // ── Network loop ──────────────────────────────────────────────────────

    private async Task NetworkLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var conns = await _net.GetConnectionsAsync();

                var sem   = new SemaphoreSlim(4, 4);
                var tasks = conns
                    .Where(c => c.Threat == ThreatLevel.Unknown
                             && !string.IsNullOrEmpty(c.RemoteAddress))
                    .Select(async c =>
                    {
                        await sem.WaitAsync(ct);
                        try { await ScanConnectionAsync(c); }
                        finally { sem.Release(); }
                    });
                await Task.WhenAll(tasks);

                Connections = conns;
                ConnectionsUpdated.Invoke(conns);
                UpdateStats();
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { System.Diagnostics.Debug.WriteLine($"[NetLoop] {ex.Message}"); }

            await Task.Delay(TimeSpan.FromSeconds(Math.Max(2, Settings.ScanIntervalSec)), ct)
                .ContinueWith(_ => { });
        }
    }

    private async Task ScanConnectionAsync(NetConnection c)
    {
        // Whitelist check
        if (!string.IsNullOrEmpty(c.Domain) && await _wl.IsDomainWhitelistedAsync(c.Domain))
        { c.Threat = ThreatLevel.Clean; return; }
        if (await _wl.IsIpWhitelistedAsync(c.RemoteAddress))
        { c.Threat = ThreatLevel.Clean; return; }

        // DNS reputation via Quad9
        if (!string.IsNullOrEmpty(c.Domain) && !_alertedDomains.Contains(c.Domain))
        {
            var (blocked, detail) = await _threat.CheckDomainAsync(c.Domain);
            if (blocked)
            {
                c.Threat = ThreatLevel.High;
                _alertedDomains.Add(c.Domain);

                var alert = new ThreatAlert
                {
                    Type     = AlertType.Dns,
                    Severity = ThreatLevel.High,
                    Title    = $"Malicious domain: {c.Domain}",
                    Detail   = detail,
                    Source   = c.Domain,
                    At       = DateTime.UtcNow
                };

                if (Settings.AutoBlockDomains)
                {
                    var ok = await _block.BlockDomainAsync(c.Domain);
                    alert.WasBlocked = ok;
                    alert.Action     = ok ? BlockAction.DnsBlocked : null;
                    c.IsBlocked      = ok;
                }
                ThreatDetected.Invoke(alert);
                return;
            }
        }

        // IP reputation
        if (!_alertedIps.Contains(c.RemoteAddress))
        {
            var (level, detail) = await _threat.CheckIpAsync(c.RemoteAddress);
            c.Threat = level;

            if (level >= ThreatLevel.Medium)
            {
                _alertedIps.Add(c.RemoteAddress);
                var alert = new ThreatAlert
                {
                    Type     = AlertType.Network,
                    Severity = level,
                    Title    = $"Suspicious IP: {c.RemoteAddress}",
                    Detail   = detail,
                    Source   = c.RemoteAddress,
                    At       = DateTime.UtcNow
                };

                if (Settings.AutoBlockIps && level >= Settings.BlockThreshold)
                {
                    var ok = await _block.BlockIpAsync(c.RemoteAddress);
                    alert.WasBlocked = ok;
                    alert.Action     = ok ? BlockAction.FirewallBlocked : null;
                    c.IsBlocked      = ok;
                }
                ThreatDetected.Invoke(alert);
            }
        }
        else if (c.Threat == ThreatLevel.Unknown)
            c.Threat = ThreatLevel.Clean;
    }

    // ── Stats ─────────────────────────────────────────────────────────────

    private void UpdateStats()
    {
        Stats = new SystemStats
        {
            TotalProcesses     = Processes.Count,
            ScannedProcesses   = Processes.Count(p => p.IsScanned),
            MaliciousProcesses = Processes.Count(p => p.Threat >= ThreatLevel.Medium),
            BlockedProcesses   = Processes.Count(p => p.IsBlocked),
            TotalConnections   = Connections.Count,
            BlockedConnections = Connections.Count(c => c.IsBlocked),
            ThreatAlerts       = _alertedHashes.Count + _alertedIps.Count + _alertedDomains.Count,
            IsElevated         = ElevationService.IsElevated
        };
        StatsUpdated.Invoke(Stats);
    }

    public void Dispose()
    {
        Stop();
        _cts.Dispose();
    }
}
