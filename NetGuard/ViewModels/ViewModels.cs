using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetGuard.Models;
using NetGuard.Services;

namespace NetGuard.ViewModels;

// ─────────────────────────────────────────────────────────────
//  BASE CLASS
// ─────────────────────────────────────────────────────────────
public abstract partial class BaseViewModel : ObservableObject
{
    [ObservableProperty] private bool _isBusy;
    [ObservableProperty] private string _statusMessage = string.Empty;

    protected void SetBusy(bool busy, string msg = "")
    {
        IsBusy = busy;
        StatusMessage = msg;
    }
}

// ─────────────────────────────────────────────────────────────
//  DASHBOARD VIEWMODEL (Aggiornato e corretto)
// ─────────────────────────────────────────────────────────────
public partial class DashboardViewModel : ObservableObject, IDisposable
{
    private readonly ThreatAnalysisPipeline _pipeline;
    private readonly DatabaseService _db;
    private readonly MonitoringEngine _engine;

    // Status con icona e colore
    [ObservableProperty] private string overallStatus = "Scanning…";
    [ObservableProperty] private string overallStatusIcon = "\uf067";     // ✓
    [ObservableProperty] private Color overallStatusColor = Color.FromArgb("#22C55E");

    // Progress
    [ObservableProperty] private bool isBusy;
    [ObservableProperty] private double progress = 0.0;

    // Metrics
    [ObservableProperty] private int activeConnections;
    [ObservableProperty] private int activeProcesses;
    [ObservableProperty] private int threatCount;
    [ObservableProperty] private int unreadAlerts;

    public ObservableCollection<Alert> RecentAlerts { get; } = new();

    private Timer? _refreshTimer;

    public DashboardViewModel(
        ThreatAnalysisPipeline pipeline,
        DatabaseService db,
        MonitoringEngine engine)
    {
        _pipeline = pipeline;
        _db = db;
        _engine = engine;

        _engine.ProcessesUpdated += OnEngineProcessesUpdated;
        _engine.ConnectionsUpdated += OnEngineConnectionsUpdated;
        _engine.StatsUpdated += OnEngineStatsUpdated;
        _engine.ThreatDetected += OnEngineThreatDetected;
    }

    public void StartAutoRefresh(int intervalMs = 30000)
    {
        _refreshTimer?.Dispose();
        _refreshTimer = new Timer(_ =>
            MainThread.BeginInvokeOnMainThread(async () => await RefreshAsync()),
            null, 0, intervalMs);
    }

    [RelayCommand]
    public async Task RefreshAsync()
    {
        IsBusy = true;
        Progress = 0.3;

        try
        {
            var conns = _engine.Connections ?? new List<NetConnection>();
            var procs = _engine.Processes ?? new List<ProcessEntry>();

            ActiveConnections = conns.Count;
            ActiveProcesses = procs.Count;
            ThreatCount = conns.Count(c => c.Threat >= ThreatLevel.Medium) +
                          procs.Count(p => p.Threat >= ThreatLevel.Medium);

            var alerts = await _db.GetAlertsAsync(20);
            UnreadAlerts = alerts.Count(a => !a.IsRead);

            RecentAlerts.Clear();
            foreach (var a in alerts.Take(10))
                RecentAlerts.Add(a);

            Progress = 0.8;
            UpdateOverallStatus();
        }
        finally
        {
            IsBusy = false;
            Progress = 0;
        }
    }

    private void UpdateOverallStatus()
    {
        if (ThreatCount == 0)
        {
            OverallStatus = "System Clean";
            OverallStatusIcon = "\uf058";        // ✓
            OverallStatusColor = Color.FromArgb("#22C55E");
        }
        else if (ThreatCount <= 3)
        {
            OverallStatus = $"ALERT — {ThreatCount} threats!";
            OverallStatusIcon = "\uf071";        // ⚠
            OverallStatusColor = Color.FromArgb("#F59E0B");
        }
        else
        {
            OverallStatus = $"CRITICAL — {ThreatCount} threats!";
            OverallStatusIcon = "\uf05e";        // ✕
            OverallStatusColor = Color.FromArgb("#EF4444");
        }
    }

    private void OnEngineProcessesUpdated(List<ProcessEntry> procs)
    {
        MainThread.BeginInvokeOnMainThread(() =>
        {
            ActiveProcesses = procs.Count;
            UpdateOverallStatus();
        });
    }

    private void OnEngineConnectionsUpdated(List<NetConnection> conns)
    {
        MainThread.BeginInvokeOnMainThread(() =>
        {
            ActiveConnections = conns.Count;
            UpdateOverallStatus();
        });
    }

    private void OnEngineStatsUpdated(SystemStats stats)
    {
        MainThread.BeginInvokeOnMainThread(() =>
        {
            ActiveProcesses = stats.TotalProcesses;
            ActiveConnections = stats.TotalConnections;
            ThreatCount = stats.MaliciousProcesses + stats.ThreatAlerts;
            UpdateOverallStatus();
        });
    }

    private void OnEngineThreatDetected(ThreatAlert alert)
    {
        var a = new Alert
        {
            Id = alert.Id,
            Type = alert.Type,
            Severity = alert.Severity,
            Title = alert.Title,
            Detail = alert.Detail,
            Source = alert.Source,
            At = alert.At,
            IsRead = alert.IsRead,
            WasBlocked = alert.WasBlocked
        };

        MainThread.BeginInvokeOnMainThread(() =>
        {
            RecentAlerts.Insert(0, a);
            if (RecentAlerts.Count > 10) RecentAlerts.RemoveAt(10);
            UnreadAlerts++;
            ThreatCount++;
            UpdateOverallStatus();
        });
    }

    public void Dispose()
    {
        _refreshTimer?.Dispose();
        _engine.ProcessesUpdated -= OnEngineProcessesUpdated;
        _engine.ConnectionsUpdated -= OnEngineConnectionsUpdated;
        _engine.StatsUpdated -= OnEngineStatsUpdated;
        _engine.ThreatDetected -= OnEngineThreatDetected;
    }
}

// ─────────────────────────────────────────────────────────────
//  ALTRI VIEWMODELS (lasciati invariati)
// ─────────────────────────────────────────────────────────────

public partial class NetworkViewModel : BaseViewModel
{
    private readonly NetworkMonitorService _network;
    private readonly ThreatAnalysisPipeline _pipeline;

    [ObservableProperty] private string filterText = string.Empty;
    [ObservableProperty] private bool showAllStates = false;

    public ObservableCollection<NetworkConnection> Connections { get; } = new();
    private List<NetworkConnection> _allConnections = new();

    public NetworkViewModel(NetworkMonitorService network, ThreatAnalysisPipeline pipeline)
    {
        _network = network;
        _pipeline = pipeline;
    }

    [RelayCommand]
    public async Task RefreshAsync()
    {
        SetBusy(true, "Reading network connections…");
        try
        {
            _allConnections = await Task.Run(() => _network.GetConnectionsAsync());
            ApplyFilter();
            _ = Task.Run(() => _pipeline.ScanConnectionsAsync(_allConnections));
        }
        finally { SetBusy(false); }
    }

    partial void OnFilterTextChanged(string value) => ApplyFilter();
    partial void OnShowAllStatesChanged(bool value) => ApplyFilter();

    private void ApplyFilter()
    {
        var filtered = _allConnections.AsEnumerable();
        if (!ShowAllStates)
            filtered = filtered.Where(c => c.State == "ESTABLISHED");

        if (!string.IsNullOrWhiteSpace(FilterText))
        {
            var t = FilterText.ToLowerInvariant();
            filtered = filtered.Where(c =>
                c.RemoteAddress.Contains(t) ||
                c.Domain.Contains(t, StringComparison.OrdinalIgnoreCase) ||
                c.ProcessName.Contains(t, StringComparison.OrdinalIgnoreCase));
        }

        Connections.Clear();
        foreach (var c in filtered.OrderBy(c => c.Threat).ThenBy(c => c.RemoteAddress))
            Connections.Add(c);
    }
}
public partial class ProcessViewModel : BaseViewModel
{
    private readonly ProcessScannerService _scanner;
    private readonly ThreatAnalysisPipeline _pipeline;

    [ObservableProperty] private string filterText = string.Empty;
    [ObservableProperty] private bool showSystemProcesses = false;
    [ObservableProperty] private int scannedCount;
    [ObservableProperty] private int totalCount;

    public ObservableCollection<ProcessInfo> Processes { get; } = new();
    private List<ProcessInfo> _all = new();

    private CancellationTokenSource? _scanCts;

    public ProcessViewModel(ProcessScannerService scanner, ThreatAnalysisPipeline pipeline)
    {
        _scanner = scanner;
        _pipeline = pipeline;
    }

    [RelayCommand]
    public async Task ScanAsync()
    {
        _scanCts?.Cancel();
        _scanCts = new CancellationTokenSource();
        var ct = _scanCts.Token;

        SetBusy(true, "Enumerating processes…");

        try
        {
            _all = await _scanner.GetProcessesAsync(ct);
            if (ct.IsCancellationRequested) return;

            TotalCount = _all.Count;
            ScannedCount = 0;
            ApplyFilter();

            SetBusy(true, "Scanning hashes…");

            var tasks = _all
                .Where(p => !string.IsNullOrEmpty(p.Path))
                .Select(async p =>
                {
                    if (ct.IsCancellationRequested) return;
                    await _pipeline.AnalyzeProcessAsync(p);

                    if (ct.IsCancellationRequested) return;

                    MainThread.BeginInvokeOnMainThread(() =>
                    {
                        ScannedCount++;
                        var idx = Processes.IndexOf(p);
                        if (idx >= 0)
                        {
                            Processes.RemoveAt(idx);
                            Processes.Insert(idx, p);
                        }
                    });
                });

            await Task.WhenAll(tasks);
        }
        catch (OperationCanceledException)
        {
            StatusMessage = "Scan cancelled";
        }
        catch (Exception ex)
        {
            StatusMessage = "Error during scan: " + ex.Message;
        }
        finally
        {
            SetBusy(false);
            _scanCts?.Dispose();
            _scanCts = null;
        }
    }

    [RelayCommand]
    public Task CancelScanAsync()
    {
        _scanCts?.Cancel();
        StatusMessage = "Cancelling scan...";
        return Task.CompletedTask;
    }

    partial void OnFilterTextChanged(string value) => ApplyFilter();
    partial void OnShowSystemProcessesChanged(bool value) => ApplyFilter();

    private void ApplyFilter()
    {
        var filtered = _all.AsEnumerable();
        if (!ShowSystemProcesses)
            filtered = filtered.Where(p => !string.IsNullOrEmpty(p.Path));

        if (!string.IsNullOrWhiteSpace(FilterText))
        {
            var t = FilterText.ToLowerInvariant();
            filtered = filtered.Where(p =>
                p.Name.Contains(t, StringComparison.OrdinalIgnoreCase) ||
                p.Path.Contains(t, StringComparison.OrdinalIgnoreCase));
        }

        Processes.Clear();
        foreach (var p in filtered.OrderByDescending(p => p.Threat).ThenBy(p => p.Name))
            Processes.Add(p);
    }
}
public partial class RulesViewModel : BaseViewModel
{
    private readonly WhitelistEngine _engine;

    [ObservableProperty] private string newPattern = string.Empty;
    [ObservableProperty] private string newDescription = string.Empty;
    [ObservableProperty] private RuleType newType = RuleType.Domain;

    public ObservableCollection<WhitelistRule> Rules { get; } = new();

    public RulesViewModel(WhitelistEngine engine) => _engine = engine;

    [RelayCommand]
    public async Task LoadAsync()
    {
        SetBusy(true, "Loading rules…");
        try
        {
            var rules = await _engine.GetAllRulesAsync();
            Rules.Clear();
            foreach (var r in rules) Rules.Add(r);
        }
        finally { SetBusy(false); }
    }

    // ... resto del codice RulesViewModel
}

public partial class SettingsViewModel : BaseViewModel
{
    private readonly DatabaseService _db;
    private readonly ThreatIntelService _intel;
    private readonly DnsCheckerService _dns;
    private readonly NotificationService _notify;

    [ObservableProperty] private string virusTotalApiKey = "";
    [ObservableProperty] private string abuseIpDbApiKey = "";
    [ObservableProperty] private string primaryDns = "9.9.9.9";
    [ObservableProperty] private string fallbackDns = "1.1.1.1";
    [ObservableProperty] private bool useDoh = true;
    [ObservableProperty] private int scanInterval = 30;
    [ObservableProperty] private bool notifyOnThreat = true;

    public SettingsViewModel(
        DatabaseService db,
        ThreatIntelService intel,
        DnsCheckerService dns,
        NotificationService notify)
    {
        _db = db;
        _intel = intel;
        _dns = dns;
        _notify = notify;
    }

    [RelayCommand]
    public async Task LoadAsync()
    {
        var s = await _db.LoadSettingsAsync();
        VirusTotalApiKey = s.VirusTotalApiKey;
        AbuseIpDbApiKey = s.AbuseIpDbApiKey;
        PrimaryDns = s.PrimaryDnsServer;
        FallbackDns = s.FallbackDnsServer;
        UseDoh = s.UseDnsOverHttps;
        ScanInterval = s.ScanIntervalSec;
        NotifyOnThreat = s.NotifyOnThreat;
    }

    [RelayCommand]
    public async Task SaveAsync()
    {
        SetBusy(true, "Saving…");
        try
        {
            var s = new AppSettings
            {
                VirusTotalApiKey = VirusTotalApiKey,
                AbuseIpDbApiKey = AbuseIpDbApiKey,
                PrimaryDnsServer = PrimaryDns,
                FallbackDnsServer = FallbackDns,
                UseDnsOverHttps = UseDoh,
                ScanIntervalSec = ScanInterval,
                NotifyOnThreat = NotifyOnThreat
            };
            await _db.SaveSettingsAsync(s);

            _intel.UpdateSettings(s);
            _notify.UpdateSettings(s);

            StatusMessage = "✅ Settings saved";
        }
        finally { SetBusy(false); }
    }
}