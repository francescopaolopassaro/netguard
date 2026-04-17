using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetGuard.Models;
using NetGuard.Services;

namespace NetGuard.ViewModels;

// ─────────────────────────────────────────────────────────────
//  Base
// ─────────────────────────────────────────────────────────────
public abstract partial class BaseViewModel : ObservableObject
{
    [ObservableProperty] private bool   _isBusy;
    [ObservableProperty] private string _statusMessage = string.Empty;

    protected void SetBusy(bool busy, string msg = "")
    {
        IsBusy        = busy;
        StatusMessage = msg;
    }
}

// ─────────────────────────────────────────────────────────────
//  Dashboard
// ─────────────────────────────────────────────────────────────
public partial class DashboardViewModel : BaseViewModel, IDisposable
{
    private readonly ThreatAnalysisPipeline _pipeline;
    private readonly DatabaseService        _db;
    private readonly NetworkMonitorService  _network;
    private readonly ProcessScannerService  _scanner;

    [ObservableProperty] private int _activeConnections;
    [ObservableProperty] private int _activeProcesses;
    [ObservableProperty] private int _threatCount;
    [ObservableProperty] private int _unreadAlerts;
    [ObservableProperty] private string _overallStatus = "Scanning…";
    [ObservableProperty] private string _overallStatusColor = "#3182CE";

    public ObservableCollection<Alert> RecentAlerts { get; } = new();

    private Timer? _refreshTimer;

    public DashboardViewModel(
        ThreatAnalysisPipeline pipeline,
        DatabaseService        db,
        NetworkMonitorService  network,
        ProcessScannerService  scanner)
    {
        _pipeline = pipeline;
        _db       = db;
        _network  = network;
        _scanner  = scanner;

        _pipeline.AlertRaised += OnAlertRaised;
    }

    public void StartAutoRefresh(int intervalMs = 30_000)
    {
        _refreshTimer = new Timer(_ =>
            MainThread.BeginInvokeOnMainThread(async () => await RefreshAsync()),
            null, 0, intervalMs);
    }

    [RelayCommand]
    public async Task RefreshAsync()
    {
        SetBusy(true, "Refreshing…");
        try
        {
            var conns   = await _network.GetConnectionsAsync();
            var procs   = await _scanner.GetProcessesAsync();
            var alerts  = await _db.GetAlertsAsync(20);

            ActiveConnections = conns.Count;
            ActiveProcesses   = procs.Count;
            ThreatCount       = conns.Count(c => c.Threat >= ThreatLevel.Medium)
                              + procs.Count(p => p.Threat >= ThreatLevel.Medium);
            UnreadAlerts      = alerts.Count(a => !a.IsRead);

            RecentAlerts.Clear();
            foreach (var a in alerts.Take(10)) RecentAlerts.Add(a);

            UpdateOverallStatus();
        }
        finally { SetBusy(false); }
    }

    private void UpdateOverallStatus()
    {
        if (ThreatCount == 0)
        {
            OverallStatus      = "System clean";
            OverallStatusColor = "#38A169";
        }
        else if (ThreatCount <= 2)
        {
            OverallStatus      = $"{ThreatCount} threat(s) detected";
            OverallStatusColor = "#D97706";
        }
        else
        {
            OverallStatus      = $"ALERT — {ThreatCount} threats!";
            OverallStatusColor = "#E53E3E";
        }
    }

    private void OnAlertRaised(object? sender, Alert alert)
    {
        MainThread.BeginInvokeOnMainThread(() =>
        {
            RecentAlerts.Insert(0, alert);
            if (RecentAlerts.Count > 10) RecentAlerts.RemoveAt(10);
            UnreadAlerts++;
            ThreatCount++;
            UpdateOverallStatus();
        });
    }

    public void Dispose() => _refreshTimer?.Dispose();
}

// ─────────────────────────────────────────────────────────────
//  Network
// ─────────────────────────────────────────────────────────────
public partial class NetworkViewModel : BaseViewModel
{
    private readonly NetworkMonitorService  _network;
    private readonly ThreatAnalysisPipeline _pipeline;

    [ObservableProperty] private string _filterText = string.Empty;
    [ObservableProperty] private bool   _showAllStates = false;

    public ObservableCollection<NetworkConnection> Connections { get; } = new();
    private List<NetworkConnection> _allConnections = new();

    public NetworkViewModel(NetworkMonitorService network, ThreatAnalysisPipeline pipeline)
    {
        _network  = network;
        _pipeline = pipeline;
    }

    [RelayCommand]
    public async Task RefreshAsync()
    {
        SetBusy(true, "Reading network connections…");
        try
        {
            _allConnections = await _network.GetConnectionsAsync();
            ApplyFilter();

            // Background threat scan
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
                c.RemoteAddress.Contains(t)
                || c.Domain.Contains(t, StringComparison.OrdinalIgnoreCase)
                || c.ProcessName.Contains(t, StringComparison.OrdinalIgnoreCase));
        }

        Connections.Clear();
        foreach (var c in filtered.OrderBy(c => c.Threat).ThenBy(c => c.RemoteAddress))
            Connections.Add(c);
    }
}

// ─────────────────────────────────────────────────────────────
//  Process Scanner
// ─────────────────────────────────────────────────────────────
public partial class ProcessViewModel : BaseViewModel
{
    private readonly ProcessScannerService  _scanner;
    private readonly ThreatAnalysisPipeline _pipeline;

    [ObservableProperty] private string _filterText = string.Empty;
    [ObservableProperty] private bool   _showSystemProcesses = false;
    [ObservableProperty] private int    _scannedCount;
    [ObservableProperty] private int    _totalCount;

    public double ScanProgress => TotalCount == 0 ? 0 : (double)ScannedCount / TotalCount;

    partial void OnScannedCountChanged(int value) => OnPropertyChanged(nameof(ScanProgress));
    partial void OnTotalCountChanged(int value)   => OnPropertyChanged(nameof(ScanProgress));

    public ObservableCollection<ProcessInfo> Processes { get; } = new();
    private List<ProcessInfo> _all = new();

    private CancellationTokenSource? _scanCts;

    public ProcessViewModel(ProcessScannerService scanner, ThreatAnalysisPipeline pipeline)
    {
        _scanner  = scanner;
        _pipeline = pipeline;
    }

    [RelayCommand]
    public async Task ScanAsync()
    {
        // Cancel any previous scan
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

            // Scan in background, updating UI as results come in
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
                        // Refresh item in list
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
            // expected if cancelled
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
        try
        {
            _scanCts?.Cancel();
            StatusMessage = "Cancelling scan...";
        }
        catch { }
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
                p.Name.Contains(t, StringComparison.OrdinalIgnoreCase)
                || p.Path.Contains(t, StringComparison.OrdinalIgnoreCase));
        }

        Processes.Clear();
        foreach (var p in filtered.OrderByDescending(p => p.Threat).ThenBy(p => p.Name))
            Processes.Add(p);
    }
}

// ─────────────────────────────────────────────────────────────
//  Rules Manager
// ─────────────────────────────────────────────────────────────
public partial class RulesViewModel : BaseViewModel
{
    private readonly WhitelistEngine _engine;

    [ObservableProperty] private string   _newPattern     = string.Empty;
    [ObservableProperty] private string   _newDescription = string.Empty;
    [ObservableProperty] private RuleType _newType        = RuleType.Domain;

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

    [RelayCommand]
    public async Task AddRuleAsync()
    {
        if (string.IsNullOrWhiteSpace(NewPattern)) return;
        var rule = new WhitelistRule
        {
            Pattern     = NewPattern.Trim(),
            Type        = NewType,
            Description = NewDescription.Trim(),
            IsEnabled   = true,
            CreatedAt   = DateTime.UtcNow
        };
        await _engine.AddRuleAsync(rule);
        Rules.Add(rule);
        NewPattern     = "";
        NewDescription = "";
    }

    [RelayCommand]
    public async Task ToggleRuleAsync(WhitelistRule rule)
    {
        rule.IsEnabled = !rule.IsEnabled;
        await _engine.UpdateRuleAsync(rule);
        var idx = Rules.IndexOf(rule);
        if (idx >= 0) { Rules.RemoveAt(idx); Rules.Insert(idx, rule); }
    }

    [RelayCommand]
    public async Task DeleteRuleAsync(WhitelistRule rule)
    {
        await _engine.DeleteRuleAsync(rule.Id);
        Rules.Remove(rule);
    }
}

// ─────────────────────────────────────────────────────────────
//  Settings
// ─────────────────────────────────────────────────────────────
public partial class SettingsViewModel : BaseViewModel
{
    private readonly DatabaseService    _db;
    private readonly ThreatIntelService _intel;
    private readonly DnsCheckerService  _dns;
    private readonly NotificationService _notify;

    [ObservableProperty] private string _virusTotalApiKey  = "";
    [ObservableProperty] private string _abuseIpDbApiKey   = "";
    [ObservableProperty] private string _primaryDns        = "9.9.9.9";
    [ObservableProperty] private string _fallbackDns       = "1.1.1.1";
    [ObservableProperty] private bool   _useDoh            = true;
    [ObservableProperty] private int    _scanInterval      = 30;
    [ObservableProperty] private bool   _notifyOnThreat    = true;

    public SettingsViewModel(
        DatabaseService    db,
        ThreatIntelService intel,
        DnsCheckerService  dns,
        NotificationService notify)
    {
        _db     = db;
        _intel  = intel;
        _dns    = dns;
        _notify = notify;
    }

    [RelayCommand]
    public async Task LoadAsync()
    {
        var s = await _db.LoadSettingsAsync();
        VirusTotalApiKey = s.VirusTotalApiKey;
        AbuseIpDbApiKey  = s.AbuseIpDbApiKey;
        PrimaryDns       = s.PrimaryDnsServer;
        FallbackDns      = s.FallbackDnsServer;
        UseDoh           = s.UseDnsOverHttps;
        ScanInterval     = s.ScanIntervalSec;
        NotifyOnThreat   = s.NotifyOnThreat;
    }

    [RelayCommand]
    public async Task SaveAsync()
    {
        SetBusy(true, "Saving…");
        try
        {
            var s = new AppSettings
            {
                VirusTotalApiKey  = VirusTotalApiKey,
                AbuseIpDbApiKey   = AbuseIpDbApiKey,
                PrimaryDnsServer  = PrimaryDns,
                FallbackDnsServer = FallbackDns,
                UseDnsOverHttps   = UseDoh,
                ScanIntervalSec   = ScanInterval,
                NotifyOnThreat    = NotifyOnThreat
            };
            await _db.SaveSettingsAsync(s);

            // Propagate to live services — no restart needed
            _intel.UpdateSettings(s);
            _notify.UpdateSettings(s);

            StatusMessage = "✅ Settings saved";
        }
        finally { SetBusy(false); }
    }
}
