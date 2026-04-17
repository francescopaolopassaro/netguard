using System.Collections.ObjectModel;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using NetGuard.Models;
using NetGuard.Services;

namespace NetGuard.ViewModels;

public partial class MainViewModel : ObservableObject, IDisposable
{
    private readonly MonitoringEngine _engine;
    private readonly BlockingService  _block;
    private readonly DatabaseService  _db;
    private readonly ProcessService   _proc;

    // ── Observable state ────────────────────────────────────────────────

    [ObservableProperty] private bool   _isElevated;
    [ObservableProperty] private string _elevationStatus = "";
    [ObservableProperty] private bool   _isRunning;
    [ObservableProperty] private string _scanStatus = "Stopped";

    // Stats
    [ObservableProperty] private int    _totalProcesses;
    [ObservableProperty] private int    _maliciousProcesses;
    [ObservableProperty] private int    _blockedCount;
    [ObservableProperty] private int    _totalConnections;
    [ObservableProperty] private int    _threatAlerts;
    [ObservableProperty] private string _overallStatus = "OFFLINE";
    [ObservableProperty] private Color  _overallStatusColor = Color.FromArgb("#636366");

    // Process tab
    [ObservableProperty] private string _procFilter = "";
    [ObservableProperty] private bool   _showOnlyThreats;
    public ObservableCollection<ProcessEntry>  Processes   { get; } = new();
    private List<ProcessEntry> _allProcs = new();

    // Network tab
    [ObservableProperty] private string _netFilter = "";
    [ObservableProperty] private bool   _showEstablishedOnly = true;
    public ObservableCollection<NetConnection> Connections { get; } = new();
    private List<NetConnection> _allConns = new();

    // Alerts tab
    public ObservableCollection<ThreatAlert>  Alerts      { get; } = new();

    // Settings
    [ObservableProperty] private AppSettings  _settings = new();

    // ── Selected items for detail ────────────────────────────────────────
    [ObservableProperty] private ProcessEntry?  _selectedProcess;
    [ObservableProperty] private NetConnection? _selectedConnection;

    // ── Auto-block toggles ───────────────────────────────────────────────
    public bool AutoBlockProcesses
    {
        get => Settings.AutoBlockProcesses;
        set { Settings.AutoBlockProcesses = value; _engine.Settings = Settings; OnPropertyChanged(); }
    }
    public bool AutoBlockDomains
    {
        get => Settings.AutoBlockDomains;
        set { Settings.AutoBlockDomains = value; _engine.Settings = Settings; OnPropertyChanged(); }
    }
    public bool AutoBlockIps
    {
        get => Settings.AutoBlockIps;
        set { Settings.AutoBlockIps = value; _engine.Settings = Settings; OnPropertyChanged(); }
    }

    public MainViewModel(
        MonitoringEngine engine,
        BlockingService  block,
        DatabaseService  db,
        ProcessService   proc)
    {
        _engine = engine;
        _block  = block;
        _db     = db;
        _proc   = proc;

        IsElevated      = ElevationService.IsElevated;
        ElevationStatus = ElevationService.ElevationStatus;

        // Wire up engine events
        _engine.ProcessesUpdated   += OnProcessesUpdated;
        _engine.ConnectionsUpdated += OnConnectionsUpdated;
        _engine.ThreatDetected     += OnThreatDetected;
        _engine.StatsUpdated       += OnStatsUpdated;
    }

    // ── Init ─────────────────────────────────────────────────────────────

    public async Task InitAsync()
    {
        Settings = await _db.LoadSettingsAsync();
        _engine.Settings = Settings;
        OnPropertyChanged(nameof(AutoBlockProcesses));
        OnPropertyChanged(nameof(AutoBlockDomains));
        OnPropertyChanged(nameof(AutoBlockIps));

        var alerts = await _db.GetAlertsAsync(100);
        foreach (var a in alerts) Alerts.Add(a);

        StartCommand.Execute(null);
    }

    // ── Commands ──────────────────────────────────────────────────────────

    [RelayCommand]
    private void Start()
    {
        _engine.Start();
        IsRunning  = true;
        ScanStatus = $"Scanning every {Settings.ScanIntervalSec}s";
        UpdateOverallStatus();
    }

    [RelayCommand]
    private void Stop()
    {
        _engine.Stop();
        IsRunning  = false;
        ScanStatus = "Stopped";
        OverallStatus      = "PAUSED";
        OverallStatusColor = Color.FromArgb("#FF9500");
    }

    [RelayCommand]
    private void ElevateNow() => ElevationService.RestartElevated();

    [RelayCommand]
    private async Task KillProcessAsync(ProcessEntry? proc)
    {
        if (proc == null) return;
        var ok = await Task.Run(() => _proc.KillProcess(proc.Pid));
        if (ok.Success) Processes.Remove(proc);
    }

    [RelayCommand]
    private async Task BlockProcessAsync(ProcessEntry? proc)
    {
        if (proc == null) return;
        await _block.BlockProcessAsync(proc, _proc);
        proc.IsBlocked = true;
        RefreshProcessList();
    }

    [RelayCommand]
    private async Task BlockDomainAsync(NetConnection? conn)
    {
        if (conn == null || string.IsNullOrEmpty(conn.Domain)) return;
        await _block.BlockDomainAsync(conn.Domain);
        conn.IsBlocked = true;
        RefreshNetList();
    }

    [RelayCommand]
    private async Task BlockIpAsync(NetConnection? conn)
    {
        if (conn == null) return;
        await _block.BlockIpAsync(conn.RemoteAddress);
        conn.IsBlocked = true;
        RefreshNetList();
    }

    [RelayCommand]
    private async Task SaveSettingsAsync()
    {
        await _db.SaveSettingsAsync(Settings);
        _engine.Settings = Settings;
    }

    // ── Filters ───────────────────────────────────────────────────────────

    partial void OnProcFilterChanged(string v)         => RefreshProcessList();
    partial void OnShowOnlyThreatsChanged(bool v)      => RefreshProcessList();
    partial void OnNetFilterChanged(string v)          => RefreshNetList();
    partial void OnShowEstablishedOnlyChanged(bool v)  => RefreshNetList();

    private void RefreshProcessList()
    {
        var q = _allProcs.AsEnumerable();
        if (ShowOnlyThreats)
            q = q.Where(p => p.Threat >= ThreatLevel.Medium);
        if (!string.IsNullOrWhiteSpace(ProcFilter))
        {
            var f = ProcFilter.ToLowerInvariant();
            q = q.Where(p => p.Name.Contains(f, StringComparison.OrdinalIgnoreCase)
                           || p.Path.Contains(f, StringComparison.OrdinalIgnoreCase));
        }
        MainThread.BeginInvokeOnMainThread(() =>
        {
            Processes.Clear();
            foreach (var p in q.OrderByDescending(p => p.Threat).ThenBy(p => p.Name))
                Processes.Add(p);
        });
    }

    private void RefreshNetList()
    {
        var q = _allConns.AsEnumerable();
        if (ShowEstablishedOnly)
            q = q.Where(c => c.State == "ESTABLISHED");
        if (!string.IsNullOrWhiteSpace(NetFilter))
        {
            var f = NetFilter.ToLowerInvariant();
            q = q.Where(c => c.RemoteAddress.Contains(f)
                           || c.Domain.Contains(f, StringComparison.OrdinalIgnoreCase)
                           || c.ProcessName.Contains(f, StringComparison.OrdinalIgnoreCase));
        }
        MainThread.BeginInvokeOnMainThread(() =>
        {
            Connections.Clear();
            foreach (var c in q.OrderByDescending(c => c.Threat).ThenBy(c => c.Domain))
                Connections.Add(c);
        });
    }

    // ── Engine events ─────────────────────────────────────────────────────

    private void OnProcessesUpdated(List<ProcessEntry> procs)
    {
        _allProcs = procs;
        RefreshProcessList();
    }

    private void OnConnectionsUpdated(List<NetConnection> conns)
    {
        _allConns = conns;
        RefreshNetList();
    }

    private void OnThreatDetected(ThreatAlert alert)
    {
        _ = _db.SaveAlertAsync(alert);
        MainThread.BeginInvokeOnMainThread(() =>
        {
            Alerts.Insert(0, alert);
            ThreatAlerts++;
            UpdateOverallStatus();
        });
    }

    private void OnStatsUpdated(SystemStats stats)
    {
        MainThread.BeginInvokeOnMainThread(() =>
        {
            TotalProcesses    = stats.TotalProcesses;
            MaliciousProcesses= stats.MaliciousProcesses;
            BlockedCount      = stats.BlockedProcesses + stats.BlockedConnections;
            TotalConnections  = stats.TotalConnections;
            ThreatAlerts      = Alerts.Count;
            UpdateOverallStatus();
        });
    }

    private void UpdateOverallStatus()
    {
        if (!IsRunning)                          { OverallStatus = "OFFLINE";    OverallStatusColor = Color.FromArgb("#636366"); return; }
        if (MaliciousProcesses > 0 || ThreatAlerts > 5) { OverallStatus = "CRITICAL";  OverallStatusColor = Color.FromArgb("#FF0040"); return; }
        if (ThreatAlerts > 0)                    { OverallStatus = "ALERT";      OverallStatusColor = Color.FromArgb("#FF4444"); return; }
        OverallStatus      = "PROTECTED";
        OverallStatusColor = Color.FromArgb("#30D158");
    }

    public void Dispose()
    {
        _engine.ProcessesUpdated   -= OnProcessesUpdated;
        _engine.ConnectionsUpdated -= OnConnectionsUpdated;
        _engine.ThreatDetected     -= OnThreatDetected;
        _engine.StatsUpdated       -= OnStatsUpdated;
        _engine.Dispose();
    }
}
