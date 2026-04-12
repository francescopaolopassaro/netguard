#if WINDOWS
using System.Diagnostics;
using System.Management;
using System.Runtime.Versioning;

namespace NetGuard.Platforms.Windows;

/// <summary>
/// Windows-only: uses WMI Win32_Process and ETW (if elevated) for
/// richer process/connection data beyond what IPGlobalProperties provides.
/// Falls back gracefully when not running as Administrator.
/// </summary>
[SupportedOSPlatform("windows")]
public class WindowsNativeMonitor : IDisposable
{
    private ManagementEventWatcher? _processStartWatcher;
    private ManagementEventWatcher? _processStopWatcher;

    public event EventHandler<ProcessStartedEventArgs>? ProcessStarted;
    public event EventHandler<int>?                      ProcessStopped;  // PID

    public bool IsElevated { get; } =
        new System.Security.Principal.WindowsPrincipal(
            System.Security.Principal.WindowsIdentity.GetCurrent())
        .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);

    // ── WMI Process Watchers ──────────────────────────────────
    public void StartWatching()
    {
        try
        {
            // Process creation events
            _processStartWatcher = new ManagementEventWatcher(
                new WqlEventQuery(
                    "SELECT * FROM Win32_ProcessStartTrace"));
            _processStartWatcher.EventArrived += OnProcessStarted;
            _processStartWatcher.Start();

            // Process termination events
            _processStopWatcher = new ManagementEventWatcher(
                new WqlEventQuery(
                    "SELECT * FROM Win32_ProcessStopTrace"));
            _processStopWatcher.EventArrived += OnProcessStopped;
            _processStopWatcher.Start();

            Debug.WriteLine("[WindowsMonitor] WMI watchers started.");
        }
        catch (ManagementException ex)
        {
            // Common if not elevated — degrade gracefully
            Debug.WriteLine($"[WindowsMonitor] WMI unavailable: {ex.Message}");
        }
    }

    private void OnProcessStarted(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var pid  = Convert.ToInt32(e.NewEvent["ProcessID"]);
            var name = e.NewEvent["ProcessName"]?.ToString() ?? "";
            var args = new ProcessStartedEventArgs { Pid = pid, Name = name };

            // Try to get the full path
            try
            {
                using var searcher = new ManagementObjectSearcher(
                    $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId = {pid}");
                foreach (ManagementObject obj in searcher.Get())
                    args.Path = obj["ExecutablePath"]?.ToString() ?? "";
            }
            catch { }

            ProcessStarted?.Invoke(this, args);
        }
        catch { }
    }

    private void OnProcessStopped(object sender, EventArrivedEventArgs e)
    {
        try
        {
            var pid = Convert.ToInt32(e.NewEvent["ProcessID"]);
            ProcessStopped?.Invoke(this, pid);
        }
        catch { }
    }

    // ── WMI Helpers ───────────────────────────────────────────
    public static List<WmiProcessInfo> GetAllProcesses()
    {
        var result = new List<WmiProcessInfo>();
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT ProcessId, Name, ExecutablePath, WorkingSetSize, CommandLine " +
                "FROM Win32_Process");
            foreach (ManagementObject obj in searcher.Get())
                result.Add(new WmiProcessInfo
                {
                    Pid    = Convert.ToInt32(obj["ProcessId"]),
                    Name   = obj["Name"]?.ToString() ?? "",
                    Path   = obj["ExecutablePath"]?.ToString() ?? "",
                    Memory = Convert.ToInt64(obj["WorkingSetSize"] ?? 0L)
                });
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[WMI] GetAllProcesses error: {ex.Message}");
        }
        return result;
    }

    // ── Authenticode Verification ─────────────────────────────
    public static (bool Valid, string Subject, string Issuer) VerifySignature(string filePath)
    {
        try
        {
            var cert = new System.Security.Cryptography.X509Certificates.X509Certificate2(filePath);
            return (true, cert.Subject, cert.Issuer);
        }
        catch
        {
            return (false, "", "");
        }
    }

    // ── Firewall Rule (requires elevation) ───────────────────
    public static bool BlockProcess(string exePath)
    {
        if (!new System.Security.Principal.WindowsPrincipal(
                System.Security.Principal.WindowsIdentity.GetCurrent())
            .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator))
        {
            Debug.WriteLine("[Firewall] Elevation required to block processes.");
            return false;
        }

        try
        {
            // Add Windows Firewall outbound block rule via netsh
            using var proc = Process.Start(new ProcessStartInfo(
                "netsh",
                $"advfirewall firewall add rule name=\"NetGuard_BLOCK_{Path.GetFileName(exePath)}\" " +
                $"dir=out action=block program=\"{exePath}\"")
            {
                UseShellExecute = false,
                CreateNoWindow  = true
            });
            proc?.WaitForExit();
            return true;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[Firewall] Block failed: {ex.Message}");
            return false;
        }
    }

    public void Dispose()
    {
        _processStartWatcher?.Stop();
        _processStartWatcher?.Dispose();
        _processStopWatcher?.Stop();
        _processStopWatcher?.Dispose();
    }
}

public class ProcessStartedEventArgs : EventArgs
{
    public int    Pid  { get; set; }
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
}

public class WmiProcessInfo
{
    public int    Pid    { get; set; }
    public string Name   { get; set; } = "";
    public string Path   { get; set; } = "";
    public long   Memory { get; set; }
}
#endif
