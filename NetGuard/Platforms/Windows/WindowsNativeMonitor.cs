#if WINDOWS
using System.Management;
using System.Runtime.Versioning;

namespace NetGuard.Platforms.Windows;

[SupportedOSPlatform("windows")]
public sealed class WindowsNativeMonitor : IDisposable
{
    private ManagementEventWatcher? _startWatcher;
    private ManagementEventWatcher? _stopWatcher;

    public event Action<int, string, string>? ProcessStarted;  // pid, name, path
    public event Action<int>?                 ProcessStopped;  // pid

    public void Start()
    {
        try
        {
            _startWatcher = new ManagementEventWatcher(
                new WqlEventQuery("SELECT * FROM Win32_ProcessStartTrace"));
            _startWatcher.EventArrived += (_, e) =>
            {
                var pid  = Convert.ToInt32(e.NewEvent["ProcessID"]);
                var name = e.NewEvent["ProcessName"]?.ToString() ?? "";
                // Resolve path via WMI
                var path = "";
                try
                {
                    using var s = new ManagementObjectSearcher(
                        $"SELECT ExecutablePath FROM Win32_Process WHERE ProcessId={pid}");
                    foreach (ManagementObject o in s.Get())
                        path = o["ExecutablePath"]?.ToString() ?? "";
                }
                catch { }
                ProcessStarted?.Invoke(pid, name, path);
            };
            _startWatcher.Start();

            _stopWatcher = new ManagementEventWatcher(
                new WqlEventQuery("SELECT * FROM Win32_ProcessStopTrace"));
            _stopWatcher.EventArrived += (_, e) =>
                ProcessStopped?.Invoke(Convert.ToInt32(e.NewEvent["ProcessID"]));
            _stopWatcher.Start();
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"[WMI] {ex.Message}");
        }
    }

    /// <summary>
    /// Block a process via Windows Firewall outbound rule (requires elevation).
    /// </summary>
    public static bool AddFirewallBlock(string exePath, string ruleName)
    {
        try
        {
            using var proc = System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo(
                    "netsh",
                    $"advfirewall firewall add rule name=\"{ruleName}\" " +
                    $"dir=out action=block program=\"{exePath}\" enable=yes")
                {
                    UseShellExecute        = false,
                    CreateNoWindow         = true,
                    RedirectStandardOutput = true
                });
            proc?.WaitForExit(3000);
            return proc?.ExitCode == 0;
        }
        catch { return false; }
    }

    public void Dispose()
    {
        _startWatcher?.Stop();
        _startWatcher?.Dispose();
        _stopWatcher?.Stop();
        _stopWatcher?.Dispose();
    }
}
#endif
