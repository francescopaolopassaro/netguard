using System.Diagnostics;
using System.Runtime.InteropServices;

namespace NetGuard.Services;

/// <summary>
/// Checks for and requests elevated privileges.
/// Windows: Administrator via UAC
/// Linux:   root via pkexec/sudo
/// </summary>
public static class ElevationService
{
    private static bool? _cachedElevated;

    public static bool IsElevated
    {
        get
        {
            if (_cachedElevated.HasValue) return _cachedElevated.Value;
            _cachedElevated = CheckElevated();
            return _cachedElevated.Value;
        }
    }

    private static bool CheckElevated()
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                using var identity  = System.Security.Principal.WindowsIdentity.GetCurrent();
                var principal = new System.Security.Principal.WindowsPrincipal(identity);
                return principal.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
            }
            else
            {
                // Linux: check if running as root (UID 0)
                var uid = GetLinuxUid();
                return uid == 0;
            }
        }
        catch { return false; }
    }

    /// <summary>
    /// Restart the application with elevated privileges.
    /// </summary>
    public static void RestartElevated()
    {
        if (IsElevated) return;

        var exe = Process.GetCurrentProcess().MainModule?.FileName ?? "";

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            Process.Start(new ProcessStartInfo(exe)
            {
                UseShellExecute = true,
                Verb = "runas"  // UAC prompt
            });
        }
        else
        {
            // Linux: re-launch via pkexec
            Process.Start(new ProcessStartInfo("pkexec", $"\"{exe}\"")
            {
                UseShellExecute = false
            });
        }

        Environment.Exit(0);
    }

    public static string ElevationStatus =>
        IsElevated ? "🔓 Administrator" : "🔒 Limited (some features disabled)";

    public static string ElevationHint =>
        IsElevated ? "" : RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? "Run as Administrator for full process visibility and blocking"
            : "Run as root (sudo) for full process visibility and blocking";

    private static int GetLinuxUid()
    {
        try
        {
            var output = RunCommand("id", "-u");
            return int.TryParse(output.Trim(), out var uid) ? uid : -1;
        }
        catch { return -1; }
    }

    private static string RunCommand(string cmd, string args)
    {
        using var proc = new Process
        {
            StartInfo = new ProcessStartInfo(cmd, args)
            {
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            }
        };
        proc.Start();
        var result = proc.StandardOutput.ReadToEnd();
        proc.WaitForExit();
        return result;
    }
}
