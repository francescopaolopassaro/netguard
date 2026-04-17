using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using NetGuard.Models;

namespace NetGuard.Services;

public class ProcessService
{
    private readonly Dictionary<string, string>  _hashCache   = new();
    private readonly Dictionary<int, double>     _prevCpu     = new();
    private readonly Dictionary<int, DateTime>   _prevTime    = new();
    private readonly Dictionary<int, ProcessEntry> _knownProcs = new();
    private readonly SemaphoreSlim _hashLock = new(4, 4); // 4 parallel hashes

    // ── Public ────────────────────────────────────────────────────────────

    public async Task<List<ProcessEntry>> GetAllAsync()
    {
        var result = new List<ProcessEntry>();
        var procs  = Process.GetProcesses();

        var tasks = procs.Select(p => BuildEntryAsync(p)).ToArray();
        var entries = await Task.WhenAll(tasks);

        foreach (var e in entries)
            if (e != null) result.Add(e);

        return result.OrderBy(p => p.Name).ToList();
    }

    public async Task<string?> ComputeHashAsync(string path)
    {
        if (string.IsNullOrEmpty(path) || !File.Exists(path)) return null;
        if (_hashCache.TryGetValue(path, out var cached)) return cached;

        await _hashLock.WaitAsync();
        try
        {
            if (_hashCache.TryGetValue(path, out cached)) return cached;
            await using var fs = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var sha  = SHA256.Create();
            var bytes  = await Task.Run(() => sha.ComputeHash(fs));
            var hash   = Convert.ToHexString(bytes).ToLowerInvariant();
            _hashCache[path] = hash;
            return hash;
        }
        catch { return null; }
        finally { _hashLock.Release(); }
    }

    // Kill a process by PID — works even without elevation for own processes
    public (bool Success, string Error) KillProcess(int pid)
    {
        try
        {
            var proc = Process.GetProcessById(pid);
            proc.Kill(entireProcessTree: true);
            return (true, "");
        }
        catch (Exception ex)
        {
            // On Windows without elevation: try via taskkill
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return KillViaTaskkill(pid);
            // On Linux: try via kill command
            return KillViaSignal(pid);
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────

    private async Task<ProcessEntry?> BuildEntryAsync(Process p)
    {
        var entry = new ProcessEntry { Pid = p.Id, Name = p.ProcessName };
        try
        {
            entry.Threads  = p.Threads.Count;
            entry.MemoryKb = p.WorkingSet64 / 1024;

            // CPU %
            entry.CpuPercent = ComputeCpu(p);

            // Path (may throw on system/protected processes)
            try { entry.Path = p.MainModule?.FileName ?? ""; }
            catch { entry.Path = GetFallbackPath(p.Id); }

            // Command line
            try { entry.CommandLine = GetCommandLine(p); }
            catch { }

            // Start time
            try { entry.StartTime = p.StartTime; }
            catch { }

            // User
            entry.User = GetProcessUser(p.Id);

            // Hash (async, non-blocking)
            if (!string.IsNullOrEmpty(entry.Path))
            {
                var hash = await ComputeHashAsync(entry.Path);
                if (hash != null) entry.Hash = hash;

                // Authenticode on Windows
                if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                    (entry.IsSigned, entry.Publisher) = GetSignatureInfo(entry.Path);
            }

            return entry;
        }
        catch { return entry; } // Return partial entry rather than null
        finally { p.Dispose(); }
    }

    private double ComputeCpu(Process p)
    {
        try
        {
            var now      = DateTime.UtcNow;
            var totalCpu = p.TotalProcessorTime;

            if (_prevCpu.TryGetValue(p.Id, out var prevVal) &&
                _prevTime.TryGetValue(p.Id, out var prevT))
            {
                var elapsed  = (now - prevT).TotalSeconds;
                var cpuDelta = (totalCpu.TotalSeconds - prevVal);
                var cpu      = (cpuDelta / (elapsed * Environment.ProcessorCount)) * 100.0;
                _prevCpu[p.Id]  = totalCpu.TotalSeconds;
                _prevTime[p.Id] = now;
                return Math.Round(Math.Max(0, cpu), 1);
            }
            _prevCpu[p.Id]  = totalCpu.TotalSeconds;
            _prevTime[p.Id] = now;
        }
        catch { }
        return 0;
    }

    private static string GetFallbackPath(int pid)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return "";
        try
        {
            return new FileInfo($"/proc/{pid}/exe").LinkTarget ?? "";
        }
        catch { return ""; }
    }

    private static string GetCommandLine(Process p)
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            try
            {
                var cmdline = File.ReadAllText($"/proc/{p.Id}/cmdline");
                return cmdline.Replace('\0', ' ').Trim();
            }
            catch { return ""; }
        }
        return ""; // Windows: WMI handled in platform layer
    }

    private static string GetProcessUser(int pid)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return "";
        try
        {
            var status = File.ReadAllLines($"/proc/{pid}/status");
            var uidLine = status.FirstOrDefault(l => l.StartsWith("Uid:"));
            if (uidLine == null) return "";
            var uid = uidLine.Split('\t')[1].Trim();
            return uid == "0" ? "root" : $"uid:{uid}";
        }
        catch { return ""; }
    }

    private static (bool Signed, string Publisher) GetSignatureInfo(string path)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || !File.Exists(path))
            return (false, "");
        try
        {
            var cert = System.Security.Cryptography.X509Certificates
                .X509Certificate.CreateFromSignedFile(path);
            return (true, cert.Subject);
        }
        catch { return (false, ""); }
    }

    private static (bool, string) KillViaTaskkill(int pid)
    {
        try
        {
            using var proc = Process.Start(new ProcessStartInfo(
                "taskkill", $"/F /PID {pid} /T")
            {
                UseShellExecute        = false,
                CreateNoWindow         = true,
                RedirectStandardOutput = true,
                RedirectStandardError  = true
            });
            proc?.WaitForExit(3000);
            return (proc?.ExitCode == 0, "");
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    private static (bool, string) KillViaSignal(int pid)
    {
        try
        {
            using var proc = Process.Start(new ProcessStartInfo(
                "kill", $"-9 {pid}")
            {
                UseShellExecute        = false,
                CreateNoWindow         = true,
                RedirectStandardError  = true
            });
            proc?.WaitForExit(3000);
            return (proc?.ExitCode == 0, "");
        }
        catch (Exception ex) { return (false, ex.Message); }
    }
}
