using NetGuard.Models;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace NetGuard.Services;

/// <summary>
/// Enumerates running processes, resolves their executable paths
/// and computes SHA-256 hashes for threat-intel lookups.
/// On Windows also reads digital signature publisher.
/// </summary>
public class ProcessScannerService
{
    private readonly Dictionary<string, string> _hashCache = new();

    // ── Public API ────────────────────────────────────────────

    public async Task<List<ProcessInfo>> GetProcessesAsync()
    {
        var result = new List<ProcessInfo>();
        var procs  = Process.GetProcesses();

        var tasks = procs.Select(async p =>
        {
            try
            {
                var info = await BuildProcessInfoAsync(p);
                return info;
            }
            catch { return null; }
            finally { p.Dispose(); }
        });

        var infos = await Task.WhenAll(tasks);
        result.AddRange(infos.Where(i => i != null)!);
        return result.OrderBy(p => p.Name).ToList();
    }

    public async Task<string> ComputeHashAsync(string path)
    {
        if (_hashCache.TryGetValue(path, out var cached)) return cached;
        try
        {
            await using var fs   = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var sha        = SHA256.Create();
            var hashBytes        = await Task.Run(() => sha.ComputeHash(fs));
            var hash             = Convert.ToHexString(hashBytes).ToLowerInvariant();
            _hashCache[path]     = hash;
            return hash;
        }
        catch { return ""; }
    }

    // ── Private ───────────────────────────────────────────────

    private async Task<ProcessInfo> BuildProcessInfoAsync(Process p)
    {
        var info = new ProcessInfo
        {
            Pid       = p.Id,
            Name      = p.ProcessName,
            StartTime = TryGetStartTime(p)
        };

        try
        {
            info.Path     = p.MainModule?.FileName ?? "";
            info.MemoryKb = p.WorkingSet64 / 1024;
        }
        catch { /* Access denied on some system processes */ }

        if (!string.IsNullOrEmpty(info.Path))
        {
            info.Hash = await ComputeHashAsync(info.Path);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                (info.IsSigned, info.Publisher) = GetWindowsSignatureInfo(info.Path);
        }

        return info;
    }

    private static DateTime TryGetStartTime(Process p)
    {
        try { return p.StartTime; }
        catch { return DateTime.MinValue; }
    }

    // ── Windows: Authenticode / digital signature ─────────────
    private static (bool IsSigned, string Publisher) GetWindowsSignatureInfo(string path)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return (false, "");
        try
        {
            // System.Security.Cryptography.X509Certificates approach
            var cert = X509CertificateLoader.LoadCertificateFromFile(path);
            return (true, cert.Subject);
        }
        catch { return (false, ""); }
    }

    // ── Linux: read /proc/PID/exe symlink ────────────────────
    public static string GetLinuxExePath(int pid)
    {
        try { return new FileInfo($"/proc/{pid}/exe").LinkTarget ?? ""; }
        catch { return ""; }
    }
}
