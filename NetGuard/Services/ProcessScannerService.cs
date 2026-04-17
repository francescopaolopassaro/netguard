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
    private readonly SemaphoreSlim _semaphore = new(Math.Max(2, Environment.ProcessorCount));

    // ── Public API ────────────────────────────────────────────

    public async Task<List<ProcessInfo>> GetProcessesAsync(CancellationToken cancellationToken = default)
    {
        var result = new List<ProcessInfo>();

        Process[] procs;
        try
        {
            procs = Process.GetProcesses();
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"GetProcesses failed: {ex}");
            return result;
        }

        var tasks = new List<Task<ProcessInfo?>>();

        foreach (var p in procs)
        {
            // Capture p for closure
            var proc = p;
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    await _semaphore.WaitAsync(cancellationToken);
                    if (cancellationToken.IsCancellationRequested) return null;
                    return await BuildProcessInfoSafeAsync(proc, cancellationToken);
                }
                catch (OperationCanceledException) { return null; }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error scanning process {proc.Id}: {ex}");
                    return null;
                }
                finally
                {
                    try { _semaphore.Release(); } catch { }
                    try { proc.Dispose(); } catch { }
                }
            }, cancellationToken));
        }

        var infos = await Task.WhenAll(tasks);
        result.AddRange(infos.Where(i => i != null)!.Cast<ProcessInfo>());
        return result.OrderBy(p => p.Name).ToList();
    }

    public async Task<string> ComputeHashAsync(string path, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(path)) return "";
        if (_hashCache.TryGetValue(path, out var cached)) return cached;
        try
        {
            await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var sha = SHA256.Create();
            // Compute hash on thread pool to avoid blocking caller thread
            var hashBytes = await Task.Run(() => sha.ComputeHash(fs), cancellationToken);
            var hash = Convert.ToHexString(hashBytes).ToLowerInvariant();
            _hashCache[path] = hash;
            return hash;
        }
        catch (OperationCanceledException) { return ""; }
        catch (Exception ex)
        {
            Debug.WriteLine($"ComputeHash failed for '{path}': {ex.Message}");
            return "";
        }
    }

    // ── Private ───────────────────────────────────────────────────────

    private async Task<ProcessInfo?> BuildProcessInfoSafeAsync(Process p, CancellationToken cancellationToken)
    {
        var info = new ProcessInfo
        {
            Pid = p.Id,
            Name = string.Empty,
            StartTime = DateTime.MinValue
        };

        try
        {
            info.Name = p.ProcessName;
        }
        catch { info.Name = "<unknown>"; }

        try { info.StartTime = TryGetStartTime(p); } catch { info.StartTime = DateTime.MinValue; }

        try
        {
            try
            {
                info.Path = p.MainModule?.FileName ?? string.Empty;
            }
            catch (Exception ex)
            {
                // Access denied or process exited
                Debug.WriteLine($"Could not read MainModule for pid {p.Id}: {ex.Message}");
                info.Path = string.Empty;
            }

            try
            {
                info.MemoryKb = p.WorkingSet64 / 1024;
            }
            catch { info.MemoryKb = 0; }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"Error reading basic info for pid {p.Id}: {ex.Message}");
        }

        if (!string.IsNullOrEmpty(info.Path))
        {
            // Compute hash with cancellation support
            info.Hash = await ComputeHashAsync(info.Path, cancellationToken);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    (info.IsSigned, info.Publisher) = GetWindowsSignatureInfo(info.Path);
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"GetWindowsSignatureInfo failed for '{info.Path}': {ex.Message}");
                    info.IsSigned = false;
                    info.Publisher = string.Empty;
                }
            }
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
