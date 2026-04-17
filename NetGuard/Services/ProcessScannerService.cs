using NetGuard.Models;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Threading;
using System.Text;

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

    // P/Invoke to get process image path without enumerating modules (safer than Process.MainModule)
#if WINDOWS
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool QueryFullProcessImageName(IntPtr hProcess, int dwFlags, StringBuilder lpExeName, ref int lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);
#endif

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

        // Per-scan error counter and threshold
        int errorCount = 0;
        const int maxErrors = 20;

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var ct = linkedCts.Token;

        void ReportError()
        {
            var v = Interlocked.Increment(ref errorCount);
            if (v > maxErrors)
            {
                Debug.WriteLine($"Process scan: too many errors ({v}), cancelling scan");
                try { linkedCts.Cancel(); } catch { }
            }
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
                    await _semaphore.WaitAsync(ct);
                    if (ct.IsCancellationRequested) return null;
                    return await BuildProcessInfoSafeAsync(proc, ct, ReportError);
                }
                catch (OperationCanceledException) { return null; }
                catch (Exception ex)
                {
                    Debug.WriteLine($"Error scanning process {proc.Id}: {ex}");
                    ReportError();
                    return null;
                }
                finally
                {
                    try { _semaphore.Release(); } catch { }
                    try { proc.Dispose(); } catch { }
                }
            }));
        }

        ProcessInfo?[] infos;
        try
        {
            infos = await Task.WhenAll(tasks);
        }
        catch (OperationCanceledException)
        {
            // Scan was cancelled; collect results from successfully completed tasks
            infos = tasks.Where(t => t.IsCompletedSuccessfully).Select(t => t.Result).ToArray();
            Debug.WriteLine("Process scan cancelled; returning partial results.");
        }

        result.AddRange(infos.Where(i => i != null)!.Cast<ProcessInfo>());
        return result.OrderBy(p => p.Name).ToList();
    }

    public async Task<string> ComputeHashAsync(string path, CancellationToken cancellationToken = default, Action? onError = null)
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
        catch (CryptographicException cex)
        {
            Debug.WriteLine($"ComputeHash cryptographic error for '{path}': {cex.Message}");
            try { onError?.Invoke(); } catch { }
            return "";
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"ComputeHash failed for '{path}': {ex.Message}");
            try { onError?.Invoke(); } catch { }
            return "";
        }
    }

    // ── Private ───────────────────────────────────────────────────────

    private async Task<ProcessInfo?> BuildProcessInfoSafeAsync(Process p, CancellationToken cancellationToken, Action onError)
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
                // First try safer native query to get process image path without module enumeration
#if WINDOWS
                try
                {
                    var path = TryGetProcessPathNative(p.Id);
                    if (!string.IsNullOrEmpty(path))
                    {
                        info.Path = path;
                    }
                    else
                    {
                        // Fallback to Process.MainModule (may throw Access Denied)
                        try { info.Path = p.MainModule?.FileName ?? string.Empty; } catch (Exception ex2) { Debug.WriteLine($"Could not read MainModule for pid {p.Id}: {ex2.Message}"); info.Path = string.Empty; }
                    }
                }
                catch (Exception exNative)
                {
                    Debug.WriteLine($"Native path lookup failed for pid {p.Id}: {exNative.Message}");
                    try { info.Path = p.MainModule?.FileName ?? string.Empty; } catch (Exception ex2) { Debug.WriteLine($"Could not read MainModule for pid {p.Id}: {ex2.Message}"); info.Path = string.Empty; }
                }
#else
                info.Path = p.MainModule?.FileName ?? string.Empty;
#endif
            }
            catch (Exception ex)
            {
                // Access denied or process exited
                Debug.WriteLine($"Could not read MainModule for pid {p.Id}: {ex.Message}");
                // do not count expected access-denied as an error
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
            Debug.WriteLine($"Error reading basic info for pid {p.Id}: {ex}");
            // unexpected error -> count it
            onError?.Invoke();
        }

        if (!string.IsNullOrEmpty(info.Path))
        {
            // Compute hash with cancellation support and error reporting
            info.Hash = await ComputeHashAsync(info.Path, cancellationToken, onError);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    (info.IsSigned, info.Publisher) = GetWindowsSignatureInfo(info.Path);
                }
                catch (CryptographicException cex)
                {
                    Debug.WriteLine($"GetWindowsSignatureInfo cryptographic error for '{info.Path}': {cex.Message}");
                    onError?.Invoke();
                    info.IsSigned = false;
                    info.Publisher = string.Empty;
                }
                catch (Exception ex)
                {
                    Debug.WriteLine($"GetWindowsSignatureInfo failed for '{info.Path}': {ex.Message}");
                    onError?.Invoke();
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

#if WINDOWS
    private static string TryGetProcessPathNative(int pid)
    {
        IntPtr h = IntPtr.Zero;
        try
        {
            // Try limited info first (works for many processes without full rights)
            h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (h == IntPtr.Zero)
            {
                // fallback to more permissions
                h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
                if (h == IntPtr.Zero) return string.Empty;
            }

            var sb = new StringBuilder(1024);
            int size = sb.Capacity;
            if (QueryFullProcessImageName(h, 0, sb, ref size))
            {
                return sb.ToString();
            }
            return string.Empty;
        }
        finally
        {
            try { if (h != IntPtr.Zero) CloseHandle(h); } catch { }
        }
    }
#endif

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
