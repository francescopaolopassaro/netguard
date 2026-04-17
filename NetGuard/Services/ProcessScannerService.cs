using NetGuard.Models;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Threading;
using System.Text;
using System.IO;
using System.Collections.Concurrent;

namespace NetGuard.Services;

/// <summary>
/// Enumerates running processes, resolves their executable paths
/// and computes SHA-256 hashes for threat-intel lookups.
/// On Windows also reads digital signature publisher.
/// </summary>
public class ProcessScannerService
{
    private readonly Dictionary<string, string> _hashCache = new();
    private SemaphoreSlim _semaphore;

    private readonly string _diagLog = Path.Combine(Path.GetTempPath(), "NetGuard_process_scan.log");

    // Configurable thresholds (defaulted, updated from AppSettings in ctor)
    private int _perOperationTimeoutMs = 8000;
    private long _maxHashFileSizeBytes = 50 * 1024 * 1024;
    private int _maxErrors = 50;

    // Deduplication of heavy operations across processes
    private readonly ConcurrentDictionary<string, Task<string>> _hashTasks = new();
    private readonly ConcurrentDictionary<string, Task<(bool, string)>> _sigTasks = new();

    // Scan result summary
    public bool LastScanCancelled { get; private set; }
    public int LastScanErrorCount { get; private set; }

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

    public ProcessScannerService(AppSettings settings)
    {
        // Apply settings with safe fallbacks
        try
        {
            _perOperationTimeoutMs = Math.Max(1000, settings.ScannerPerOperationTimeoutMs);
            _maxHashFileSizeBytes = Math.Max(1, settings.ScannerMaxHashFileSizeBytes);
            _maxErrors = Math.Max(1, settings.ScannerMaxErrors);
            var concurrency = Math.Clamp(settings.ScannerMaxConcurrency, 1, Math.Max(1, Environment.ProcessorCount));
            _semaphore = new SemaphoreSlim(concurrency, concurrency);
        }
        catch
        {
            _perOperationTimeoutMs = 8000;
            _maxHashFileSizeBytes = 50 * 1024 * 1024;
            _maxErrors = 50;
            _semaphore = new SemaphoreSlim(Math.Min(4, Math.Max(2, Environment.ProcessorCount)));
        }
    }

    // ── Public API ────────────────────────────────────────────

    public async Task<List<ProcessInfo>> GetProcessesAsync(CancellationToken cancellationToken = default)
    {
        LastScanCancelled = false;
        LastScanErrorCount = 0;

        var result = new List<ProcessInfo>();

        Process[] procs;
        try
        {
            procs = Process.GetProcesses();
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"GetProcesses failed: {ex}");
            File.AppendAllText(_diagLog, $"{DateTime.Now:O} GetProcesses failed: {ex}\n");
            return result;
        }

        // Per-scan error counter and threshold
        int errorCount = 0;

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var ct = linkedCts.Token;

        void ReportError()
        {
            var v = Interlocked.Increment(ref errorCount);
            if (v > _maxErrors)
            {
                Debug.WriteLine($"Process scan: too many errors ({v}), cancelling scan");
                try { linkedCts.Cancel(); } catch { }
                try { File.AppendAllText(_diagLog, $"{DateTime.Now:O} Too many errors ({v}), cancelling scan\n"); } catch { }
            }
        }

        var tasks = new List<Task<ProcessInfo?>>();

        foreach (var p in procs)
        {
            var proc = p; // capture
            tasks.Add(Task.Run(async () =>
            {
                try
                {
                    // Wait for a slot; use the global cancellation token only here so waiting is not cancelled by short timeouts
                    await _semaphore.WaitAsync(ct);
                    if (ct.IsCancellationRequested) return null;

                    // Build info; BuildProcessInfoSafeAsync will call ReportError only for fatal/unexpected errors
                    return await BuildProcessInfoSafeAsync(proc, ct, ReportError);
                }
                catch (OperationCanceledException)
                {
                    Debug.WriteLine($"Scan for pid {proc.Id} cancelled.");
                    try { File.AppendAllText(_diagLog, $"{DateTime.Now:O} Scan for pid {proc.Id} cancelled.\n"); } catch { }
                    return null;
                }
                catch (Exception ex)
                {
                    // Unexpected fatal error -> count it
                    Debug.WriteLine($"Fatal error scanning process {proc.Id}: {ex}");
                    try { File.AppendAllText(_diagLog, $"{DateTime.Now:O} Fatal scanning pid {proc.Id}: {ex}\n"); } catch { }
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
            try { File.AppendAllText(_diagLog, $"{DateTime.Now:O} Process scan cancelled; returning partial results.\n"); } catch { }
            LastScanCancelled = true;
        }

        result.AddRange(infos.Where(i => i != null)!.Cast<ProcessInfo>());

        // store final error count
        LastScanErrorCount = errorCount;

        return result.OrderBy(p => p.Name).ToList();
    }

    // Deduplicated hash compute with timeout
    private Task<string> ComputeHashDedupedAsync(string path, CancellationToken ct)
    {
        return _hashTasks.GetOrAdd(path, pkey => Task.Run(async () =>
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(_perOperationTimeoutMs);
                var res = await ComputeHashAsync(path, cts.Token, null);
                return res ?? string.Empty;
            }
            catch (OperationCanceledException)
            {
                Debug.WriteLine($"ComputeHash timed out for {path}");
                try { File.AppendAllText(_diagLog, $"{DateTime.Now:O} ComputeHash timed out for {path}\n"); } catch { }
                return string.Empty;
            }
            finally
            {
                _hashTasks.TryRemove(path, out _);
            }
        }));
    }

    // Deduplicated signature extraction with timeout
    private Task<(bool, string)> ComputeSignatureDedupedAsync(string path, CancellationToken ct)
    {
        return _sigTasks.GetOrAdd(path, pkey => Task.Run(async () =>
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(_perOperationTimeoutMs);
                try
                {
                    var fi = new FileInfo(path);
                    if (fi.Exists && fi.Length > _maxHashFileSizeBytes)
                    {
                        return (false, string.Empty);
                    }
                }
                catch { }

                var sig = await Task.Run(() => GetWindowsSignatureInfo(path));
                return sig;
            }
            catch (OperationCanceledException)
            {
                Debug.WriteLine($"Signature extraction timed out for {path}");
                try { File.AppendAllText(_diagLog, $"{DateTime.Now:O} Signature extraction timed out for {path}\n"); } catch { }
                return (false, string.Empty);
            }
            finally
            {
                _sigTasks.TryRemove(path, out _);
            }
        }));
    }

    // Original ComputeHash (kept mostly unchanged) used by dedup wrapper
    public async Task<string> ComputeHashAsync(string path, CancellationToken cancellationToken = default, Action? onError = null)
    {
        if (string.IsNullOrEmpty(path)) return "";
        if (_hashCache.TryGetValue(path, out var cached)) return cached;

        try
        {
            // Skip hashing extremely large files to avoid long blocking
            try
            {
                var fi = new FileInfo(path);
                if (fi.Exists && fi.Length > _maxHashFileSizeBytes)
                {
                    Debug.WriteLine($"Skipping hash for large file: {path} ({fi.Length} bytes)");
                    try { File.AppendAllText(_diagLog, $"{DateTime.Now:O} Skipping hash for large file: {path} ({fi.Length})\n"); } catch { }
                    return string.Empty;
                }
            }
            catch { /* ignore file info errors and try hashing */ }

            await using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var sha = SHA256.Create();
            // Compute hash on thread pool to avoid blocking caller thread
            var hashBytes = await Task.Run(() => sha.ComputeHash(fs));
            var hash = Convert.ToHexString(hashBytes).ToLowerInvariant();
            _hashCache[path] = hash;
            return hash;
        }
        catch (OperationCanceledException) { return ""; }
        catch (CryptographicException cex)
        {
            Debug.WriteLine($"ComputeHash cryptographic error for '{path}': {cex.Message}");
            try { File.AppendAllText(_diagLog, $"{DateTime.Now:O} ComputeHash cryptographic error for '{path}': {cex.Message}\n"); } catch { }
            try { onError?.Invoke(); } catch { }
            return "";
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"ComputeHash failed for '{path}': {ex.Message}");
            try { File.AppendAllText(_diagLog, $"{DateTime.Now:O} ComputeHash failed for '{path}': {ex.Message}\n"); } catch { }
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
            try { File.AppendAllText(_diagLog, $"{DateTime.Now:O} Error reading basic info for pid {p.Id}: {ex}\n"); } catch { }
            onError?.Invoke();
        }

        if (!string.IsNullOrEmpty(info.Path))
        {
            // Deduplicated compute hash with timeout
            info.Hash = await ComputeHashDedupedAsync(info.Path, cancellationToken);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                try
                {
                    // Use deduped signature extraction with timeout
                    var sig = await ComputeSignatureDedupedAsync(info.Path, cancellationToken);
                    info.IsSigned = sig.Item1;
                    info.Publisher = sig.Item2 ?? string.Empty;
                }
                catch (Exception exSig)
                {
                    Debug.WriteLine($"Signature extraction failed for '{info.Path}': {exSig.Message}");
                    try { File.AppendAllText(_diagLog, $"{DateTime.Now:O} Signature extraction failed for '{info.Path}': {exSig.Message}\n"); } catch { }
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
