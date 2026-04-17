#if !WINDOWS
using System.Text.RegularExpressions;

namespace NetGuard.Platforms.Linux;

public static class LinuxNativeMonitor
{
    // ── /proc helpers ─────────────────────────────────────────────────────

    public static string GetExePath(int pid)
    {
        try { return new FileInfo($"/proc/{pid}/exe").LinkTarget ?? ""; }
        catch { return ""; }
    }

    public static string GetComm(int pid)
    {
        try { return File.ReadAllText($"/proc/{pid}/comm").Trim(); }
        catch { return ""; }
    }

    public static string GetCmdline(int pid)
    {
        try { return File.ReadAllText($"/proc/{pid}/cmdline").Replace('\0', ' ').Trim(); }
        catch { return ""; }
    }

    public static int GetUid(int pid)
    {
        try
        {
            var line = File.ReadAllLines($"/proc/{pid}/status")
                .FirstOrDefault(l => l.StartsWith("Uid:"));
            return line == null ? -1 : int.Parse(line.Split('\t')[1].Trim());
        }
        catch { return -1; }
    }

    /// <summary>Async generator of new PIDs appearing in /proc.</summary>
    public static async IAsyncEnumerable<int> WatchNewProcessesAsync(
        TimeSpan interval, CancellationToken ct)
    {
        var known = GetAllPids().ToHashSet();
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(interval, ct).ContinueWith(_ => { });
            var current = GetAllPids();
            foreach (var pid in current.Except(known))
            {
                known.Add(pid);
                yield return pid;
            }
            known.IntersectWith(current);
        }
    }

    public static List<int> GetAllPids() =>
        Directory.GetDirectories("/proc")
            .Select(d => Path.GetFileName(d))
            .Where(n => int.TryParse(n, out _))
            .Select(int.Parse)
            .ToList();

    // ── Firewall (iptables / nftables) ────────────────────────────────────

    public static async Task<bool> DropIpAsync(string ip)
    {
        // Try iptables
        var (code, _) = await RunAsync("iptables", $"-A OUTPUT -d {ip} -j DROP");
        if (code == 0) return true;
        // Fallback to nftables
        (code, _) = await RunAsync("nft", $"add rule ip filter output ip daddr {ip} drop");
        return code == 0;
    }

    public static async Task<bool> RemoveDropIpAsync(string ip)
    {
        var (code, _) = await RunAsync("iptables", $"-D OUTPUT -d {ip} -j DROP");
        return code == 0;
    }

    // ── DNS (hosts file) ──────────────────────────────────────────────────

    public static async Task<bool> BlockDomainInHostsAsync(string domain)
    {
        const string path = "/etc/hosts";
        try
        {
            var entry = $"127.0.0.1 {domain} # NetGuard";
            var lines = File.Exists(path)
                ? (await File.ReadAllLinesAsync(path)).ToList()
                : new List<string>();
            if (lines.Any(l => l.Contains(domain))) return true;
            lines.Add(entry);
            await File.WriteAllLinesAsync(path, lines);
            await RunAsync("systemd-resolve", "--flush-caches");
            return true;
        }
        catch { return false; }
    }

    // ── Shared ────────────────────────────────────────────────────────────

    private static async Task<(int Code, string Output)> RunAsync(string cmd, string args)
    {
        try
        {
            using var proc = System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo(cmd, args)
                {
                    UseShellExecute        = false,
                    CreateNoWindow         = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true
                });
            if (proc == null) return (-1, "");
            var output = await proc.StandardOutput.ReadToEndAsync();
            await proc.WaitForExitAsync();
            return (proc.ExitCode, output);
        }
        catch { return (-1, ""); }
    }
}
#endif
