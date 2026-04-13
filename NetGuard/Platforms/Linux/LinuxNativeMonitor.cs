#if !WINDOWS
using System.Diagnostics;

namespace NetGuard.Platforms.Linux;

/// <summary>
/// Linux-only helpers: parses /proc filesystem for process and
/// network information with no external dependencies.
/// For privileged monitoring (eBPF, audit), see integration notes below.
/// </summary>
public static class LinuxNativeMonitor
{
    // ── /proc filesystem readers ──────────────────────────────

    /// <summary>
    /// Reads /proc/[pid]/status for a quick process snapshot.
    /// More reliable than System.Diagnostics.Process on some distros.
    /// </summary>
    public static ProcStatus? ReadProcStatus(int pid)
    {
        var path = $"/proc/{pid}/status";
        if (!File.Exists(path)) return null;

        try
        {
            var lines = File.ReadAllLines(path);
            var dict  = lines
                .Where(l => l.Contains(':'))
                .ToDictionary(
                    l => l[..l.IndexOf(':')].Trim(),
                    l => l[(l.IndexOf(':') + 1)..].Trim());

            return new ProcStatus
            {
                Pid  = pid,
                Name = dict.GetValueOrDefault("Name",   ""),
                State= dict.GetValueOrDefault("State",  ""),
                VmRss= ParseKb(dict.GetValueOrDefault("VmRSS", "0 kB")),
                Uid  = ParseFirstInt(dict.GetValueOrDefault("Uid", "0")),
                Ppid = ParseFirstInt(dict.GetValueOrDefault("PPid","0"))
            };
        }
        catch { return null; }
    }

    /// <summary>Returns the executable path from /proc/[pid]/exe symlink.</summary>
    public static string GetExePath(int pid)
    {
        try { return new FileInfo($"/proc/{pid}/exe").LinkTarget ?? ""; }
        catch { return ""; }
    }

    /// <summary>
    /// Returns all open file descriptors for a process as symlink targets.
    /// Used to detect processes with suspicious open sockets.
    /// </summary>
    public static List<string> GetOpenFds(int pid)
    {
        var result = new List<string>();
        var fdDir  = $"/proc/{pid}/fd";
        if (!Directory.Exists(fdDir)) return result;
        try
        {
            foreach (var fd in Directory.GetFiles(fdDir))
            {
                var target = new FileInfo(fd).LinkTarget ?? "";
                if (!string.IsNullOrEmpty(target)) result.Add(target);
            }
        }
        catch { /* permission denied */ }
        return result;
    }

    /// <summary>
    /// Reads /proc/net/tcp and /proc/net/tcp6 and returns a summary
    /// count of ESTABLISHED connections per process.
    /// </summary>
    public static Dictionary<int, int> GetEstablishedCountByPid()
    {
        var counts     = new Dictionary<int, int>();
        var inodePids  = BuildInodeToPidMap();

        foreach (var file in new[]{ "/proc/net/tcp", "/proc/net/tcp6" })
        {
            if (!File.Exists(file)) continue;
            foreach (var line in File.ReadAllLines(file).Skip(1))
            {
                var parts = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 10) continue;
                if (parts[3] != "01") continue; // 01 = ESTABLISHED
                var inode = parts[9];
                if (inodePids.TryGetValue(inode, out var pid))
                    counts[pid] = counts.GetValueOrDefault(pid, 0) + 1;
            }
        }
        return counts;
    }

    // ── eBPF / audit integration points ─────────────────────
    // For real-time kernel-level monitoring (new process execve, socket
    // connect syscalls) on Linux the recommended approaches are:
    //
    //   1. auditd rules + parsing /var/log/audit/audit.log
    //      Requires: libaudit, auditd running, root
    //      Rule example: auditctl -a always,exit -F arch=b64 -S execve
    //
    //   2. BCC/eBPF (bpftrace or libbpf)
    //      Requires: Linux ≥ 5.8, CAP_BPF or root
    //      Trace syscalls: execve, connect, bind with PID context
    //
    //   3. inotifywait on /proc to detect new PID directories
    //      No root required, lower fidelity
    //
    // NetGuard uses polled /proc scanning for zero-dependency operation.
    // An optional integration class per approach can be added here.

    /// <summary>
    /// Watches /proc using a polling loop to detect new processes.
    /// No root required; detects processes within ~1 scan interval.
    /// </summary>
    public static async IAsyncEnumerable<int> WatchNewProcessesAsync(
        TimeSpan interval,
        CancellationToken ct)
    {
        var known = new HashSet<int>(GetAllPids());
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(interval, ct);
            var current = GetAllPids();
            foreach (var pid in current.Except(known))
            {
                known.Add(pid);
                yield return pid;
            }
            // Clean up exited PIDs
            known.IntersectWith(current);
        }
    }

    public static List<int> GetAllPids()
        => Directory.GetDirectories("/proc")
            .Select(d => Path.GetFileName(d))
            .Where(n => int.TryParse(n, out _))
            .Select(int.Parse)
            .ToList();

    // ── cgroups v2: CPU/memory limits ────────────────────────
    public static (long CpuShares, long MemLimitBytes) ReadCgroups(int pid)
    {
        var cgroupFile = $"/proc/{pid}/cgroup";
        if (!File.Exists(cgroupFile)) return (0, 0);
        try
        {
            // Read the cgroup path then look up cpu/memory controllers
            var lines  = File.ReadAllLines(cgroupFile);
            var cgPath = lines.FirstOrDefault(l => l.Contains("::"))?.Split("::")[1].Trim() ?? "";
            var cgRoot = $"/sys/fs/cgroup{cgPath}";

            var cpu = ReadLongFile(Path.Combine(cgRoot, "cpu.shares"));
            var mem = ReadLongFile(Path.Combine(cgRoot, "memory.max"));
            return (cpu, mem);
        }
        catch { return (0, 0); }
    }

    // ── Helpers ───────────────────────────────────────────────
    private static Dictionary<string, int> BuildInodeToPidMap()
    {
        var map = new Dictionary<string, int>();
        foreach (var pidDir in Directory.GetDirectories("/proc")
            .Where(d => int.TryParse(Path.GetFileName(d), out _)))
        {
            var pid   = int.Parse(Path.GetFileName(pidDir));
            var fdDir = $"{pidDir}/fd";
            if (!Directory.Exists(fdDir)) continue;
            try
            {
                foreach (var fd in Directory.GetFiles(fdDir))
                {
                    var target = new FileInfo(fd).LinkTarget ?? "";
                    var m      = System.Text.RegularExpressions.Regex.Match(target, @"socket:\[(\d+)\]");
                    if (m.Success) map[m.Groups[1].Value] = pid;
                }
            }
            catch { }
        }
        return map;
    }

    private static long ParseKb(string s)
    {
        var parts = s.Split(' ');
        return long.TryParse(parts[0], out var v) ? v : 0;
    }

    private static int ParseFirstInt(string s)
    {
        var parts = s.Split('\t', ' ');
        return int.TryParse(parts[0], out var v) ? v : 0;
    }

    private static long ReadLongFile(string path)
    {
        if (!File.Exists(path)) return 0;
        var text = File.ReadAllText(path).Trim();
        return text == "max" ? long.MaxValue : long.TryParse(text, out var v) ? v : 0;
    }
}

public class ProcStatus
{
    public int    Pid   { get; set; }
    public string Name  { get; set; } = "";
    public string State { get; set; } = "";
    public long   VmRss { get; set; }  // KB
    public int    Uid   { get; set; }
    public int    Ppid  { get; set; }
}
#endif
