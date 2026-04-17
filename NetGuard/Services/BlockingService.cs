using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using NetGuard.Models;

namespace NetGuard.Services;

/// <summary>
/// Actually blocks threats:
///   Processes → Kill + optional firewall rule
///   Domains   → /etc/hosts or Windows hosts file
///   IPs       → iptables (Linux) / netsh (Windows)
/// </summary>
public class BlockingService
{
    private const string HostsPath_Windows = @"C:\Windows\System32\drivers\etc\hosts";
    private const string HostsPath_Linux   = "/etc/hosts";
    private const string BlockMarker       = "# NetGuard block";

    private readonly HashSet<string> _blockedIps      = new();
    private readonly HashSet<string> _blockedDomains  = new();
    private readonly HashSet<int>    _blockedPids     = new();

    public event Action<string, BlockAction>? Blocked;

    // ── Process ───────────────────────────────────────────────────────────

    public async Task<bool> BlockProcessAsync(ProcessEntry proc, ProcessService svc)
    {
        if (_blockedPids.Contains(proc.Pid)) return true;

        // 1. Kill the process
        var (killed, err) = svc.KillProcess(proc.Pid);
        if (!killed)
        {
            Debug.WriteLine($"[Block] Kill failed for {proc.Name}: {err}");
        }

        // 2. Add firewall outbound block for the executable
        if (!string.IsNullOrEmpty(proc.Path))
        {
            await AddFirewallBlockAsync(proc.Path, proc.Name);
        }

        _blockedPids.Add(proc.Pid);
        Blocked?.Invoke(proc.Name, BlockAction.Killed);
        return killed;
    }

    // ── Domain (hosts file) ───────────────────────────────────────────────

    public async Task<bool> BlockDomainAsync(string domain)
    {
        if (_blockedDomains.Contains(domain)) return true;

        var hostsPath = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? HostsPath_Windows : HostsPath_Linux;

        try
        {
            var entry = $"127.0.0.1 {domain} {BlockMarker}";
            var www   = $"127.0.0.1 www.{domain} {BlockMarker}";

            var lines = File.Exists(hostsPath)
                ? (await File.ReadAllLinesAsync(hostsPath)).ToList()
                : new List<string>();

            bool changed = false;
            if (!lines.Any(l => l.Contains(domain)))
            {
                lines.Add(entry);
                if (!domain.StartsWith("www.")) lines.Add(www);
                changed = true;
            }

            if (changed)
            {
                await File.WriteAllLinesAsync(hostsPath, lines, Encoding.UTF8);
                await FlushDnsCacheAsync();
            }

            _blockedDomains.Add(domain);
            Blocked?.Invoke(domain, BlockAction.DnsBlocked);
            return true;
        }
        catch (UnauthorizedAccessException)
        {
            // Try with elevated write on Windows
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return await BlockDomainElevatedWindowsAsync(domain);
            Debug.WriteLine("[Block] Need root to write /etc/hosts");
            return false;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[Block] hosts error: {ex.Message}");
            return false;
        }
    }

    // ── IP (firewall) ─────────────────────────────────────────────────────

    public async Task<bool> BlockIpAsync(string ip)
    {
        if (_blockedIps.Contains(ip)) return true;

        try
        {
            bool ok;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                ok = await BlockIpWindowsAsync(ip);
            else
                ok = await BlockIpLinuxAsync(ip);

            if (ok)
            {
                _blockedIps.Add(ip);
                Blocked?.Invoke(ip, BlockAction.FirewallBlocked);
            }
            return ok;
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[Block] IP block error: {ex.Message}");
            return false;
        }
    }

    // ── Unblock ───────────────────────────────────────────────────────────

    public async Task UnblockDomainAsync(string domain)
    {
        var hostsPath = RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? HostsPath_Windows : HostsPath_Linux;
        try
        {
            if (!File.Exists(hostsPath)) return;
            var lines = (await File.ReadAllLinesAsync(hostsPath))
                .Where(l => !l.Contains(domain))
                .ToList();
            await File.WriteAllLinesAsync(hostsPath, lines);
            await FlushDnsCacheAsync();
            _blockedDomains.Remove(domain);
        }
        catch { }
    }

    public async Task UnblockIpAsync(string ip)
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                await RunAsync("netsh", $"advfirewall firewall delete rule name=\"NetGuard_BLOCK_{ip}\"");
            else
                await RunAsync("iptables", $"-D OUTPUT -d {ip} -j DROP");
            _blockedIps.Remove(ip);
        }
        catch { }
    }

    // ── Lists ─────────────────────────────────────────────────────────────

    public IReadOnlySet<string> BlockedDomains => _blockedDomains;
    public IReadOnlySet<string> BlockedIps     => _blockedIps;
    public bool IsDomainBlocked(string d)      => _blockedDomains.Contains(d);
    public bool IsIpBlocked(string ip)         => _blockedIps.Contains(ip);

    // ── Platform: Windows ─────────────────────────────────────────────────

    private async Task AddFirewallBlockAsync(string exePath, string name)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;
        try
        {
            var ruleName = $"NetGuard_BLOCK_{name.Replace(" ", "_")}";
            await RunAsync("netsh",
                $"advfirewall firewall add rule name=\"{ruleName}\" " +
                $"dir=out action=block program=\"{exePath}\" enable=yes");
        }
        catch { }
    }

    private async Task<bool> BlockIpWindowsAsync(string ip)
    {
        var ruleName = $"NetGuard_BLOCK_{ip}";
        var result = await RunAsync("netsh",
            $"advfirewall firewall add rule name=\"{ruleName}\" " +
            $"dir=out action=block remoteip={ip} enable=yes");
        return result.ExitCode == 0;
    }

    private async Task<bool> BlockDomainElevatedWindowsAsync(string domain)
    {
        try
        {
            // Use PowerShell to append with elevation
            var cmd = $"Add-Content -Path '{HostsPath_Windows}' " +
                      $"-Value '127.0.0.1 {domain} {BlockMarker}'";
            var result = await RunAsync("powershell",
                $"-NonInteractive -Command \"{cmd}\"");
            return result.ExitCode == 0;
        }
        catch { return false; }
    }

    // ── Platform: Linux ───────────────────────────────────────────────────

    private async Task<bool> BlockIpLinuxAsync(string ip)
    {
        // Try iptables first, then nftables
        var iptResult = await RunAsync("iptables",
            $"-A OUTPUT -d {ip} -j DROP");
        if (iptResult.ExitCode == 0) return true;

        var nftResult = await RunAsync("nft",
            $"add rule ip filter output ip daddr {ip} drop");
        return nftResult.ExitCode == 0;
    }

    // ── DNS cache flush ───────────────────────────────────────────────────

    private static async Task FlushDnsCacheAsync()
    {
        try
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                await RunAsync("ipconfig", "/flushdns");
            else
            {
                // Try multiple Linux DNS cache managers
                await RunAsync("systemd-resolve", "--flush-caches");
                await RunAsync("resolvectl", "flush-caches");
            }
        }
        catch { }
    }

    // ── Shared runner ─────────────────────────────────────────────────────

    private static async Task<(int ExitCode, string Output)> RunAsync(string cmd, string args)
    {
        try
        {
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo(cmd, args)
                {
                    UseShellExecute        = false,
                    CreateNoWindow         = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError  = true
                }
            };
            proc.Start();
            var output = await proc.StandardOutput.ReadToEndAsync();
            await proc.WaitForExitAsync();
            return (proc.ExitCode, output);
        }
        catch { return (-1, ""); }
    }
}
