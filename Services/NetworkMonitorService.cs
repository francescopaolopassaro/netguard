using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using NetGuard.Models;

namespace NetGuard.Services;

/// <summary>
/// Enumerates active TCP/UDP connections.
/// Windows: uses netstat -b (with elevation) or IPGlobalProperties.
/// Linux:   parses /proc/net/tcp, /proc/net/tcp6, /proc/net/udp.
/// </summary>
public class NetworkMonitorService
{
    private readonly Dictionary<string, string> _reverseDnsCache = new();
    private readonly SemaphoreSlim _dnsLock = new(1, 1);

    // ── Public API ────────────────────────────────────────────
    public async Task<List<NetworkConnection>> GetConnectionsAsync()
    {
        return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? await GetConnectionsWindowsAsync()
            : await GetConnectionsLinuxAsync();
    }

    // ── Windows ───────────────────────────────────────────────
    private async Task<List<NetworkConnection>> GetConnectionsWindowsAsync()
    {
        var connections = new List<NetworkConnection>();
        try
        {
            // IPGlobalProperties gives us TCP connections without elevation
            var props = IPGlobalProperties.GetIPGlobalProperties();
            var tcpConns = props.GetActiveTcpConnections();
            var listeners = props.GetActiveTcpListeners();

            // Build PID→ProcessName map via netstat -b output (best-effort, needs elevation)
            var pidMap = await GetWindowsPidMapAsync();

            foreach (var c in tcpConns)
            {
                var conn = new NetworkConnection
                {
                    Protocol      = "TCP",
                    LocalAddress  = c.LocalEndPoint.Address.ToString(),
                    LocalPort     = c.LocalEndPoint.Port,
                    RemoteAddress = c.RemoteEndPoint.Address.ToString(),
                    RemotePort    = c.RemoteEndPoint.Port,
                    State         = c.State.ToString()
                };
                if (pidMap.TryGetValue($"{conn.LocalAddress}:{conn.LocalPort}", out var pid))
                {
                    conn.ProcessId   = pid.Id;
                    conn.ProcessName = pid.Name;
                }
                conn.Domain = await ReverseDnsAsync(conn.RemoteAddress);
                connections.Add(conn);
            }

            // UDP listeners (no state)
            foreach (var u in props.GetActiveUdpListeners())
                connections.Add(new NetworkConnection
                {
                    Protocol     = "UDP",
                    LocalAddress = u.Address.ToString(),
                    LocalPort    = u.Port,
                    State        = "LISTEN"
                });
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[NetworkMonitor] Windows error: {ex.Message}");
        }
        return connections;
    }

    private static async Task<Dictionary<string, (int Id, string Name)>> GetWindowsPidMapAsync()
    {
        var map = new Dictionary<string, (int, string)>();
        try
        {
            // netstat -ano gives us PID column, no elevation needed
            var output = await RunCommandAsync("netstat", "-ano");
            foreach (var line in output.Split('\n'))
            {
                // TCP    0.0.0.0:135    0.0.0.0:0    LISTENING    1234
                var parts = line.Trim().Split(new[]{' ', '\t'}, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 5) continue;
                if (!int.TryParse(parts[^1], out var pid)) continue;
                var local = parts[1];
                try
                {
                    var p = Process.GetProcessById(pid);
                    map[local] = (pid, p.ProcessName);
                }
                catch { /* process may have exited */ }
            }
        }
        catch (Exception ex) { Debug.WriteLine($"[PidMap] {ex.Message}"); }
        return map;
    }

    // ── Linux ─────────────────────────────────────────────────
    private async Task<List<NetworkConnection>> GetConnectionsLinuxAsync()
    {
        var connections = new List<NetworkConnection>();
        try
        {
            var inodePidMap = BuildInodePidMap();

            foreach (var (proto, path) in new[]
            {
                ("TCP",  "/proc/net/tcp"),
                ("TCP6", "/proc/net/tcp6"),
                ("UDP",  "/proc/net/udp"),
                ("UDP6", "/proc/net/udp6")
            })
            {
                if (!File.Exists(path)) continue;
                var lines = await File.ReadAllLinesAsync(path);
                foreach (var line in lines.Skip(1)) // skip header
                {
                    var conn = ParseProcNetLine(line, proto, inodePidMap);
                    if (conn != null)
                    {
                        conn.Domain = await ReverseDnsAsync(conn.RemoteAddress);
                        connections.Add(conn);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Debug.WriteLine($"[NetworkMonitor] Linux error: {ex.Message}");
        }
        return connections;
    }

    /// <summary>
    /// Parses a line from /proc/net/tcp or /proc/net/udp.
    /// Format: sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt uid timeout inode
    /// </summary>
    private static NetworkConnection? ParseProcNetLine(
        string line, string proto, Dictionary<string, (int Pid, string Name)> inodePidMap)
    {
        var parts = line.Trim().Split(new[]{' ', '\t'}, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 10) return null;

        var local  = ParseHexEndpoint(parts[1]);
        var remote = ParseHexEndpoint(parts[2]);
        if (local == null || remote == null) return null;

        var stateHex = parts[3];
        var state    = stateHex switch
        {
            "01" => "ESTABLISHED", "02" => "SYN_SENT",  "03" => "SYN_RECV",
            "04" => "FIN_WAIT1",   "05" => "FIN_WAIT2", "06" => "TIME_WAIT",
            "07" => "CLOSE",       "08" => "CLOSE_WAIT","09" => "LAST_ACK",
            "0A" => "LISTEN",      "0B" => "CLOSING",   _   => stateHex
        };

        var inode = parts[9];
        inodePidMap.TryGetValue(inode, out var proc);

        return new NetworkConnection
        {
            Protocol      = proto,
            LocalAddress  = local.Value.Address.ToString(),
            LocalPort     = local.Value.Port,
            RemoteAddress = remote.Value.Address.ToString(),
            RemotePort    = remote.Value.Port,
            State         = state,
            ProcessId     = proc.Pid,
            ProcessName   = proc.Name ?? ""
        };
    }

    private static IPEndPoint? ParseHexEndpoint(string hex)
    {
        // "0101007F:0035"  (little-endian hex IP : hex port)
        var colonIdx = hex.IndexOf(':');
        if (colonIdx < 0) return null;
        var hexIp   = hex[..colonIdx];
        var hexPort = hex[(colonIdx + 1)..];
        if (!uint.TryParse(hexIp,   System.Globalization.NumberStyles.HexNumber, null, out var ip))   return null;
        if (!ushort.TryParse(hexPort, System.Globalization.NumberStyles.HexNumber, null, out var port)) return null;

        // Reverse bytes for little-endian
        var ipBytes = BitConverter.GetBytes(ip);
        var ipAddr  = new IPAddress(ipBytes);
        return new IPEndPoint(ipAddr, port);
    }

    /// <summary>
    /// Builds inode → PID map by scanning /proc/[pid]/fd symlinks.
    /// </summary>
    private static Dictionary<string, (int Pid, string Name)> BuildInodePidMap()
    {
        var map = new Dictionary<string, (int, string)>();
        try
        {
            foreach (var pidDir in Directory.GetDirectories("/proc").Where(d =>
                int.TryParse(Path.GetFileName(d), out _)))
            {
                var pid  = int.Parse(Path.GetFileName(pidDir));
                var name = "";
                try
                {
                    var commPath = Path.Combine(pidDir, "comm");
                    if (File.Exists(commPath)) name = File.ReadAllText(commPath).Trim();
                }
                catch { }

                var fdDir = Path.Combine(pidDir, "fd");
                if (!Directory.Exists(fdDir)) continue;
                try
                {
                    foreach (var fd in Directory.GetFiles(fdDir))
                    {
                        var target = new FileInfo(fd).LinkTarget ?? "";
                        // "socket:[12345]"
                        var m = Regex.Match(target, @"socket:\[(\d+)\]");
                        if (m.Success)
                            map[m.Groups[1].Value] = (pid, name);
                    }
                }
                catch { /* permission denied for some PIDs */ }
            }
        }
        catch { }
        return map;
    }

    // ── Reverse DNS (cached) ──────────────────────────────────
    private async Task<string> ReverseDnsAsync(string ip)
    {
        if (ip is "0.0.0.0" or "::" or "127.0.0.1" or "::1") return "";
        if (_reverseDnsCache.TryGetValue(ip, out var cached)) return cached;

        await _dnsLock.WaitAsync();
        try
        {
            if (_reverseDnsCache.TryGetValue(ip, out cached)) return cached;
            try
            {
                var entry = await Dns.GetHostEntryAsync(ip)
                    .WaitAsync(TimeSpan.FromSeconds(2));
                var host = entry.HostName;
                _reverseDnsCache[ip] = host;
                return host;
            }
            catch
            {
                _reverseDnsCache[ip] = "";
                return "";
            }
        }
        finally { _dnsLock.Release(); }
    }

    // ── Helpers ───────────────────────────────────────────────
    private static async Task<string> RunCommandAsync(string cmd, string args)
    {
        using var proc = new Process
        {
            StartInfo = new ProcessStartInfo(cmd, args)
            {
                RedirectStandardOutput = true,
                UseShellExecute        = false,
                CreateNoWindow         = true
            }
        };
        proc.Start();
        var output = await proc.StandardOutput.ReadToEndAsync();
        await proc.WaitForExitAsync();
        return output;
    }
}
