using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using NetGuard.Models;

namespace NetGuard.Services;

public class NetworkService
{
    private readonly Dictionary<string, string> _dnsCache = new();
    private readonly SemaphoreSlim _dnsLock = new(1, 1);

    public async Task<List<NetConnection>> GetConnectionsAsync()
    {
        return RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            ? await GetWindowsConnectionsAsync()
            : await GetLinuxConnectionsAsync();
    }

    // ── Windows ───────────────────────────────────────────────────────────

    private async Task<List<NetConnection>> GetWindowsConnectionsAsync()
    {
        var conns = new List<NetConnection>();
        try
        {
            // Build PID map from netstat (works without elevation for most)
            var pidMap = await BuildWindowsPidMapAsync();

            var props  = IPGlobalProperties.GetIPGlobalProperties();

            foreach (var c in props.GetActiveTcpConnections())
            {
                if (c.RemoteEndPoint.Address.Equals(IPAddress.Any)) continue;
                var local  = c.LocalEndPoint;
                var remote = c.RemoteEndPoint;
                var key    = $"{local.Address}:{local.Port}";
                pidMap.TryGetValue(key, out var proc);

                var conn = new NetConnection
                {
                    Protocol      = "TCP",
                    LocalAddress  = local.Address.ToString(),
                    LocalPort     = local.Port,
                    RemoteAddress = remote.Address.ToString(),
                    RemotePort    = remote.Port,
                    State         = c.State.ToString(),
                    Pid           = proc.Pid,
                    ProcessName   = proc.Name
                };
                conn.Domain = await ReverseDnsAsync(conn.RemoteAddress);
                conns.Add(conn);
            }

            foreach (var u in props.GetActiveUdpListeners())
                conns.Add(new NetConnection
                {
                    Protocol     = "UDP",
                    LocalAddress = u.Address.ToString(),
                    LocalPort    = u.Port,
                    State        = "LISTEN"
                });
        }
        catch (Exception ex) { Debug.WriteLine($"[Net-Win] {ex.Message}"); }
        return conns;
    }

    private async Task<Dictionary<string, (int Pid, string Name)>> BuildWindowsPidMapAsync()
    {
        var map = new Dictionary<string, (int, string)>();
        try
        {
            // netstat -ano: no elevation required
            using var proc = new Process
            {
                StartInfo = new ProcessStartInfo("netstat", "-ano")
                {
                    UseShellExecute        = false,
                    RedirectStandardOutput = true,
                    CreateNoWindow         = true
                }
            };
            proc.Start();
            var lines = (await proc.StandardOutput.ReadToEndAsync()).Split('\n');
            await proc.WaitForExitAsync();

            foreach (var line in lines)
            {
                var parts = line.Trim().Split(new[]{ ' ', '\t' },
                    StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 5) continue;
                if (!int.TryParse(parts[^1], out var pid)) continue;
                var local = parts[1];
                try
                {
                    var p = Process.GetProcessById(pid);
                    map[local] = (pid, p.ProcessName);
                    p.Dispose();
                }
                catch { }
            }
        }
        catch { }
        return map;
    }

    // ── Linux /proc/net ───────────────────────────────────────────────────

    private async Task<List<NetConnection>> GetLinuxConnectionsAsync()
    {
        var conns     = new List<NetConnection>();
        var inodePids = BuildLinuxInodeMap();

        foreach (var (proto, path) in new[]
        {
            ("TCP",  "/proc/net/tcp"),
            ("TCP6", "/proc/net/tcp6"),
            ("UDP",  "/proc/net/udp"),
            ("UDP6", "/proc/net/udp6"),
        })
        {
            if (!File.Exists(path)) continue;
            var lines = await File.ReadAllLinesAsync(path);
            foreach (var line in lines.Skip(1))
            {
                var conn = ParseProcNetLine(line, proto, inodePids);
                if (conn == null) continue;
                conn.Domain = await ReverseDnsAsync(conn.RemoteAddress);
                conns.Add(conn);
            }
        }
        return conns;
    }

    private static NetConnection? ParseProcNetLine(
        string line, string proto,
        Dictionary<string, (int Pid, string Name)> inodePids)
    {
        var parts = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 10) return null;

        var local  = ParseLinuxEndpoint(parts[1]);
        var remote = ParseLinuxEndpoint(parts[2]);
        if (local == null || remote == null) return null;

        // Skip 0.0.0.0:0 remote (unconnected)
        if (remote.Address.Equals(IPAddress.Any) && remote.Port == 0) return null;

        var stateHex = parts[3].ToUpperInvariant();
        var state    = stateHex switch
        {
            "01" => "ESTABLISHED", "02" => "SYN_SENT",  "03" => "SYN_RECV",
            "04" => "FIN_WAIT1",   "05" => "FIN_WAIT2", "06" => "TIME_WAIT",
            "0A" => "LISTEN",      "08" => "CLOSE_WAIT", _   => stateHex
        };

        inodePids.TryGetValue(parts[9], out var proc);

        return new NetConnection
        {
            Protocol      = proto,
            LocalAddress  = local.Address.ToString(),
            LocalPort     = local.Port,
            RemoteAddress = remote.Address.ToString(),
            RemotePort    = remote.Port,
            State         = state,
            Pid           = proc.Pid,
            ProcessName   = proc.Name ?? ""
        };
    }

    private static IPEndPoint? ParseLinuxEndpoint(string hex)
    {
        var idx = hex.IndexOf(':');
        if (idx < 0) return null;
        if (!uint.TryParse(hex[..idx],
                System.Globalization.NumberStyles.HexNumber, null, out var ipRaw)) return null;
        if (!ushort.TryParse(hex[(idx + 1)..],
                System.Globalization.NumberStyles.HexNumber, null, out var port)) return null;
        return new IPEndPoint(new IPAddress(BitConverter.GetBytes(ipRaw)), port);
    }

    private static Dictionary<string, (int Pid, string Name)> BuildLinuxInodeMap()
    {
        var map = new Dictionary<string, (int, string)>();
        try
        {
            foreach (var pidDir in Directory.GetDirectories("/proc")
                .Where(d => int.TryParse(Path.GetFileName(d), out _)))
            {
                var pid  = int.Parse(Path.GetFileName(pidDir));
                var name = "";
                try { name = File.ReadAllText(Path.Combine(pidDir, "comm")).Trim(); } catch { }

                var fdDir = Path.Combine(pidDir, "fd");
                if (!Directory.Exists(fdDir)) continue;
                try
                {
                    foreach (var fd in Directory.GetFiles(fdDir))
                    {
                        var target = new FileInfo(fd).LinkTarget ?? "";
                        var m      = Regex.Match(target, @"socket:\[(\d+)\]");
                        if (m.Success) map[m.Groups[1].Value] = (pid, name);
                    }
                }
                catch { }
            }
        }
        catch { }
        return map;
    }

    // ── Reverse DNS ───────────────────────────────────────────────────────

    private async Task<string> ReverseDnsAsync(string ip)
    {
        if (ip is "0.0.0.0" or "::" or "127.0.0.1" or "::1") return "";
        if (!IPAddress.TryParse(ip, out var addr)) return "";

        // Skip private ranges — no useful PTR
        var bytes = addr.GetAddressBytes();
        if (bytes.Length == 4 && (
            bytes[0] == 10 ||
            bytes[0] == 127 ||
            (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) ||
            (bytes[0] == 192 && bytes[1] == 168)))
            return "";

        if (_dnsCache.TryGetValue(ip, out var cached)) return cached;
        await _dnsLock.WaitAsync();
        try
        {
            if (_dnsCache.TryGetValue(ip, out cached)) return cached;
            try
            {
                var entry = await Dns.GetHostEntryAsync(ip)
                    .WaitAsync(TimeSpan.FromSeconds(1));
                _dnsCache[ip] = entry.HostName;
                return entry.HostName;
            }
            catch { _dnsCache[ip] = ""; return ""; }
        }
        finally { _dnsLock.Release(); }
    }
}
