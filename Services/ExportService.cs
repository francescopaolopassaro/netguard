using System.Globalization;
using System.Text;
using NetGuard.Models;

namespace NetGuard.Services;

/// <summary>
/// Exports NetGuard data to CSV files for SIEM integration or manual review.
/// </summary>
public class ExportService
{
    private readonly DatabaseService _db;

    public ExportService(DatabaseService db) => _db = db;

    // ── Alerts → CSV ──────────────────────────────────────────
    public async Task<string> ExportAlertsAsync(string? outputPath = null)
    {
        var alerts = await _db.GetAlertsAsync(10_000);
        var sb = new StringBuilder();

        sb.AppendLine("Timestamp,Severity,Type,Title,Source,Detail,Read");
        foreach (var a in alerts)
            sb.AppendLine(string.Join(",",
                CsvField(a.At.ToString("O")),
                CsvField(a.Severity.ToString()),
                CsvField(a.Type.ToString()),
                CsvField(a.Title),
                CsvField(a.Source),
                CsvField(a.Detail),
                a.IsRead ? "true" : "false"));

        return await WriteFileAsync("netguard_alerts", sb.ToString(), outputPath);
    }

    // ── Connections → CSV ─────────────────────────────────────
    public async Task<string> ExportConnectionsAsync(
        IEnumerable<NetworkConnection> connections,
        string? outputPath = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("Protocol,LocalAddress,LocalPort,RemoteAddress,RemotePort,Domain,State,ProcessName,PID,Threat,FirstSeen");

        foreach (var c in connections)
            sb.AppendLine(string.Join(",",
                CsvField(c.Protocol),
                CsvField(c.LocalAddress),
                c.LocalPort.ToString(CultureInfo.InvariantCulture),
                CsvField(c.RemoteAddress),
                c.RemotePort.ToString(CultureInfo.InvariantCulture),
                CsvField(c.Domain),
                CsvField(c.State),
                CsvField(c.ProcessName),
                c.ProcessId.ToString(CultureInfo.InvariantCulture),
                CsvField(c.Threat.ToString()),
                CsvField(c.FirstSeen.ToString("O"))));

        return await WriteFileAsync("netguard_connections", sb.ToString(), outputPath);
    }

    // ── Processes → CSV ───────────────────────────────────────
    public async Task<string> ExportProcessesAsync(
        IEnumerable<ProcessInfo> processes,
        string? outputPath = null)
    {
        var sb = new StringBuilder();
        sb.AppendLine("PID,Name,Path,Hash,IsSigned,Publisher,MemoryKB,Threat,ThreatDetail,StartTime");

        foreach (var p in processes)
            sb.AppendLine(string.Join(",",
                p.Pid.ToString(CultureInfo.InvariantCulture),
                CsvField(p.Name),
                CsvField(p.Path),
                CsvField(p.Hash),
                p.IsSigned ? "true" : "false",
                CsvField(p.Publisher),
                p.MemoryKb.ToString(CultureInfo.InvariantCulture),
                CsvField(p.Threat.ToString()),
                CsvField(p.ThreatDetail),
                CsvField(p.StartTime == DateTime.MinValue
                    ? "" : p.StartTime.ToString("O"))));

        return await WriteFileAsync("netguard_processes", sb.ToString(), outputPath);
    }

    // ── Whitelist Rules → CSV ─────────────────────────────────
    public async Task<string> ExportWhitelistAsync(string? outputPath = null)
    {
        var rules = await _db.GetRulesAsync();
        var sb    = new StringBuilder();
        sb.AppendLine("ID,Pattern,Type,Description,Enabled,CreatedAt");

        foreach (var r in rules)
            sb.AppendLine(string.Join(",",
                r.Id.ToString(CultureInfo.InvariantCulture),
                CsvField(r.Pattern),
                CsvField(r.Type.ToString()),
                CsvField(r.Description),
                r.IsEnabled ? "true" : "false",
                CsvField(r.CreatedAt.ToString("O"))));

        return await WriteFileAsync("netguard_whitelist", sb.ToString(), outputPath);
    }

    // ── Helpers ───────────────────────────────────────────────
    private static async Task<string> WriteFileAsync(
        string baseName, string content, string? outputPath)
    {
        if (string.IsNullOrEmpty(outputPath))
        {
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var ts      = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            outputPath  = Path.Combine(desktop, $"{baseName}_{ts}.csv");
        }

        await File.WriteAllTextAsync(outputPath, content, Encoding.UTF8);
        return outputPath;
    }

    /// <summary>Wraps a value in CSV quotes, escaping any internal quotes.</summary>
    private static string CsvField(string value)
    {
        if (string.IsNullOrEmpty(value)) return "\"\"";
        var escaped = value.Replace("\"", "\"\"");
        return $"\"{escaped}\"";
    }
}
