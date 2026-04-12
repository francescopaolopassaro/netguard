using NetGuard.Models;

namespace NetGuard.Services;

/// <summary>
/// Sends OS-level notifications when threats are detected.
/// MAUI's LocalNotification via CommunityToolkit on Windows/Linux.
/// </summary>
public class NotificationService
{
    private readonly DatabaseService _db;
    private AppSettings _settings;

    public NotificationService(DatabaseService db, AppSettings settings)
    {
        _db      = db;
        _settings= settings;
    }

    public void UpdateSettings(AppSettings s) => _settings = s;

    public async Task NotifyThreatAsync(Alert alert)
    {
        if (!_settings.NotifyOnThreat) return;
        if (alert.Severity < ThreatLevel.Medium) return;

        // ── In-app notification (always shown) ─────────────
        // The DashboardViewModel subscribes to ThreatAnalysisPipeline.AlertRaised
        // and shows alerts in the RecentAlerts list.

        // ── OS notification ─────────────────────────────────
        // On Windows: uses WinRT ToastNotification
        // On Linux:   uses libnotify via process (notify-send)
        await SendOsNotificationAsync(
            title:   $"NetGuard — {alert.Severity} Threat",
            message: $"{alert.Title}\n{alert.Source}");
    }

    private static async Task SendOsNotificationAsync(string title, string message)
    {
        if (OperatingSystem.IsWindows())
        {
            await SendWindowsToastAsync(title, message);
        }
        else if (OperatingSystem.IsLinux())
        {
            await SendLinuxNotifyAsync(title, message);
        }
    }

    private static async Task SendWindowsToastAsync(string title, string body)
    {
        // Uses Windows.UI.Notifications (available in .NET 9 on Windows)
        // Requires a package identity for UWP toast; fallback to MessageBox for unpackaged apps.
        try
        {
            // For unpackaged MAUI apps the simplest path is a dialog:
            await MainThread.InvokeOnMainThreadAsync(() =>
                Application.Current?.MainPage?.DisplayAlert(title, body, "Dismiss"));
        }
        catch { /* suppress if window not available */ }
    }

    private static async Task SendLinuxNotifyAsync(string title, string body)
    {
        // notify-send is available on most GNOME/KDE desktops
        try
        {
            using var proc = new System.Diagnostics.Process
            {
                StartInfo = new System.Diagnostics.ProcessStartInfo(
                    "notify-send",
                    $"--app-name=NetGuard --urgency=normal \"{title}\" \"{body}\"")
                {
                    UseShellExecute = false,
                    CreateNoWindow  = true
                }
            };
            proc.Start();
            await proc.WaitForExitAsync();
        }
        catch { /* notify-send not installed or display server unavailable */ }
    }
}
