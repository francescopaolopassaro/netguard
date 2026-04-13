using System.Diagnostics;
using NetGuard.Models;

namespace NetGuard.Views;

[QueryProperty(nameof(ProcessPid), "pid")]
public partial class ProcessDetailPage : ContentPage
{
    private ProcessInfo? _proc;

    public int ProcessPid { get; set; }

    // Injected via DI — passed by the ProcessPage as a static ref
    public static ProcessInfo? CurrentProcess { get; set; }

    public ProcessDetailPage()
    {
        InitializeComponent();
    }

    protected override void OnAppearing()
    {
        base.OnAppearing();
        _proc = CurrentProcess;
        if (_proc != null) PopulateUi(_proc);
    }

    private void PopulateUi(ProcessInfo p)
    {
        // Threat icon + badge
        ThreatIconLabel.Text = p.Threat switch
        {
            ThreatLevel.High   => "⛔",
            ThreatLevel.Medium => "⚠",
            ThreatLevel.Clean  => "✅",
            _                  => "⏳"
        };

        NameLabel.Text = p.Name;

        ThreatBadgeLabel.Text      = p.Threat.ToString();
        ThreatBadgeLabel.TextColor = p.Threat switch
        {
            ThreatLevel.High   => Color.FromArgb("#E53E3E"),
            ThreatLevel.Medium => Color.FromArgb("#D97706"),
            ThreatLevel.Clean  => Color.FromArgb("#38A169"),
            _                  => Color.FromArgb("#718096")
        };

        // Fields
        PidLabel.Text    = p.Pid.ToString();
        PathLabel.Text   = string.IsNullOrEmpty(p.Path) ? "(unavailable — permission denied)" : p.Path;
        HashLabel.Text   = string.IsNullOrEmpty(p.Hash) ? "(not computed)" : p.Hash;

        SignedLabel.Text      = p.IsSigned ? "✅ Signed" : "⚠ Unsigned";
        SignedLabel.TextColor = p.IsSigned
            ? Color.FromArgb("#38A169")
            : Color.FromArgb("#D97706");
        PublisherLabel.Text = p.IsSigned ? $"by {p.Publisher}" : "";

        MemLabel.Text   = $"{p.MemoryKb:N0} KB  ({p.MemoryKb / 1024.0:N1} MB)";
        StartLabel.Text = p.StartTime == DateTime.MinValue
            ? "(unknown)"
            : p.StartTime.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

        ScanResultLabel.Text = p.IsScanned
            ? p.ThreatDetail
            : "Not yet scanned";
        ScanResultLabel.TextColor = p.Threat switch
        {
            ThreatLevel.High   => Color.FromArgb("#C53030"),
            ThreatLevel.Medium => Color.FromArgb("#C05621"),
            ThreatLevel.Clean  => Color.FromArgb("#276749"),
            _                  => Color.FromArgb("#718096")
        };

        // Threat detail panel
        if (p.Threat >= ThreatLevel.Medium && !string.IsNullOrEmpty(p.ThreatDetail))
        {
            ThreatDetailFrame.IsVisible    = true;
            ThreatDetailTextLabel.Text     = p.ThreatDetail;
        }

        // Kill button — only for non-system processes
        KillButton.IsVisible = p.Threat >= ThreatLevel.Medium && p.Pid > 4;
    }

    private async void OnVirusTotalClicked(object? sender, EventArgs e)
    {
        if (_proc == null) return;
        var query = !string.IsNullOrEmpty(_proc.Hash) ? _proc.Hash : _proc.Name;
        await Launcher.OpenAsync(new Uri($"https://www.virustotal.com/gui/search/{Uri.EscapeDataString(query)}"));
    }

    private async void OnCopyHashClicked(object? sender, EventArgs e)
    {
        if (_proc == null || string.IsNullOrEmpty(_proc.Hash)) return;
        await Clipboard.SetTextAsync(_proc.Hash);
        await DisplayAlert("Copied", "SHA-256 hash copied to clipboard.", "OK");
    }

    private async void OnKillClicked(object? sender, EventArgs e)
    {
        if (_proc == null) return;
        var confirm = await DisplayAlert(
            "Kill process",
            $"Terminate '{_proc.Name}' (PID {_proc.Pid})? This cannot be undone.",
            "Kill", "Cancel");

        if (!confirm) return;

        try
        {
            var proc = Process.GetProcessById(_proc.Pid);
            proc.Kill(entireProcessTree: true);
            KillButton.Text      = "✓ Killed";
            KillButton.IsEnabled = false;
        }
        catch (Exception ex)
        {
            await DisplayAlert("Error", $"Could not kill process: {ex.Message}", "OK");
        }
    }

    private async void OnBackClicked(object? sender, EventArgs e)
        => await Shell.Current.GoToAsync("..");

}
