using NetGuard.Models;

namespace NetGuard.Views;

[QueryProperty(nameof(AlertId), "alertId")]
public partial class AlertDetailPage : ContentPage
{
    private Alert? _alert;
    private readonly Services.DatabaseService _db;

    public int AlertId { get; set; }

    public AlertDetailPage(Services.DatabaseService db)
    {
        InitializeComponent();
        _db = db;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        var alerts = await _db.GetAlertsAsync(500);
        _alert = alerts.FirstOrDefault(a => a.Id == AlertId);
        if (_alert != null) PopulateUi(_alert);
    }

    private void PopulateUi(Alert a)
    {
        IconLabel.Text      = a.Icon;
        TitleLabel.Text     = a.Title;
        SeverityLabel.Text  = $"Severity: {a.Severity}";
        TypeLabel.Text      = a.Type.ToString();
        SourceLabel.Text    = a.Source;
        DetailLabel.Text    = a.Detail;
        TimeLabel.Text      = a.At.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
        SeverityDetailLabel.Text  = a.Severity.ToString();
        SeverityDetailLabel.TextColor = Color.FromArgb(a.SeverityColor);

        // Banner background colour
        SeverityBanner.BackgroundColor = a.Severity switch
        {
            ThreatLevel.High   => Color.FromArgb("#C53030"),
            ThreatLevel.Medium => Color.FromArgb("#C05621"),
            ThreatLevel.Low    => Color.FromArgb("#2B6CB0"),
            _                  => Color.FromArgb("#4A5568")
        };

        // Recommended actions for high/medium
        if (a.Severity >= ThreatLevel.Medium)
        {
            ActionsFrame.IsVisible = true;
            ActionsLabel.Text = a.Type switch
            {
                AlertType.MaliciousProcess =>
                    "1. Kill the process immediately via Task Manager\n" +
                    "2. Delete or quarantine the executable\n" +
                    "3. Run a full system scan with your antivirus\n" +
                    "4. Check startup entries (Run → msconfig / systemd)",

                AlertType.MaliciousDomain =>
                    "1. Block the domain in your hosts file or firewall\n" +
                    "2. Identify which process is connecting to it\n" +
                    "3. Consider using Quad9 as your system DNS",

                AlertType.BlacklistedIp =>
                    "1. Add a firewall rule to block outbound traffic to this IP\n" +
                    "2. Check which process is connecting\n" +
                    "3. Review recent network activity logs",

                _ => "Review the alert details and take appropriate action."
            };
        }

        // VT button — show only if there's something to look up
        VtButton.IsVisible = !string.IsNullOrEmpty(a.Source);
    }

    private async void OnVirusTotalClicked(object? sender, EventArgs e)
    {
        if (_alert == null) return;
        var query = Uri.EscapeDataString(_alert.Source);
        var url = $"https://www.virustotal.com/gui/search/{query}";
        await Launcher.OpenAsync(new Uri(url));
    }

    private async void OnMarkReadClicked(object? sender, EventArgs e)
    {
        if (_alert == null) return;
        _alert.IsRead = true;
        // Persist read state (DatabaseService update)
        MarkReadButton.IsEnabled = false;
        MarkReadButton.Text = "✓ Marked";
        await Shell.Current.GoToAsync("..");
    }

    private async void OnBackClicked(object? sender, EventArgs e)
        => await Shell.Current.GoToAsync("..");
}
