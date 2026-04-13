using NetGuard.Models;
using NetGuard.Services;

namespace NetGuard.Views;

public partial class ConnectionDetailPage : ContentPage
{
    private NetworkConnection? _conn;

    private readonly IpLookupService  _geo;
    private readonly DnsCheckerService _dns;
    private readonly WhitelistEngine   _whitelist;

    // Static handoff from the list page (avoids serialisation issues)
    public static NetworkConnection? Current { get; set; }

    public ConnectionDetailPage(
        IpLookupService  geo,
        DnsCheckerService dns,
        WhitelistEngine   whitelist)
    {
        InitializeComponent();
        _geo       = geo;
        _dns       = dns;
        _whitelist = whitelist;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        _conn = Current;
        if (_conn == null) return;

        PopulateBasicInfo(_conn);

        // Kick off async lookups
        await Task.WhenAll(
            LoadGeoAsync(_conn.RemoteAddress),
            LoadDnsAsync(_conn.Domain, _conn.RemoteAddress));
    }

    // ── Basic info ────────────────────────────────────────────
    private void PopulateBasicInfo(NetworkConnection c)
    {
        ThreatIconLabel.Text = c.Threat switch
        {
            ThreatLevel.High   => "⛔",
            ThreatLevel.Medium => "⚠",
            ThreatLevel.Clean  => "✅",
            _                  => "🔵"
        };

        DomainLabel.Text  = string.IsNullOrEmpty(c.Domain) ? c.RemoteAddress : c.Domain;
        IpPortLabel.Text  = $"{c.RemoteAddress}:{c.RemotePort}";
        ProtocolLabel.Text = c.Protocol;
        RemoteLabel.Text  = $"{c.RemoteAddress}:{c.RemotePort}";
        StateLabel.Text   = c.State;
        ProcessLabel.Text = string.IsNullOrEmpty(c.ProcessName)
            ? $"PID {c.ProcessId}"
            : $"{c.ProcessName} (PID {c.ProcessId})";

        // Port risk
        var portRisk = IpLookupService.AssessPort(c.RemotePort, c.Protocol);
        PortRiskLabel.Text = portRisk.Level.ToString();
        PortRiskLabel.TextColor = portRisk.Level switch
        {
            ThreatLevel.High   => Color.FromArgb("#C53030"),
            ThreatLevel.Medium => Color.FromArgb("#C05621"),
            ThreatLevel.Clean  => Color.FromArgb("#276749"),
            _                  => Color.FromArgb("#718096")
        };
        PortNoteLabel.Text = portRisk.Note;
    }

    // ── Geolocation ───────────────────────────────────────────
    private async Task LoadGeoAsync(string ip)
    {
        try
        {
            var geo = await _geo.LookupIpAsync(ip);
            GeoSpinner.IsRunning = false;
            GeoSpinner.IsVisible = false;

            if (geo == null)
            {
                GeoErrorLabel.IsVisible = true;
                GeoErrorLabel.Text = "Private/reserved address — no geo data available";
                return;
            }

            GeoGrid.IsVisible    = true;
            LocationLabel.Text   = geo.DisplayLocation;
            IspLabel.Text        = $"{geo.Isp} / {geo.Org}".Trim(' ', '/');

            ProxyLabel.Text      = geo.IsProxy ? "⚠ Yes — VPN or proxy detected" : "No";
            ProxyLabel.TextColor = geo.IsProxy
                ? Color.FromArgb("#C05621")
                : Color.FromArgb("#38A169");

            HostingLabel.Text      = geo.IsHosting ? "⚠ Hosting provider" : "No";
            HostingLabel.TextColor = geo.IsHosting
                ? Color.FromArgb("#C05621")
                : Color.FromArgb("#718096");
        }
        catch (Exception ex)
        {
            GeoSpinner.IsRunning    = false;
            GeoErrorLabel.IsVisible = true;
            GeoErrorLabel.Text      = $"Geo lookup failed: {ex.Message}";
        }
    }

    // ── DNS ───────────────────────────────────────────────────
    private async Task LoadDnsAsync(string domain, string ip)
    {
        try
        {
            if (!string.IsNullOrEmpty(domain))
            {
                var r = await _dns.CheckDomainAsync(domain);
                DnsResultLabel.Text = r.Quad9Blocked
                    ? $"⛔ Blocked by Quad9: {r.Detail}"
                    : r.ThreatLevel == ThreatLevel.Clean
                        ? $"✅ Clean on Quad9. IPs: {string.Join(", ", r.Quad9Ips.Take(3))}"
                        : r.Detail;
                DnsResultLabel.TextColor = r.Quad9Blocked
                    ? Color.FromArgb("#C53030")
                    : Color.FromArgb("#276749");
            }
            else
            {
                var r = await _dns.CheckIpAsync(ip);
                DnsResultLabel.Text = string.IsNullOrEmpty(r.PtrRecord)
                    ? "No PTR record found"
                    : $"PTR: {r.PtrRecord}";
            }
        }
        catch (Exception ex)
        {
            DnsResultLabel.Text = $"DNS lookup failed: {ex.Message}";
        }
    }

    // ── Actions ───────────────────────────────────────────────
    private async void OnVirusTotalClicked(object? sender, EventArgs e)
    {
        if (_conn == null) return;
        await Launcher.OpenAsync(
            new Uri($"https://www.virustotal.com/gui/ip-address/{_conn.RemoteAddress}"));
    }

    private async void OnCopyIpClicked(object? sender, EventArgs e)
    {
        if (_conn == null) return;
        await Clipboard.SetTextAsync(_conn.RemoteAddress);
        await DisplayAlert("Copied", $"{_conn.RemoteAddress} copied to clipboard.", "OK");
    }

    private async void OnWhitelistClicked(object? sender, EventArgs e)
    {
        if (_conn == null) return;

        var options = new List<string>();
        if (!string.IsNullOrEmpty(_conn.Domain)) options.Add($"Domain: {_conn.Domain}");
        options.Add($"IP: {_conn.RemoteAddress}");

        var choice = await DisplayActionSheet(
            "Add to whitelist", "Cancel", null, options.ToArray());

        if (choice == null || choice == "Cancel") return;

        if (choice.StartsWith("Domain:"))
        {
            await _whitelist.AddRuleAsync(new WhitelistRule
            {
                Pattern     = _conn.Domain,
                Type        = RuleType.Domain,
                Description = $"Whitelisted from connection detail — {DateTime.Now:yyyy-MM-dd}"
            });
        }
        else
        {
            await _whitelist.AddRuleAsync(new WhitelistRule
            {
                Pattern     = _conn.RemoteAddress,
                Type        = RuleType.Ip,
                Description = $"Whitelisted from connection detail — {DateTime.Now:yyyy-MM-dd}"
            });
        }

        await DisplayAlert("Added", "Rule added to whitelist.", "OK");
    }

    private async void OnBackClicked(object? sender, EventArgs e)
        => await Shell.Current.GoToAsync("..");
}
