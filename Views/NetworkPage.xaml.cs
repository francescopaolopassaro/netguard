using NetGuard.Models;
using NetGuard.Services;
using NetGuard.ViewModels;

namespace NetGuard.Views;

public partial class NetworkPage : ContentPage
{
    private readonly NetworkViewModel _vm;
    private readonly ExportService    _export;

    public NetworkPage(NetworkViewModel vm, ExportService export)
    {
        InitializeComponent();
        _vm     = vm;
        _export = export;
        BindingContext = vm;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        await _vm.RefreshCommand.ExecuteAsync(null);
    }

    // ── Row tap → ConnectionDetailPage ───────────────────────
    private async void OnConnectionSelected(object? sender, SelectionChangedEventArgs e)
    {
        if (e.CurrentSelection.FirstOrDefault() is not NetworkConnection conn) return;
        ConnectionList.SelectedItem = null; // deselect immediately

        ConnectionDetailPage.Current = conn;
        await Shell.Current.GoToAsync("connectiondetail");
    }

    // ── Export CSV ────────────────────────────────────────────
    private async void OnExportClicked(object? sender, EventArgs e)
    {
        try
        {
            var path = await _export.ExportConnectionsAsync(_vm.Connections);
            await DisplayAlert("Exported",
                $"Connections saved to:\n{path}", "OK");
        }
        catch (Exception ex)
        {
            await DisplayAlert("Export failed", ex.Message, "OK");
        }
    }
}

