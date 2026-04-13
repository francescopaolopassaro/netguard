using NetGuard.Models;
using NetGuard.Services;
using NetGuard.ViewModels;

namespace NetGuard.Views;

public partial class DashboardPage : ContentPage
{
    private readonly DashboardViewModel _vm;
    private readonly ExportService      _export;

    public DashboardPage(DashboardViewModel vm, ExportService export)
    {
        InitializeComponent();
        _vm     = vm;
        _export = export;
        BindingContext = vm;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        _vm.StartAutoRefresh(30_000);
        await _vm.RefreshCommand.ExecuteAsync(null);
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        _vm.Dispose();
    }

    // ── Alert tap → AlertDetailPage ───────────────────────────
    private async void OnAlertSelected(object? sender, SelectionChangedEventArgs e)
    {
        if (e.CurrentSelection.FirstOrDefault() is not Alert alert) return;
        AlertList.SelectedItem = null;

        await Shell.Current.GoToAsync($"alertdetail?alertId={alert.Id}");
    }

    // ── Export alerts CSV ─────────────────────────────────────
    private async void OnExportAlertsClicked(object? sender, EventArgs e)
    {
        try
        {
            var path = await _export.ExportAlertsAsync();
            await DisplayAlert("Exported", $"Alerts saved to:\n{path}", "OK");
        }
        catch (Exception ex)
        {
            await DisplayAlert("Export failed", ex.Message, "OK");
        }
    }
}
