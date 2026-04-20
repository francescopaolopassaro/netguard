using NetGuard.Models;
using NetGuard.Services;
using NetGuard.ViewModels;

namespace NetGuard.Views;

public partial class DashboardPage : ContentPage
{
    private readonly DashboardViewModel _vm;
    private readonly ExportService _export;

    public DashboardPage(DashboardViewModel vm, ExportService export)
    {
        InitializeComponent();
        _vm = vm;
        _export = export;
        BindingContext = vm;

        // Collega i tap alle card
        ConnCard.GestureRecognizers.Add(new TapGestureRecognizer
        { Command = new Command(async () => await Shell.Current.GoToAsync("network")) });

        ProcCard.GestureRecognizers.Add(new TapGestureRecognizer
        { Command = new Command(async () => await Shell.Current.GoToAsync("process")) });

        ThreatCard.GestureRecognizers.Add(new TapGestureRecognizer
        { Command = new Command(async () => await DisplayAlert("Threats", $"{_vm.ThreatCount} threats detected", "OK")) });

        AlertCard.GestureRecognizers.Add(new TapGestureRecognizer
        { Command = new Command(async () => await Shell.Current.GoToAsync("alertdetail")) });
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        _vm.StartAutoRefresh(30_000);
        await _vm.RefreshAsync();
    }

    protected override void OnDisappearing()
    {
        base.OnDisappearing();
        _vm.Dispose();
    }

    private async void OnAlertSelected(object? sender, SelectionChangedEventArgs e)
    {
        if (e.CurrentSelection.FirstOrDefault() is not Alert alert) return;

        if (sender is CollectionView cv)
            cv.SelectedItem = null;

        await Shell.Current.GoToAsync($"alertdetail?alertId={alert.Id}");
    }

    private async void OnExportAlertsClicked(object? sender, EventArgs e)
    {
        try
        {
            var path = await _export.ExportAlertsAsync();
            await DisplayAlert("Export Completed", $"Alerts saved to:\n{path}", "OK");
        }
        catch (Exception ex)
        {
            await DisplayAlert("Export Error", ex.Message, "OK");
        }
    }
}