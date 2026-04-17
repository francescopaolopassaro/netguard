using NetGuard.Models;
using NetGuard.Services;
using NetGuard.ViewModels;

namespace NetGuard.Views;

public partial class ProcessPage : ContentPage
{
    private readonly ProcessViewModel _vm;
    private readonly ExportService    _export;

    public ProcessPage(ProcessViewModel vm, ExportService export)
    {
        InitializeComponent();
        _vm     = vm;
        _export = export;
        BindingContext = vm;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();

        // If the app is not elevated, prompt the user to restart elevated for full process access
        try
        {
            if (!ElevationService.IsElevated)
            {
                var wantElevate = await DisplayAlert(
                    "Administrator privileges required",
                    "Full process enumeration and blocking require Administrator rights. Restart elevated now?",
                    "Restart as admin",
                    "Continue without elevation");

                if (wantElevate)
                {
                    // This will relaunch the app elevated and exit the current process
                    ElevationService.RestartElevated();
                    return; // process will exit, but keep return for safety
                }
            }
        }
        catch
        {
            // Ignore elevation check failures and continue with scan attempt
        }

        await _vm.ScanCommand.ExecuteAsync(null);
    }

    // ── Row tap → ProcessDetailPage ───────────────────────────
    private async void OnProcessSelected(object? sender, SelectionChangedEventArgs e)
    {
        if (e.CurrentSelection.FirstOrDefault() is not ProcessInfo proc) return;
        ProcessList.SelectedItem = null; // deselect immediately

        ProcessDetailPage.CurrentProcess = proc;
        await Shell.Current.GoToAsync("processdetail");
    }

    // ── Export CSV ────────────────────────────────────────────
    private async void OnExportClicked(object? sender, EventArgs e)
    {
        try
        {
            var path = await _export.ExportProcessesAsync(_vm.Processes);
            await DisplayAlert("Exported",
                $"Processes saved to:\n{path}", "OK");
        }
        catch (Exception ex)
        {
            await DisplayAlert("Export failed", ex.Message, "OK");
        }
    }
}
