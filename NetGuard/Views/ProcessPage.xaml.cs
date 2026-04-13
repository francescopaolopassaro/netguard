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
