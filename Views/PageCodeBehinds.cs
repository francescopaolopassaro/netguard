using NetGuard.ViewModels;

namespace NetGuard.Views;

// ─────────────────────────────────────────────────────────────
//  Dashboard
// ─────────────────────────────────────────────────────────────
public partial class DashboardPage : ContentPage
{
    private readonly DashboardViewModel _vm;

    public DashboardPage(DashboardViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
        BindingContext = vm;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        _vm.StartAutoRefresh(30_000);
        await _vm.RefreshCommand.ExecuteAsync(null);
    }
}

// ─────────────────────────────────────────────────────────────
//  Network
// ─────────────────────────────────────────────────────────────
public partial class NetworkPage : ContentPage
{
    private readonly NetworkViewModel _vm;

    public NetworkPage(NetworkViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
        BindingContext = vm;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        await _vm.RefreshCommand.ExecuteAsync(null);
    }
}

// ─────────────────────────────────────────────────────────────
//  Process
// ─────────────────────────────────────────────────────────────
public partial class ProcessPage : ContentPage
{
    private readonly ProcessViewModel _vm;

    public ProcessPage(ProcessViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
        BindingContext = vm;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        await _vm.ScanCommand.ExecuteAsync(null);
    }
}

// ─────────────────────────────────────────────────────────────
//  Rules
// ─────────────────────────────────────────────────────────────
public partial class RulesPage : ContentPage
{
    private readonly RulesViewModel _vm;

    public RulesPage(RulesViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
        BindingContext = vm;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        await _vm.LoadCommand.ExecuteAsync(null);
    }
}

// ─────────────────────────────────────────────────────────────
//  Settings
// ─────────────────────────────────────────────────────────────
public partial class SettingsPage : ContentPage
{
    private readonly SettingsViewModel _vm;

    public SettingsPage(SettingsViewModel vm)
    {
        InitializeComponent();
        _vm = vm;
        BindingContext = vm;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        await _vm.LoadCommand.ExecuteAsync(null);
    }
}
