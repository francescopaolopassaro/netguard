using NetGuard.ViewModels;
using NetGuard.Views;

namespace NetGuard;

public partial class App : Application
{
    private readonly MainViewModel _mainViewModel;

    public App(MainViewModel mainViewModel)   // ← Riceve il ViewModel tramite DI
    {
        InitializeComponent();
        _mainViewModel = mainViewModel;

        MainPage = new AppShell(_mainViewModel);
    }

    protected override Window CreateWindow(IActivationState? activationState)
    {
        var window = base.CreateWindow(activationState);
        window.Title = "NetGuard — Network Security Monitor";
        window.Width = 1200;
        window.Height = 800;
        window.MinimumWidth = 900;
        window.MinimumHeight = 600;
        return window;
    }
}