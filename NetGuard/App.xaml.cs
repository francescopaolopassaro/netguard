using NetGuard.ViewModels;
using NetGuard.Views;
using Microsoft.Extensions.DependencyInjection;

namespace NetGuard;

public partial class App : Application
{
    public App()
    {
        InitializeComponent();

        // Do NOT set MainPage here when overriding CreateWindow; CreateWindow will set window.Page.
    }

    protected override Window CreateWindow(IActivationState? activationState)
    {
        // Resolve services from the MauiContext when available
        var services = this.Handler?.MauiContext?.Services
                       ?? Application.Current?.Handler?.MauiContext?.Services;

        Page page;

        if (services != null && services.GetService(typeof(MainViewModel)) is MainViewModel vm)
        {
            // Create AppShell with resolved VM; AppShell.OnAppearing will call vm.InitAsync()
            page = new AppShell(vm);
        }
        else
        {
            // Fallback page to ensure window is visible and to avoid dispatcher issues
            page = new ContentPage
            {
                Content = new StackLayout
                {
                    Padding = 20,
                    Children =
                    {
                        new Label { Text = "Starting..." },
                        new Label { Text = "MainViewModel not available yet; try running without Live Visual Tree/Hot Reload." }
                    }
                }
            };
        }

        var window = new Window(page)
        {
            Title = "NetGuard — Network Security Monitor",
            Width = 1200,
            Height = 800,
            MinimumWidth = 900,
            MinimumHeight = 600
        };

        return window;
    }
}