using NetGuard.ViewModels;
using NetGuard.Views;
using System.Windows.Input;

namespace NetGuard.Views;

public partial class AppShell : Shell
{
    public static AppShell Instance { get; private set; }

    public ICommand ShowAboutCommand { get; }

    public AppShell(MainViewModel vm)
    {
        InitializeComponent();
        BindingContext = vm;
        Instance = this;

        // Register route names for navigation to detail pages
        Routing.RegisterRoute("processdetail", typeof(ProcessDetailPage));
        Routing.RegisterRoute("connectiondetail", typeof(ConnectionDetailPage));
        Routing.RegisterRoute("alertdetail", typeof(AlertDetailPage));
        Routing.RegisterRoute("about", typeof(AboutPage));

        ShowAboutCommand = new Command(async () => await Shell.Current.GoToAsync("about"));
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();
        if (BindingContext is MainViewModel vm)
        {
            await vm.InitAsync();
        }
    }
}