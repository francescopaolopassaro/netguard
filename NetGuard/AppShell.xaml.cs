using NetGuard.ViewModels;

namespace NetGuard.Views;

public partial class AppShell : Shell
{
    private readonly MainViewModel _vm;

    public AppShell(MainViewModel vm)
    {
        InitializeComponent();
        _vm = vm ?? throw new ArgumentNullException(nameof(vm)); // protezione
        BindingContext = vm;
    }

    protected override async void OnAppearing()
    {
        base.OnAppearing();

        if (_vm != null)
        {
            await _vm.InitAsync();
        }
        else
        {
            System.Diagnostics.Debug.WriteLine("ERRORE: MainViewModel è null in AppShell");
        }
    }
}