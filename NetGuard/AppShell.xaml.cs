using NetGuard.ViewModels;
using NetGuard.Views;
using System.Windows.Input;
namespace NetGuard.Views // Assicurati che il namespace sia questo
{
    public partial class AppShell : Shell
    {
        public static AppShell Instance { get; private set; }

        public ICommand ShowAboutCommand { get; }

        public AppShell(MainViewModel vm)
        {
            InitializeComponent();
            BindingContext = vm;
            Instance = this;

            // Registrazione delle route (OBBLIGATORIO!)
            Routing.RegisterRoute("network", typeof(NetworkPage));
            Routing.RegisterRoute("process", typeof(ProcessPage));
            Routing.RegisterRoute("rules", typeof(RulesPage));
            Routing.RegisterRoute("settings", typeof(SettingsPage));
            Routing.RegisterRoute("alertdetail", typeof(AlertDetailPage));
            Routing.RegisterRoute("processdetail", typeof(ProcessDetailPage));
            Routing.RegisterRoute("connectiondetail", typeof(ConnectionDetailPage));
            //Routing.RegisterRoute("about", typeof(AboutPage));

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
}