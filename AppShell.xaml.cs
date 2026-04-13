namespace NetGuard;

public partial class AppShell : Shell
{
    public AppShell()
    {
        InitializeComponent();
        Routing.RegisterRoute("dashboard",         typeof(Views.DashboardPage));
        Routing.RegisterRoute("network",           typeof(Views.NetworkPage));
        Routing.RegisterRoute("processes",         typeof(Views.ProcessPage));
        Routing.RegisterRoute("rules",             typeof(Views.RulesPage));
        Routing.RegisterRoute("settings",          typeof(Views.SettingsPage));
        Routing.RegisterRoute("alertdetail",       typeof(Views.AlertDetailPage));
        Routing.RegisterRoute("processdetail",     typeof(Views.ProcessDetailPage));
        Routing.RegisterRoute("connectiondetail",  typeof(Views.ConnectionDetailPage));
    }
}
