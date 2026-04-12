namespace NetGuard;

public partial class App : Application
{
    public App()
    {
        InitializeComponent();
        MainPage = new AppShell();
    }

    protected override Window CreateWindow(IActivationState? activationState)
    {
        var window = base.CreateWindow(activationState);
        window.Title  = "NetGuard — Network Security Monitor";
        window.Width  = 1200;
        window.Height = 800;
        window.MinimumWidth  = 900;
        window.MinimumHeight = 600;
        return window;
    }
}
