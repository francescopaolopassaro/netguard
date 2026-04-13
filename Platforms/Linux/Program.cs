using Microsoft.Maui;
using Microsoft.Maui.Hosting;

namespace NetGuard;

/// <summary>
/// Linux/GTK entry point for the MAUI application.
/// </summary>
class Program : MauiProgram
{
    static void Main(string[] args)
    {
        var app = CreateMauiApp();
        app.Run();
    }
}
