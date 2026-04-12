using CommunityToolkit.Maui;
using Microsoft.Extensions.Logging;
using NetGuard.Services;
using NetGuard.ViewModels;
using NetGuard.Views;

namespace NetGuard;

public static class MauiProgram
{
    public static MauiApp CreateMauiApp()
    {
        var builder = MauiApp.CreateBuilder();

        builder
            .UseMauiApp<App>()
            .UseMauiCommunityToolkit()
            .ConfigureFonts(fonts =>
            {
                fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                fonts.AddFont("OpenSans-SemiBold.ttf", "OpenSansSemiBold");
            });

        // ── Services (Singleton — shared state) ───────────────
        builder.Services.AddSingleton<DatabaseService>();
        builder.Services.AddSingleton<WhitelistEngine>();
        builder.Services.AddSingleton<NetworkMonitorService>();
        builder.Services.AddSingleton<ProcessScannerService>();
        builder.Services.AddSingleton<DnsCheckerService>(sp =>
        {
            var db       = sp.GetRequiredService<DatabaseService>();
            var settings = db.LoadSettingsAsync().GetAwaiter().GetResult();
            return new DnsCheckerService(settings);
        });
        builder.Services.AddSingleton<ThreatIntelService>(sp =>
        {
            var db       = sp.GetRequiredService<DatabaseService>();
            var settings = db.LoadSettingsAsync().GetAwaiter().GetResult();
            return new ThreatIntelService(db, settings);
        });
        builder.Services.AddSingleton<ThreatAnalysisPipeline>();

        // ── ViewModels ────────────────────────────────────────
        builder.Services.AddTransient<DashboardViewModel>();
        builder.Services.AddTransient<NetworkViewModel>();
        builder.Services.AddTransient<ProcessViewModel>();
        builder.Services.AddTransient<RulesViewModel>();
        builder.Services.AddTransient<SettingsViewModel>();

        // ── Pages ─────────────────────────────────────────────
        builder.Services.AddTransient<DashboardPage>();
        builder.Services.AddTransient<NetworkPage>();
        builder.Services.AddTransient<ProcessPage>();
        builder.Services.AddTransient<RulesPage>();
        builder.Services.AddTransient<SettingsPage>();

#if DEBUG
        builder.Logging.AddDebug();
#endif

        return builder.Build();
    }
}
