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

#if DEBUG
        builder.Logging.AddDebug();
#endif

        // ==================== CORE SERVICES ====================
        builder.Services.AddSingleton<DatabaseService>();

        builder.Services.AddSingleton<WhitelistService>();           // ← Richiesto da MonitoringEngine
        builder.Services.AddSingleton<WhitelistEngine>();            // ← Usato altrove (Pipeline)

        builder.Services.AddSingleton<ProcessService>();
        builder.Services.AddSingleton<ProcessScannerService>();
        builder.Services.AddSingleton<NetworkService>();
        builder.Services.AddSingleton<NetworkMonitorService>();
        builder.Services.AddSingleton<BlockingService>();
        builder.Services.AddSingleton<IpLookupService>();
        builder.Services.AddSingleton<DnsCheckerService>();
        builder.Services.AddSingleton<ExportService>();
        builder.Services.AddSingleton<NotificationService>();

        // ThreatService (usato da MonitoringEngine)
        builder.Services.AddSingleton<ThreatService>(sp =>
        {
            var db = sp.GetRequiredService<DatabaseService>();
            var settings = db.LoadSettingsAsync().GetAwaiter().GetResult();
            return new ThreatService(settings);
        });

        // ThreatIntelService (nuovo)
        builder.Services.AddSingleton<ThreatIntelService>(sp =>
        {
            var db = sp.GetRequiredService<DatabaseService>();
            var settings = db.LoadSettingsAsync().GetAwaiter().GetResult();
            return new ThreatIntelService(db, settings);
        });

        // ThreatAnalysisPipeline
        builder.Services.AddSingleton<ThreatAnalysisPipeline>(sp =>
        {
            return new ThreatAnalysisPipeline(
                sp.GetRequiredService<WhitelistEngine>(),
                sp.GetRequiredService<DnsCheckerService>(),
                sp.GetRequiredService<ThreatIntelService>(),
                sp.GetRequiredService<DatabaseService>(),
                sp.GetRequiredService<ProcessScannerService>()
            );
        });

        // MonitoringEngine - ORA dovrebbe funzionare
        builder.Services.AddSingleton<MonitoringEngine>();

        // ==================== VIEWMODELS ====================
        builder.Services.AddTransient<DashboardViewModel>();
        builder.Services.AddTransient<NetworkViewModel>();
        builder.Services.AddTransient<ProcessViewModel>();
        builder.Services.AddTransient<RulesViewModel>();
        builder.Services.AddTransient<SettingsViewModel>();
        builder.Services.AddSingleton<MainViewModel>();

        // ==================== PAGES ====================
        builder.Services.AddTransient<DashboardPage>();
        builder.Services.AddTransient<NetworkPage>();
        builder.Services.AddTransient<ProcessPage>();
        builder.Services.AddTransient<RulesPage>();
        builder.Services.AddTransient<SettingsPage>();

        builder.Services.AddTransient<ProcessDetailPage>();
        builder.Services.AddTransient<ConnectionDetailPage>();
        builder.Services.AddTransient<AlertDetailPage>();

        // Application
        builder.Services.AddSingleton<App>();

        return builder.Build();
    }
}