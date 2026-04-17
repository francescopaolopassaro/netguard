using CommunityToolkit.Maui;
using Microsoft.Extensions.Logging;
using NetGuard.Services;
using NetGuard.ViewModels;
using NetGuard.Views;
using NetGuard.Models;
using System.Threading.Tasks;

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

        // Register AppSettings early with defaults; update asynchronously from DB to avoid blocking DI
        builder.Services.AddSingleton<AppSettings>(sp =>
        {
            var settings = new AppSettings();
            var db = sp.GetRequiredService<DatabaseService>();
            _ = Task.Run(async () =>
            {
                try
                {
                    var loaded = await db.LoadSettingsAsync();
                    // Copy loaded values into the singleton instance
                    settings.VirusTotalApiKey   = loaded.VirusTotalApiKey;
                    settings.AbuseIpDbApiKey    = loaded.AbuseIpDbApiKey;
                    settings.AutoBlockProcesses= loaded.AutoBlockProcesses;
                    settings.AutoBlockDomains  = loaded.AutoBlockDomains;
                    settings.AutoBlockIps      = loaded.AutoBlockIps;
                    settings.ScanIntervalSec   = loaded.ScanIntervalSec;
                    settings.NotifyOnThreat    = loaded.NotifyOnThreat;
                    settings.PrimaryDnsServer  = loaded.PrimaryDnsServer;
                    settings.FallbackDnsServer = loaded.FallbackDnsServer;
                    settings.UseDnsOverHttps   = loaded.UseDnsOverHttps;
                    settings.DarkMode          = loaded.DarkMode;
                    settings.BlockThreshold    = loaded.BlockThreshold;
                }
                catch { /* ignore loading errors */ }
            });
            return settings;
        });

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

        // ThreatService: non bloccare la registrazione con GetAwaiter().GetResult();
        builder.Services.AddSingleton<ThreatService>(sp =>
        {
            // Costruiamo il servizio con impostazioni di default and update in background
            var db = sp.GetRequiredService<DatabaseService>();
            var appSettings = sp.GetRequiredService<AppSettings>();
            var svc = new ThreatService(appSettings);
            _ = Task.Run(async () =>
            {
                try
                {
                    var settings = await db.LoadSettingsAsync();
                    svc.UpdateConfig(settings);
                }
                catch { /* ignore */ }
            });
            return svc;
        });

        // ThreatIntelService: costruito senza bloccare; aggiorniamo le impostazioni in background
        builder.Services.AddSingleton<ThreatIntelService>(sp =>
        {
            var db = sp.GetRequiredService<DatabaseService>();
            var appSettings = sp.GetRequiredService<AppSettings>();
            var svc = new ThreatIntelService(db, appSettings);
            _ = Task.Run(async () =>
            {
                try
                {
                    var settings = await db.LoadSettingsAsync();
                    svc.UpdateSettings(settings);
                }
                catch { /* ignore */ }
            });
            return svc;
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

        // ==================== APP ====================
        // IMPORTANTE: NON registriamo l'App qui! La piattaforma crea l'istanza
        // builder.Services.AddSingleton<App>();  ← RIMOSSO

        return builder.Build();
    }
}