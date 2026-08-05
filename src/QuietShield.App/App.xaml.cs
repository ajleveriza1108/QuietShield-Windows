using System.Windows;
using System.Windows.Threading;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using QuietShield.App.ViewModels;
using QuietShield.Licensing;
using QuietShield.Windows.Integration;

namespace QuietShield.App;

public partial class App : Application
{
    private IHost? _host;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var builder = Host.CreateApplicationBuilder(e.Args);
        builder.Logging.ClearProviders();
        builder.Logging.AddDebug();

        builder.Services.AddSingleton<INetworkEnvironmentDiscovery, ReadOnlyNetworkEnvironmentDiscovery>();
        builder.Services.AddSingleton<IDnsConfigurationDiscovery, ReadOnlyDnsConfigurationDiscovery>();
        builder.Services.AddSingleton<IInstalledApplicationDiscovery, DeferredInstalledApplicationDiscovery>();
        builder.Services.AddSingleton<IWin32ExecutableDiscovery, DeferredWin32ExecutableDiscovery>();
        builder.Services.AddSingleton<IStoreApplicationIdentityDiscovery, DeferredStoreApplicationIdentityDiscovery>();
        builder.Services.AddSingleton<IFirewallStateDiscovery, DeferredFirewallStateDiscovery>();
        builder.Services.AddSingleton<IFilteringPlatformCapabilityDiscovery, DeferredFilteringPlatformCapabilityDiscovery>();
        builder.Services.AddSingleton<IWindowsServiceStateDiscovery, DeferredWindowsServiceStateDiscovery>();
        builder.Services.AddSingleton<IStartupCapabilityDiscovery, DeferredStartupCapabilityDiscovery>();
        builder.Services.AddSingleton<INotificationCapabilityDiscovery, DeferredNotificationCapabilityDiscovery>();
        builder.Services.AddSingleton<IPowerStateDiscovery, DeferredPowerStateDiscovery>();
        builder.Services.AddSingleton<ISystemTrayFoundation, FoundationSystemTrayService>();
        builder.Services.AddSingleton<ILicenseService, FoundationLicenseService>();
        builder.Services.AddSingleton<MainViewModel>();
        builder.Services.AddSingleton<MainWindow>();

        _host = builder.Build();
        await _host.StartAsync().ConfigureAwait(true);

        var window = _host.Services.GetRequiredService<MainWindow>();
        MainWindow = window;
        window.Show();

        var viewModel = _host.Services.GetRequiredService<MainViewModel>();
        await viewModel.InitializeAsync(CancellationToken.None).ConfigureAwait(true);

        if (e.Args.Contains("--foundation-smoke", StringComparer.OrdinalIgnoreCase))
        {
            var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
            timer.Tick += (_, _) =>
            {
                timer.Stop();
                window.Close();
            };
            timer.Start();
        }
    }

    protected override async void OnExit(ExitEventArgs e)
    {
        if (_host is not null)
        {
            await _host.StopAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(true);
            _host.Dispose();
        }

        base.OnExit(e);
    }
}
