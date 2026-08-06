using System.Windows;
using System.Windows.Threading;
using System.IO;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using QuietShield.App.ViewModels;
using QuietShield.App.Windowing;
using QuietShield.Core.Dns;
using QuietShield.Licensing;
using QuietShield.Windows.Diagnostics;
using QuietShield.Windows.Dns;
using QuietShield.Windows.Discovery;
using QuietShield.Windows.Discovery.Applications;
using QuietShield.Windows.Integration;

namespace QuietShield.App;

public partial class App : Application
{
    private static readonly JsonSerializerOptions GuiValidationSerializerOptions = new() { WriteIndented = true };
    private IHost? _host;

    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var builder = Host.CreateApplicationBuilder(e.Args);
        builder.Logging.ClearProviders();
        builder.Logging.AddDebug();

        builder.Services.AddSingleton<IPowerShellJsonRunner, PowerShellJsonRunner>();
        builder.Services.AddSingleton<IUninstallRegistrationSource, RegistryUninstallRegistrationSource>();
        builder.Services.AddSingleton<IStorePackageSource, PowerShellStorePackageSource>();
        builder.Services.AddSingleton<IStartMenuEntrySource, StartMenuEntrySource>();
        builder.Services.AddSingleton<IDiscoveryClock, SystemDiscoveryClock>();
        builder.Services.AddSingleton<IApplicationInventoryCache>(services => new JsonApplicationInventoryCache(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "QuietShield", "Discovery", "applications.json"),
            services.GetRequiredService<IDiscoveryClock>()));
        builder.Services.AddSingleton<ApplicationInventoryService>();
        builder.Services.AddSingleton<IApplicationInventoryService>(services => services.GetRequiredService<ApplicationInventoryService>());
        builder.Services.AddSingleton<IInstalledApplicationDiscovery>(services => services.GetRequiredService<ApplicationInventoryService>());
        builder.Services.AddSingleton<INetworkEnvironmentDiscovery, ReadOnlyNetworkEnvironmentDiscovery>();
        builder.Services.AddSingleton<IDnsConfigurationDiscovery, ReadOnlyDnsConfigurationDiscovery>();
        builder.Services.AddSingleton<IFirewallStateDiscovery, ReadOnlyFirewallStateDiscovery>();
        builder.Services.AddSingleton<IFilteringPlatformCapabilityDiscovery, ReadOnlyFilteringPlatformCapabilityDiscovery>();
        builder.Services.AddSingleton<IWindowsServiceStateDiscovery, ReadOnlyWindowsServiceStateDiscovery>();
        builder.Services.AddSingleton<IStartupCapabilityDiscovery, DeferredStartupCapabilityDiscovery>();
        builder.Services.AddSingleton<INotificationCapabilityDiscovery, DeferredNotificationCapabilityDiscovery>();
        builder.Services.AddSingleton<IPowerStateDiscovery, ReadOnlyPowerStateDiscovery>();
        builder.Services.AddSingleton<ISystemTrayFoundation, FoundationSystemTrayService>();
        builder.Services.AddSingleton<INetworkRefreshNotificationSource, WindowsNetworkRefreshNotificationSource>();
        builder.Services.AddSingleton<IReadOnlyDiscoveryCoordinator, ReadOnlyDiscoveryCoordinator>();
        builder.Services.AddSingleton<IPrivacySafeDiagnosticExporter, PrivacySafeDiagnosticExporter>();
        builder.Services.AddSingleton<IDnsClock, SystemDnsClock>();
        builder.Services.AddSingleton<IProtectionListSignatureVerifier, NonProductionSampleSignatureVerifier>();
        builder.Services.AddSingleton<IProtectionListStore, InMemoryProtectionListStore>();
        builder.Services.AddSingleton<ProtectionListActivator>();
        builder.Services.AddSingleton<ICustomDomainListService, InMemoryCustomDomainListService>();
        builder.Services.AddSingleton<IDnsDecisionCache>(services => new InMemoryDnsDecisionCache(services.GetRequiredService<IDnsClock>(), 512));
        builder.Services.AddSingleton<IDnsRuntimePolicyConfiguration, FoundationDnsRuntimePolicyConfiguration>();
        builder.Services.AddSingleton<IDnsRuntimePolicyEvaluator, FoundationDnsRuntimePolicyEvaluator>();
        builder.Services.AddSingleton<ILocalDnsRuntimeDiagnostic, LocalDnsRuntimeDiagnostic>();
        builder.Services.AddSingleton<IDnsListenerSnapshotSource, SystemDnsListenerSnapshotSource>();
        builder.Services.AddSingleton<IDnsRehearsalReadinessDiscovery, ReadOnlyDnsRehearsalReadinessDiscovery>();
        builder.Services.AddSingleton<ILicenseService, FoundationLicenseService>();
        builder.Services.AddSingleton<IDisplayWorkAreaProvider, WindowsDisplayWorkAreaProvider>();
        if (e.Args.Any(static argument => argument.Contains("smoke", StringComparison.OrdinalIgnoreCase)))
        {
            builder.Services.AddSingleton<IWindowPlacementStore, InMemoryWindowPlacementStore>();
        }
        else
        {
            builder.Services.AddSingleton<IWindowPlacementStore>(_ => new JsonWindowPlacementStore(
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "QuietShield", "UI", "window-placement.json")));
        }
        builder.Services.AddSingleton<MainViewModel>();
        builder.Services.AddSingleton<MainWindow>();

        _host = builder.Build();
        await _host.StartAsync().ConfigureAwait(true);

        var window = _host.Services.GetRequiredService<MainWindow>();
        MainWindow = window;
        window.Show();

        var viewModel = _host.Services.GetRequiredService<MainViewModel>();
        await viewModel.InitializeAsync(CancellationToken.None).ConfigureAwait(true);

        var diagnosticOutputIndex = Array.FindIndex(e.Args, static argument => argument.Equals("--diagnostic-output", StringComparison.OrdinalIgnoreCase));
        if (diagnosticOutputIndex >= 0 && diagnosticOutputIndex + 1 < e.Args.Length)
        {
            await viewModel.ExportValidationDiagnosticAsync(e.Args[diagnosticOutputIndex + 1], CancellationToken.None).ConfigureAwait(true);
        }

        if (e.Args.Contains("--phase6-smoke", StringComparer.OrdinalIgnoreCase))
        {
            var validationOutput = GetArgumentValue(e.Args, "--gui-validation-output");
            if (string.IsNullOrWhiteSpace(validationOutput))
            {
                throw new InvalidOperationException("Phase 6 GUI validation requires --gui-validation-output.");
            }

            var result = await Phase6GuiValidator.ValidateAsync(window, viewModel).ConfigureAwait(true);
            var directory = Path.GetDirectoryName(validationOutput);
            if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
            await File.WriteAllTextAsync(
                validationOutput,
                JsonSerializer.Serialize(result, GuiValidationSerializerOptions),
                CancellationToken.None).ConfigureAwait(true);
            if (!string.Equals(result.Status, "Passed", StringComparison.Ordinal)) Environment.ExitCode = 2;
            window.Close();
            return;
        }

        if (e.Args.Contains("--foundation-smoke", StringComparer.OrdinalIgnoreCase) ||
            e.Args.Contains("--phase2-smoke", StringComparer.OrdinalIgnoreCase) ||
            e.Args.Contains("--phase3-smoke", StringComparer.OrdinalIgnoreCase) ||
            e.Args.Contains("--phase4-smoke", StringComparer.OrdinalIgnoreCase) ||
            e.Args.Contains("--phase5-smoke", StringComparer.OrdinalIgnoreCase))
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

    private static string? GetArgumentValue(string[] arguments, string name)
    {
        for (var index = 0; index < arguments.Length - 1; index++)
        {
            if (arguments[index].Equals(name, StringComparison.OrdinalIgnoreCase)) return arguments[index + 1];
        }
        return null;
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
