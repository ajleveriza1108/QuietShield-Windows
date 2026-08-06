using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;
using System.Windows.Input;
using System.Windows.Media.Imaging;
using Microsoft.Extensions.Logging;
using QuietShield.Core.ConnectionLock;
using QuietShield.Core.Dns;
using QuietShield.Core.Protection;
using QuietShield.Core.Simulation;
using QuietShield.Licensing;
using QuietShield.Windows.Diagnostics;
using QuietShield.Windows.Dns;
using QuietShield.Windows.Integration;

namespace QuietShield.App.ViewModels;

public sealed class ApplicationListItem
{
    private readonly Lazy<BitmapSource?> _icon;

    public ApplicationListItem(InstalledApplicationInfo application)
    {
        Application = application;
        _icon = new Lazy<BitmapSource?>(() => ApplicationIconConverter.LoadIcon(Application.Icon));
    }

    public InstalledApplicationInfo Application { get; }
    public string Id => Application.Id;
    public string DisplayName => Application.DisplayName;
    public string? Publisher => Application.Publisher;
    public string? Version => Application.Version;
    public InstalledApplicationType ApplicationType => Application.ApplicationType;
    public string ApplicationTypeLabel => Application.IsWindowsSystemComponent ? "Windows system component" : Application.ApplicationType.ToString();
    public string PathValue => Application.MainExecutablePath ?? Application.PackageFamilyName ?? Application.InstallLocation ?? "No exact executable or package target was discovered";
    public string PathStatus => Application.PackageFamilyName is not null ? "Package managed" : Application.MainExecutablePath is null ? "Ambiguous or unsupported" : Application.ExecutableExists ? "Present" : "Missing or moved";
    public string PolicyLabel => Application.IsWindowsSystemComponent ? "Safety classification / profile default" : "Profile default / simulated program override";
    public BitmapSource? IconImage => _icon.Value;
    public string? IconSourcePath => Application.Icon?.SourcePath;
}

public sealed partial class MainViewModel : INotifyPropertyChanged, IDisposable
{
    private static readonly Action<ILogger, Exception?> LogInitializedMessage = LoggerMessage.Define(
        LogLevel.Information,
        new EventId(2003, "ResponsiveGuiInitialized"),
        "QuietShield Phase 6 responsive GUI foundation initialized; Windows DNS and protection engines remain unchanged.");
    private readonly IReadOnlyDiscoveryCoordinator _discovery;
    private readonly INetworkRefreshNotificationSource _notifications;
    private readonly IPrivacySafeDiagnosticExporter _diagnostics;
    private readonly ILicenseService _licenseService;
    private readonly ISystemTrayFoundation _systemTray;
    private readonly ProtectionListActivator _dnsListActivator;
    private readonly IProtectionListStore _dnsListStore;
    private readonly ICustomDomainListService _customDnsLists;
    private readonly IDnsDecisionCache _dnsDecisionCache;
    private readonly ILocalDnsRuntimeDiagnostic _dnsRuntimeDiagnostic;
    private readonly IDnsRehearsalReadinessDiscovery _dnsRehearsalReadinessDiscovery;
    private readonly ILogger<MainViewModel> _logger;
    private readonly ObservableCollection<ApplicationListItem> _allApplications = new();
    private CancellationTokenSource? _refreshCancellation;
    private ReadOnlyDiscoveryBundle? _bundle;
    private NavigationItem _selectedPage;
    private ApplicationListItem? _selectedApplication;
    private string _searchText = string.Empty;
    private SimulatedConnectionType _selectedConnectionType = SimulatedConnectionType.Unknown;
    private ProgramConnectionPolicy _selectedPolicy = ProgramConnectionPolicy.AllowedOnAll;
    private ProtectionMode _selectedProfileMode = ProtectionMode.Standard;
    private string _networkSummary = "Read-only detection pending";
    private string _networkTypeSummary = "Pending";
    private string _meteredStatusSummary = "Pending";
    private string _firewallSummary = "Pending";
    private string _dnsSummary = "Pending";
    private string _applicationCount = "Pending";
    private string _lastDiscovery = "Not completed";
    private string _warningCount = "0";
    private string _activitySummary = "Discovery has not run.";
    private string _powerSummary = "Pending";
    private string _simulationDecision = "Select an application to simulate a policy.";
    private string _simulationReason = PolicySimulationResult.SimulationOnlyLabel;
    private string _lastActionStatus = "Ready for read-only discovery.";
    private string _licenseSummary = LicenseSnapshot.Foundation.DisplayStatus;
    private string _traySummary = "System tray foundation inactive";
    private bool _isRefreshing;
    private bool _isNavigationCompact;

    public MainViewModel(
        IReadOnlyDiscoveryCoordinator discovery,
        INetworkRefreshNotificationSource notifications,
        IPrivacySafeDiagnosticExporter diagnostics,
        ILicenseService licenseService,
        ISystemTrayFoundation systemTray,
        ProtectionListActivator dnsListActivator,
        IProtectionListStore dnsListStore,
        ICustomDomainListService customDnsLists,
        IDnsDecisionCache dnsDecisionCache,
        ILocalDnsRuntimeDiagnostic dnsRuntimeDiagnostic,
        IDnsRehearsalReadinessDiscovery dnsRehearsalReadinessDiscovery,
        IProfileSelectionStore profileSelectionStore,
        ILogger<MainViewModel> logger)
    {
        _discovery = discovery;
        _notifications = notifications;
        _diagnostics = diagnostics;
        _licenseService = licenseService;
        _systemTray = systemTray;
        _dnsListActivator = dnsListActivator;
        _dnsListStore = dnsListStore;
        _customDnsLists = customDnsLists;
        _dnsDecisionCache = dnsDecisionCache;
        _dnsRuntimeDiagnostic = dnsRuntimeDiagnostic;
        _dnsRehearsalReadinessDiscovery = dnsRehearsalReadinessDiscovery;
        _logger = logger;
        InitializeProgramConnectionLock(profileSelectionStore);
        NavigationItems = new ObservableCollection<NavigationItem>
        {
            new("Dashboard", "Foundation status and current read-only discovery.", "\uE80F", "READ-ONLY FOUNDATION", true),
            new("Protection", "Protection overview; enforcement remains disabled.", "\uEA18", "NOT ACTIVE"),
            new("Program Connection Lock", "Local per-program policy simulation only.", "\uE839", "SIMULATION ONLY"),
            new("Protection Profiles", "Preview local protection profiles without applying them.", "\uE77B", "SIMULATION ONLY"),
            new("Schedules", "Preview schedule behavior without creating tasks or startup entries.", "\uE787", "SIMULATION ONLY"),
            new("Metered and Cellular Data Watch", "Current Windows metered state; no traffic accounting.", "\uE9D9", "READ-ONLY"),
            new("Aggressive Program Watch", "Program monitoring is planned and currently inactive.", "\uE7BA", "NOT ACTIVE"),
            new("Compatibility Guard", "Preview compatibility exclusions without changing Windows.", "\uE8D4", "SIMULATION ONLY"),
            new("DNS Protection", "Local DNS policy simulation; Windows DNS remains unchanged.", "\uE774", "ACTIVATION BLOCKED"),
            new("Allowlist and Blocklist", "Manage in-memory DNS simulation entries.", "\uE8D7", "SIMULATION ONLY"),
            new("Activity and Statistics", "Read-only discovery activity without fabricated statistics.", "\uE9D2", "READ-ONLY"),
            new("Parent and Child Controls", "Family controls are planned and currently inactive.", "\uE716", "NOT ACTIVE"),
            new("Private Browser", "Private browsing integration is planned and currently inactive.", "\uE727", "NOT ACTIVE"),
            new("File Safety", "File safety integration is planned and currently inactive.", "\uE8A5", "NOT ACTIVE"),
            new("Licensing", "View the current local licensing foundation state.", "\uE8C7", "FOUNDATION"),
            new("Updates", "Update delivery is planned and currently inactive.", "\uE777", "NOT ACTIVE"),
            new("Settings", "Read-only discovery, cache, and privacy-safe diagnostics.", "\uE713", "SAFE CONTROLS")
        };
        _selectedPage = NavigationItems[0];
        RefreshCommand = new AsyncRelayCommand(() => RefreshAsync(true), () => !IsRefreshing);
        CancelCommand = new AsyncRelayCommand(CancelAsync, () => IsRefreshing);
        ClearCacheCommand = new AsyncRelayCommand(ClearCacheAsync, () => !IsRefreshing);
        ExportDiagnosticsCommand = new AsyncRelayCommand(ExportDiagnosticsAsync, () => _bundle is not null && !IsRefreshing);
        InitializeDnsCommands();
        InitializeDnsRuntimeCommands();
    }

    public event PropertyChangedEventHandler? PropertyChanged;
    public ObservableCollection<NavigationItem> NavigationItems { get; }
    public ObservableCollection<ApplicationListItem> Applications { get; } = new();
    public IReadOnlyList<SimulatedConnectionType> ConnectionTypes { get; } = Enum.GetValues<SimulatedConnectionType>();
    public IReadOnlyList<ProgramConnectionPolicy> ProgramPolicies { get; } = Enum.GetValues<ProgramConnectionPolicy>();
    public IReadOnlyList<ProtectionMode> ProfileModes { get; } = Enum.GetValues<ProtectionMode>();
    public ICommand RefreshCommand { get; }
    public ICommand CancelCommand { get; }
    public ICommand ClearCacheCommand { get; }
    public ICommand ExportDiagnosticsCommand { get; }

    public NavigationItem SelectedPage
    {
        get => _selectedPage;
        set
        {
            if (Equals(_selectedPage, value)) return;
            _selectedPage = value;
            OnPropertyChanged();
            foreach (var name in PageVisibilityProperties) OnPropertyChanged(name);
        }
    }

    private static readonly string[] PageVisibilityProperties =
    {
        nameof(IsDashboard), nameof(IsProgramConnectionLock), nameof(IsProtectionProfiles), nameof(IsSchedules), nameof(IsCompatibilityGuard), nameof(IsMeteredDataWatch),
        nameof(IsAggressiveProgramWatch), nameof(IsDnsProtection), nameof(IsDnsLists), nameof(IsActivity), nameof(IsLicensing), nameof(IsSettings), nameof(IsGenericPage)
    };

    public bool IsDashboard => SelectedPage.IsDashboard;
    public bool IsProgramConnectionLock => SelectedPage.Title == "Program Connection Lock";
    public bool IsProtectionProfiles => SelectedPage.Title == "Protection Profiles";
    public bool IsSchedules => SelectedPage.Title == "Schedules";
    public bool IsCompatibilityGuard => SelectedPage.Title == "Compatibility Guard";
    public bool IsMeteredDataWatch => SelectedPage.Title == "Metered and Cellular Data Watch";
    public bool IsAggressiveProgramWatch => SelectedPage.Title == "Aggressive Program Watch";
    public bool IsDnsProtection => SelectedPage.Title == "DNS Protection";
    public bool IsDnsLists => SelectedPage.Title == "Allowlist and Blocklist";
    public bool IsActivity => SelectedPage.Title == "Activity and Statistics";
    public bool IsLicensing => SelectedPage.Title == "Licensing";
    public bool IsSettings => SelectedPage.Title == "Settings";
    public bool IsGenericPage => !(IsDashboard || IsProgramConnectionLock || IsProtectionProfiles || IsSchedules || IsCompatibilityGuard || IsMeteredDataWatch || IsAggressiveProgramWatch || IsDnsProtection || IsDnsLists || IsActivity || IsLicensing || IsSettings);
    public string VersionText { get; } = "Version 0.7.0 - Program Connection Lock Foundation";
    public string FoundationMode { get; } = "Foundation Mode";
    public string ProtectionState { get; } = "Protection Not Activated";
    public string ActiveProfile { get; } = "Simulation only";
    public string SimulationBanner { get; } = PolicySimulationResult.SimulationOnlyLabel;

    public ApplicationListItem? SelectedApplication { get => _selectedApplication; set { if (SetField(ref _selectedApplication, value)) UpdateSimulation(); } }
    public string SearchText { get => _searchText; set { if (SetField(ref _searchText, value)) ApplyFilter(); } }
    public SimulatedConnectionType SelectedConnectionType { get => _selectedConnectionType; set { if (SetField(ref _selectedConnectionType, value)) UpdateSimulation(); } }
    public ProgramConnectionPolicy SelectedPolicy { get => _selectedPolicy; set { if (SetField(ref _selectedPolicy, value)) UpdateSimulation(); } }
    public ProtectionMode SelectedProfileMode { get => _selectedProfileMode; set { if (SetField(ref _selectedProfileMode, value)) UpdateSimulation(); } }
    public string NetworkSummary { get => _networkSummary; private set => SetField(ref _networkSummary, value); }
    public string NetworkTypeSummary { get => _networkTypeSummary; private set => SetField(ref _networkTypeSummary, value); }
    public string MeteredStatusSummary { get => _meteredStatusSummary; private set => SetField(ref _meteredStatusSummary, value); }
    public string FirewallSummary { get => _firewallSummary; private set => SetField(ref _firewallSummary, value); }
    public string DnsSummary { get => _dnsSummary; private set => SetField(ref _dnsSummary, value); }
    public string ApplicationCount { get => _applicationCount; private set => SetField(ref _applicationCount, value); }
    public string LastDiscovery { get => _lastDiscovery; private set => SetField(ref _lastDiscovery, value); }
    public string WarningCount { get => _warningCount; private set => SetField(ref _warningCount, value); }
    public string ActivitySummary { get => _activitySummary; private set => SetField(ref _activitySummary, value); }
    public string PowerSummary { get => _powerSummary; private set => SetField(ref _powerSummary, value); }
    public string SimulationDecision { get => _simulationDecision; private set => SetField(ref _simulationDecision, value); }
    public string SimulationReason { get => _simulationReason; private set => SetField(ref _simulationReason, value); }
    public string LastActionStatus { get => _lastActionStatus; private set => SetField(ref _lastActionStatus, value); }
    public string LicenseSummary { get => _licenseSummary; private set => SetField(ref _licenseSummary, value); }
    public string TraySummary { get => _traySummary; private set => SetField(ref _traySummary, value); }
    public bool IsRefreshing { get => _isRefreshing; private set { if (SetField(ref _isRefreshing, value)) RaiseCommandStates(); } }
    public bool IsNavigationCompact
    {
        get => _isNavigationCompact;
        internal set
        {
            if (SetField(ref _isNavigationCompact, value)) OnPropertyChanged(nameof(IsNavigationExpanded));
        }
    }
    public bool IsNavigationExpanded => !IsNavigationCompact;

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        _notifications.RefreshRequested += OnRefreshRequested;
        _notifications.Start();
        var license = await _licenseService.GetSnapshotAsync(cancellationToken).ConfigureAwait(true);
        LicenseSummary = license.DisplayStatus;
        var tray = await _systemTray.GetCapabilityAsync(cancellationToken).ConfigureAwait(true);
        TraySummary = tray.Message;
        await InitializeDnsFoundationAsync(cancellationToken).ConfigureAwait(true);
        await InitializeDnsRehearsalReadinessAsync(cancellationToken).ConfigureAwait(true);
        await RefreshAsync(false).ConfigureAwait(true);
        LogInitializedMessage(_logger, null);
    }

    public Task RefreshAfterResumeAsync() => RefreshAsync(false);

    public async Task ExportValidationDiagnosticAsync(string destinationPath, CancellationToken cancellationToken)
    {
        if (_bundle is null) throw new InvalidOperationException("Discovery must complete before diagnostic export.");
        await _diagnostics.ExportAsync(_bundle, destinationPath, cancellationToken).ConfigureAwait(true);
    }

    public void Dispose()
    {
        _notifications.RefreshRequested -= OnRefreshRequested;
        _refreshCancellation?.Cancel();
        _refreshCancellation?.Dispose();
        _refreshCancellation = null;
        GC.SuppressFinalize(this);
    }

    private async Task RefreshAsync(bool forceApplications)
    {
        if (IsRefreshing) return;
        _refreshCancellation?.Dispose();
        _refreshCancellation = new CancellationTokenSource();
        IsRefreshing = true;
        LastActionStatus = "Read-only discovery in progress…";
        try
        {
            var progress = new Progress<DiscoveryProgress>(item => LastActionStatus = item.Message);
            _bundle = await _discovery.RefreshAsync(forceApplications, progress, _refreshCancellation.Token).ConfigureAwait(true);
            UpdateFromBundle(_bundle);
            LastActionStatus = _bundle.WarningCount == 0 ? "Read-only discovery completed." : $"Discovery completed with {_bundle.WarningCount} warning(s).";
        }
        catch (OperationCanceledException) { LastActionStatus = "Discovery cancelled; no Windows setting was changed."; }
        finally { IsRefreshing = false; }
    }

    private Task CancelAsync()
    {
        _refreshCancellation?.Cancel();
        return Task.CompletedTask;
    }

    private async Task ClearCacheAsync()
    {
        await _discovery.ClearSafeCacheAsync(CancellationToken.None).ConfigureAwait(true);
        LastActionStatus = "Safe application discovery cache cleared.";
    }

    private async Task ExportDiagnosticsAsync()
    {
        if (_bundle is null) return;
        var directory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments), "QuietShield Diagnostics");
        var path = Path.Combine(directory, $"quietshield-diagnostic-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.json");
        await _diagnostics.ExportAsync(_bundle, path, CancellationToken.None).ConfigureAwait(true);
        LastActionStatus = $"Privacy-safe diagnostic summary exported to {path}";
    }

    private void UpdateFromBundle(ReadOnlyDiscoveryBundle bundle)
    {
        _allApplications.Clear();
        foreach (var app in bundle.Applications) _allApplications.Add(new ApplicationListItem(app));
        ApplyFilter();
        NetworkSummary = bundle.Network?.Summary ?? "Network discovery unavailable";
        NetworkTypeSummary = bundle.Network?.PrimaryKind.ToString() ?? "Unavailable";
        MeteredStatusSummary = bundle.Network?.Cost switch
        {
            ConnectionCostKind.Metered => "Metered",
            ConnectionCostKind.Unmetered => "Not metered",
            _ => "Unknown"
        };
        FirewallSummary = bundle.Firewall is null ? "Firewall discovery unavailable" :
            string.Join(", ", bundle.Firewall.Profiles.Select(static item => $"{item.Profile}: {(item.Enabled ? "On" : "Off")}")) + $"; QuietShield rules: {bundle.Firewall.QuietShieldOwnedRuleCount}";
        DnsSummary = bundle.Dns is null ? "DNS discovery unavailable" :
            $"{bundle.Dns.Adapters.Count} adapter configuration(s); encrypted DNS capability: {bundle.Dns.EncryptedDnsCapability}; QuietShield DNS Protection: {bundle.Dns.QuietShieldProtectionState}";
        ApplicationCount = bundle.Applications.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
        LastDiscovery = bundle.LastSuccessfulDiscoveryUtc?.ToLocalTime().ToString("G", System.Globalization.CultureInfo.CurrentCulture) ?? "Completed with warnings";
        WarningCount = bundle.WarningCount.ToString(System.Globalization.CultureInfo.InvariantCulture);
        ActivitySummary = string.Join(Environment.NewLine, bundle.Activity.Select(static item => $"{item.Stage}: {(item.Succeeded ? "Succeeded" : "Warning")} — {item.Message}"));
        PowerSummary = bundle.Power is null ? "Power discovery unavailable" : $"{bundle.Power.PowerSource}; battery {(bundle.Power.BatteryPercentage.HasValue ? bundle.Power.BatteryPercentage + "%" : "not reported")}; Battery Saver {FormatNullable(bundle.Power.IsBatterySaverActive)}";
        SelectedConnectionType = MapConnection(bundle.Network);
    }

    private void ApplyFilter()
    {
        var selectedId = SelectedApplication?.Id;
        Applications.Clear();
        var query = SearchText.Trim();
        foreach (var app in _allApplications.Where(app => string.IsNullOrWhiteSpace(query) ||
                     app.DisplayName.Contains(query, StringComparison.CurrentCultureIgnoreCase) ||
                     (app.Publisher?.Contains(query, StringComparison.CurrentCultureIgnoreCase) ?? false)))
        {
            Applications.Add(app);
        }
        SelectedApplication = Applications.FirstOrDefault(item => item.Id == selectedId) ?? Applications.FirstOrDefault();
    }

    private void UpdateSimulation()
    {
        UpdateProgramConnectionLockSimulation();
    }

    private async void OnRefreshRequested(object? sender, EventArgs args) => await RefreshAsync(false).ConfigureAwait(true);
    private static SimulatedConnectionType MapConnection(NetworkEnvironmentSnapshot? network) => network?.PrimaryKind switch
    {
        DetectedNetworkKind.WiFi => SimulatedConnectionType.WiFi,
        DetectedNetworkKind.Ethernet => SimulatedConnectionType.Ethernet,
        DetectedNetworkKind.Cellular => SimulatedConnectionType.Cellular,
        DetectedNetworkKind.VpnOrVirtual => SimulatedConnectionType.Vpn,
        _ => network?.Cost == ConnectionCostKind.Metered ? SimulatedConnectionType.Metered : network?.Cost == ConnectionCostKind.Unmetered ? SimulatedConnectionType.Unmetered : SimulatedConnectionType.Unknown
    };
    private static string FormatNullable(bool? value) => value.HasValue ? value.Value ? "On" : "Off" : "Unknown";
    private void RaiseCommandStates()
    {
        foreach (var command in new[] { RefreshCommand, CancelCommand, ClearCacheCommand, ExportDiagnosticsCommand }.OfType<AsyncRelayCommand>()) command.RaiseCanExecuteChanged();
        RaiseDnsCommandStates();
        RaiseDnsRuntimeCommandStates();
    }
    private bool SetField<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        OnPropertyChanged(name);
        return true;
    }
    private void OnPropertyChanged([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

}
