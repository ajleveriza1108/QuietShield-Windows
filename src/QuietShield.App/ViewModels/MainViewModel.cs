using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using QuietShield.Licensing;
using QuietShield.Windows.Integration;

namespace QuietShield.App.ViewModels;

public sealed partial class MainViewModel : INotifyPropertyChanged
{
    private readonly INetworkEnvironmentDiscovery _networkDiscovery;
    private readonly ILicenseService _licenseService;
    private readonly ISystemTrayFoundation _systemTray;
    private readonly ILogger<MainViewModel> _logger;
    private NavigationItem _selectedPage;
    private string _networkSummary = "Read-only detection pending";
    private string _licenseSummary = LicenseSnapshot.Foundation.DisplayStatus;
    private string _traySummary = "System tray foundation inactive";

    public MainViewModel(
        INetworkEnvironmentDiscovery networkDiscovery,
        ILicenseService licenseService,
        ISystemTrayFoundation systemTray,
        ILogger<MainViewModel> logger)
    {
        _networkDiscovery = networkDiscovery;
        _licenseService = licenseService;
        _systemTray = systemTray;
        _logger = logger;

        NavigationItems = new ObservableCollection<NavigationItem>
        {
            new("Dashboard", "Foundation status and safe read-only discovery", true),
            new("Protection", "Protection engine lifecycle and current state"),
            new("Program Connection Lock", "Per-program connection policies"),
            new("Protection Profiles", "Standard, High, Extreme, and Custom profiles"),
            new("Schedules", "Time-based protection profile activation"),
            new("Metered Data Watch", "Metered and cellular usage controls"),
            new("Aggressive Program Watch", "High-frequency program activity review"),
            new("Compatibility Guard", "Compatibility exclusions and recovery"),
            new("DNS Protection", "Encrypted DNS and blocking policy"),
            new("Allowlist and Blocklist", "Explicit program and destination policy"),
            new("Activity and Statistics", "Privacy-preserving validated activity"),
            new("Parent and Child Controls", "Parent-protected settings and approvals"),
            new("Private Browser", "Future isolated browsing surface"),
            new("File Safety", "Future local file safety workflows"),
            new("Licensing", "Universal three-device licence pool"),
            new("Updates", "Future signed update and rollback flow"),
            new("Settings", "Accessible application preferences")
        };

        _selectedPage = NavigationItems[0];
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    public ObservableCollection<NavigationItem> NavigationItems { get; }

    public NavigationItem SelectedPage
    {
        get => _selectedPage;
        set
        {
            if (Equals(_selectedPage, value))
            {
                return;
            }

            _selectedPage = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(IsDashboard));
            OnPropertyChanged(nameof(IsFeaturePage));
        }
    }

    public bool IsDashboard => SelectedPage.IsDashboard;

    public bool IsFeaturePage => !IsDashboard;

    public string VersionText { get; } = "Version 0.1.0 — Foundation";

    public string ProtectionState { get; } = "Foundation Mode / Protection Not Yet Activated";

    public string ActiveProfile { get; } = "Not configured";

    public string NetworkSummary
    {
        get => _networkSummary;
        private set => SetField(ref _networkSummary, value);
    }

    public string LicenseSummary
    {
        get => _licenseSummary;
        private set => SetField(ref _licenseSummary, value);
    }

    public string TraySummary
    {
        get => _traySummary;
        private set => SetField(ref _traySummary, value);
    }

    public async Task InitializeAsync(CancellationToken cancellationToken)
    {
        var network = await _networkDiscovery.DiscoverAsync(cancellationToken).ConfigureAwait(true);
        NetworkSummary = network.IsSuccess && network.Value is not null
            ? network.Value.Summary
            : network.Message;

        var license = await _licenseService.GetSnapshotAsync(cancellationToken).ConfigureAwait(true);
        LicenseSummary = license.DisplayStatus;

        var tray = await _systemTray.GetCapabilityAsync(cancellationToken).ConfigureAwait(true);
        TraySummary = tray.Message;

        LogInitialized(_logger);
    }

    private void SetField(ref string field, string value, [CallerMemberName] string? propertyName = null)
    {
        if (string.Equals(field, value, StringComparison.Ordinal))
        {
            return;
        }

        field = value;
        OnPropertyChanged(propertyName);
    }

    private void OnPropertyChanged([CallerMemberName] string? propertyName = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

    [LoggerMessage(
        EventId = 2001,
        Level = LogLevel.Information,
        Message = "QuietShield foundation dashboard initialized with protection engines inactive and read-only network discovery only.")]
    private static partial void LogInitialized(ILogger logger);
}
