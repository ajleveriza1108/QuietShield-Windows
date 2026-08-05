namespace QuietShield.Windows.Integration;

public enum InstalledApplicationType
{
    Win32,
    MicrosoftStoreOrMsix,
    SystemComponent,
    Unknown
}

public sealed record ApplicationIconReference(string SourcePath, int ResourceIndex);

public sealed record InstalledApplicationInfo(
    string Id,
    string DisplayName,
    string? Publisher,
    string? Version,
    string? InstallLocation,
    string? MainExecutablePath,
    InstalledApplicationType ApplicationType,
    ApplicationIconReference? Icon,
    bool ExecutableExists,
    bool IsWindowsSystemComponent,
    IReadOnlyList<string> DiscoverySources);

public sealed record Win32ExecutableInfo(
    string DisplayName,
    string ExecutablePath,
    bool Exists,
    ApplicationIconReference? Icon);

public sealed record StoreApplicationIdentity(
    string PackageFamilyName,
    string PackageFullName,
    string DisplayName,
    string? Publisher,
    string? Version,
    string? InstallLocation,
    bool IsFramework,
    bool IsResourcePackage,
    bool IsNonRemovable);

public sealed record DiscoveryProgress(string Stage, int Completed, int Total, string Message);

public enum DetectedNetworkKind
{
    None,
    WiFi,
    Ethernet,
    Cellular,
    VpnOrVirtual,
    Other,
    Unknown
}

public enum ConnectionCostKind
{
    Metered,
    Unmetered,
    Unknown
}

public enum NetworkCategoryKind
{
    Public,
    Private,
    DomainAuthenticated,
    Unknown
}

public sealed record NetworkAdapterInfo(
    string Id,
    int InterfaceIndex,
    string Name,
    string Description,
    DetectedNetworkKind Kind,
    bool IsOperational,
    bool HasIpv4,
    bool HasIpv6,
    bool HasDefaultRoute,
    bool IsVpnOrVirtual,
    ConnectionCostKind Cost,
    NetworkCategoryKind Category);

public sealed record NetworkEnvironmentSnapshot(
    DetectedNetworkKind PrimaryKind,
    ConnectionCostKind Cost,
    NetworkCategoryKind Category,
    bool HasDefaultRoute,
    IReadOnlyList<NetworkAdapterInfo> Adapters,
    string Summary,
    DateTimeOffset DetectedAtUtc);

public enum DnsAddressFamilyKind
{
    Ipv4,
    Ipv6,
    Unknown
}

public enum DnsConfigurationMode
{
    Automatic,
    Manual,
    Mixed,
    Unknown
}

public enum EncryptedDnsCapabilityKind
{
    Available,
    Unavailable,
    Unknown
}

public sealed record DnsServerInfo(DnsAddressFamilyKind AddressFamily, string Address);

public sealed record DnsAdapterConfiguration(
    string AdapterId,
    string AdapterName,
    DnsConfigurationMode Mode,
    IReadOnlyList<DnsServerInfo> Servers);

public sealed record DnsConfigurationSnapshot(
    IReadOnlyList<DnsAdapterConfiguration> Adapters,
    EncryptedDnsCapabilityKind EncryptedDnsCapability,
    string QuietShieldProtectionState,
    DateTimeOffset DetectedAtUtc);

public enum FirewallProfileKind
{
    Domain,
    Private,
    Public
}

public sealed record FirewallProfileState(FirewallProfileKind Profile, bool Enabled);

public sealed record FirewallStateSnapshot(
    bool ServiceAvailable,
    IReadOnlyList<FirewallProfileState> Profiles,
    int QuietShieldOwnedRuleCount,
    DateTimeOffset DetectedAtUtc);

public sealed record FilteringPlatformCapability(
    bool UserModeApiAvailable,
    bool FutureChangesRequireElevation,
    bool QuietShieldProviderExists,
    bool QuietShieldSublayerExists,
    int QuietShieldFilterCount,
    bool QuietShieldCalloutDriverExists,
    string Status);

public sealed record ServiceStateInfo(string ServiceName, bool Registered, bool Running, string Status);

public sealed record ServiceStateSnapshot(
    ServiceStateInfo QuietShieldService,
    ServiceStateInfo BaseFilteringEngine,
    ServiceStateInfo WindowsFirewall,
    ServiceStateInfo NetworkList,
    DateTimeOffset DetectedAtUtc);

public sealed record StartupCapabilitySnapshot(bool CanRegister, string Status);

public sealed record NotificationCapabilitySnapshot(bool IsAvailable, string Status);

public sealed record PowerStateSnapshot(
    bool IsAcConnected,
    bool IsBatteryPresent,
    int? BatteryPercentage,
    bool? IsBatterySaverActive,
    string PowerSource,
    DateTimeOffset DetectedAtUtc);

public sealed record SystemTrayCapabilitySnapshot(bool IsAvailable, bool IsActive, string Status);

public sealed record DiscoveryActivity(
    DateTimeOffset OccurredAtUtc,
    string Stage,
    bool Succeeded,
    string Message);

public sealed record ReadOnlyDiscoveryBundle(
    IReadOnlyList<InstalledApplicationInfo> Applications,
    NetworkEnvironmentSnapshot? Network,
    DnsConfigurationSnapshot? Dns,
    FirewallStateSnapshot? Firewall,
    FilteringPlatformCapability? FilteringPlatform,
    ServiceStateSnapshot? Services,
    PowerStateSnapshot? Power,
    IReadOnlyList<DiscoveryActivity> Activity,
    DateTimeOffset? LastSuccessfulDiscoveryUtc,
    int WarningCount,
    bool UsedApplicationCache);
