namespace QuietShield.Windows.Integration;

public enum DetectedNetworkKind
{
    None,
    WiFi,
    Ethernet,
    Cellular,
    Other,
    Unknown
}

public enum ConnectionCostKind
{
    Metered,
    Unmetered,
    Unknown
}

public sealed record InstalledApplicationInfo(string DisplayName, string? Version, string Source);

public sealed record Win32ExecutableInfo(string DisplayName, string ExecutablePath);

public sealed record StoreApplicationIdentity(string DisplayName, string PackageFamilyName);

public sealed record NetworkAdapterInfo(
    string Id,
    string Name,
    string Description,
    DetectedNetworkKind Kind,
    bool IsOperational,
    ConnectionCostKind Cost);

public sealed record NetworkEnvironmentSnapshot(
    DetectedNetworkKind PrimaryKind,
    ConnectionCostKind Cost,
    IReadOnlyList<NetworkAdapterInfo> Adapters,
    string Summary);

public sealed record DnsAdapterConfiguration(
    string AdapterId,
    string AdapterName,
    IReadOnlyList<string> ServerAddresses);

public sealed record DnsConfigurationSnapshot(IReadOnlyList<DnsAdapterConfiguration> Adapters);

public sealed record FirewallStateSnapshot(string Status);

public sealed record FilteringPlatformCapability(string Status);

public sealed record ServiceStateSnapshot(string ServiceName, string Status);

public sealed record StartupCapabilitySnapshot(bool CanRegister, string Status);

public sealed record NotificationCapabilitySnapshot(bool IsAvailable, string Status);

public sealed record PowerStateSnapshot(string PowerSource, int? BatteryPercentage);

public sealed record SystemTrayCapabilitySnapshot(bool IsAvailable, bool IsActive, string Status);
