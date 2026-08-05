using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Win32;
using QuietShield.Core.Results;
using QuietShield.Windows.Integration;

namespace QuietShield.Windows.Discovery;

public sealed class ReadOnlyNetworkEnvironmentDiscovery : INetworkEnvironmentDiscovery
{
    private const string ProfileScript = "$cost='Unknown'; try { $p=[Windows.Networking.Connectivity.NetworkInformation,Windows,ContentType=WindowsRuntime]::GetInternetConnectionProfile(); if($null-ne $p){$cost=$p.GetConnectionCost().NetworkCostType.ToString()} } catch {}; $profiles=@(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ InterfaceIndex=[int]$_.InterfaceIndex; Category=$_.NetworkCategory.ToString() } }); [pscustomobject]@{ Cost=$cost; Profiles=$profiles } | ConvertTo-Json -Depth 4 -Compress";
    private readonly IPowerShellJsonRunner _runner;

    public ReadOnlyNetworkEnvironmentDiscovery() : this(new PowerShellJsonRunner()) { }

    public ReadOnlyNetworkEnvironmentDiscovery(IPowerShellJsonRunner runner) => _runner = runner;

    public async Task<OperationResult<NetworkEnvironmentSnapshot>> DiscoverAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var metadata = await ReadMetadataAsync(cancellationToken).ConfigureAwait(false);
            var adapters = new List<NetworkAdapterInfo>();
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var properties = TryGetProperties(adapter);
                var index = TryGetInterfaceIndex(properties);
                var kind = NetworkClassification.MapKind(adapter.NetworkInterfaceType, adapter.Name, adapter.Description);
                var isOperational = adapter.OperationalStatus == OperationalStatus.Up;
                var hasDefaultRoute = HasDefaultRoute(properties);
                var category = metadata.Categories.TryGetValue(index, out var value) ? value : NetworkCategoryKind.Unknown;

                adapters.Add(new NetworkAdapterInfo(
                    adapter.Id,
                    index,
                    adapter.Name,
                    adapter.Description,
                    kind,
                    isOperational,
                    HasAddressFamily(properties, AddressFamily.InterNetwork),
                    HasAddressFamily(properties, AddressFamily.InterNetworkV6),
                    hasDefaultRoute,
                    kind == DetectedNetworkKind.VpnOrVirtual,
                    isOperational ? metadata.Cost : ConnectionCostKind.Unknown,
                    category));
            }

            var ordered = adapters.OrderByDescending(static item => item.IsOperational && item.HasDefaultRoute)
                .ThenByDescending(static item => item.IsOperational)
                .ThenBy(static item => item.Name, StringComparer.CurrentCultureIgnoreCase)
                .ToArray();
            var primary = ordered.FirstOrDefault(static item => item.IsOperational && item.HasDefaultRoute)
                          ?? ordered.FirstOrDefault(static item => item.IsOperational);
            var snapshot = new NetworkEnvironmentSnapshot(
                primary?.Kind ?? DetectedNetworkKind.None,
                primary?.Cost ?? ConnectionCostKind.Unknown,
                primary?.Category ?? NetworkCategoryKind.Unknown,
                primary?.HasDefaultRoute == true,
                ordered,
                CreateSummary(primary),
                DateTimeOffset.UtcNow);
            return OperationResult.Success(snapshot, "Read-only network discovery completed; no adapter or metered setting was changed.");
        }
        catch (OperationCanceledException) { throw; }
        catch (NetworkInformationException exception)
        {
            return OperationResult.Failure<NetworkEnvironmentSnapshot>($"Read-only network discovery failed: {exception.Message}");
        }
        catch (JsonException exception)
        {
            return OperationResult.Failure<NetworkEnvironmentSnapshot>($"Read-only network metadata could not be parsed: {exception.Message}");
        }
    }

    private async Task<NetworkMetadata> ReadMetadataAsync(CancellationToken cancellationToken)
    {
        var result = await _runner.RunAsync(ProfileScript, cancellationToken).ConfigureAwait(false);
        if (result.ExitCode != 0 || string.IsNullOrWhiteSpace(result.StandardOutput)) return NetworkMetadata.Empty;
        using var document = JsonDocument.Parse(result.StandardOutput);
        var root = document.RootElement;
        var cost = root.TryGetProperty("Cost", out var costElement)
            ? NetworkClassification.MapCost(costElement.GetString())
            : ConnectionCostKind.Unknown;
        var categories = new Dictionary<int, NetworkCategoryKind>();
        if (root.TryGetProperty("Profiles", out var profiles))
        {
            var sequence = profiles.ValueKind == JsonValueKind.Array ? profiles.EnumerateArray().ToArray() : new[] { profiles };
            foreach (var profile in sequence)
            {
                if (profile.TryGetProperty("InterfaceIndex", out var index) && index.TryGetInt32(out var number))
                {
                    categories[number] = profile.TryGetProperty("Category", out var category)
                        ? NetworkClassification.MapCategory(category.GetString())
                        : NetworkCategoryKind.Unknown;
                }
            }
        }

        return new NetworkMetadata(cost, categories);
    }

    private static IPInterfaceProperties? TryGetProperties(NetworkInterface adapter)
    {
        try { return adapter.GetIPProperties(); }
        catch (NetworkInformationException) { return null; }
    }

    private static int TryGetInterfaceIndex(IPInterfaceProperties? properties)
    {
        try { return properties?.GetIPv4Properties()?.Index ?? properties?.GetIPv6Properties()?.Index ?? -1; }
        catch (NetworkInformationException) { return -1; }
    }

    private static bool HasDefaultRoute(IPInterfaceProperties? properties)
    {
        try
        {
            return properties?.GatewayAddresses.Any(static gateway =>
                !gateway.Address.Equals(IPAddress.Any) && !gateway.Address.Equals(IPAddress.IPv6Any)) == true;
        }
        catch (NetworkInformationException) { return false; }
    }

    private static bool HasAddressFamily(IPInterfaceProperties? properties, AddressFamily family)
    {
        try { return properties?.UnicastAddresses.Any(address => address.Address.AddressFamily == family) == true; }
        catch (NetworkInformationException) { return false; }
    }

    private static string CreateSummary(NetworkAdapterInfo? primary) => primary is null
        ? "No operational network adapter was detected."
        : $"{NetworkClassification.DisplayKind(primary.Kind)}; {primary.Cost}; {primary.Category}; default route {(primary.HasDefaultRoute ? "present" : "not detected")}.";

    private sealed record NetworkMetadata(ConnectionCostKind Cost, IReadOnlyDictionary<int, NetworkCategoryKind> Categories)
    {
        public static NetworkMetadata Empty { get; } = new(ConnectionCostKind.Unknown, new Dictionary<int, NetworkCategoryKind>());
    }
}

public static class NetworkClassification
{
    public static DetectedNetworkKind MapKind(NetworkInterfaceType type, string name, string description)
    {
        var identity = $"{name} {description}";
        if (type is NetworkInterfaceType.Ppp or NetworkInterfaceType.Tunnel ||
            ContainsAny(identity, "VPN", "VIRTUAL", "HYPER-V", "VMWARE", "VBOX", "WIREGUARD", "TAP", "TUNNEL"))
        {
            return DetectedNetworkKind.VpnOrVirtual;
        }

        return type switch
        {
            NetworkInterfaceType.Wireless80211 => DetectedNetworkKind.WiFi,
            NetworkInterfaceType.Ethernet or NetworkInterfaceType.Ethernet3Megabit or NetworkInterfaceType.FastEthernetFx or
                NetworkInterfaceType.FastEthernetT or NetworkInterfaceType.GigabitEthernet => DetectedNetworkKind.Ethernet,
            NetworkInterfaceType.Wman or NetworkInterfaceType.Wwanpp or NetworkInterfaceType.Wwanpp2 => DetectedNetworkKind.Cellular,
            NetworkInterfaceType.Unknown => DetectedNetworkKind.Unknown,
            _ => DetectedNetworkKind.Other
        };
    }

    public static ConnectionCostKind MapCost(string? value) => value?.Trim().ToUpperInvariant() switch
    {
        "UNRESTRICTED" => ConnectionCostKind.Unmetered,
        "FIXED" or "VARIABLE" or "OVERCOSTED" => ConnectionCostKind.Metered,
        _ => ConnectionCostKind.Unknown
    };

    public static NetworkCategoryKind MapCategory(string? value) => value?.Trim().ToUpperInvariant() switch
    {
        "PUBLIC" => NetworkCategoryKind.Public,
        "PRIVATE" => NetworkCategoryKind.Private,
        "DOMAINAUTHENTICATED" => NetworkCategoryKind.DomainAuthenticated,
        _ => NetworkCategoryKind.Unknown
    };

    public static string DisplayKind(DetectedNetworkKind kind) => kind switch
    {
        DetectedNetworkKind.WiFi => "Wi-Fi",
        DetectedNetworkKind.Ethernet => "Ethernet",
        DetectedNetworkKind.Cellular => "Cellular",
        DetectedNetworkKind.VpnOrVirtual => "VPN or virtual adapter",
        DetectedNetworkKind.Other => "Other network",
        DetectedNetworkKind.None => "No network",
        _ => "Unknown network"
    };

    private static bool ContainsAny(string value, params string[] fragments) =>
        fragments.Any(fragment => value.Contains(fragment, StringComparison.OrdinalIgnoreCase));
}

public sealed class ReadOnlyDnsConfigurationDiscovery : IDnsConfigurationDiscovery
{
    private const string EncryptedDnsCapabilityScript = "if(Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue){'Available'}else{'Unknown'}";
    private readonly IPowerShellJsonRunner _runner;

    public ReadOnlyDnsConfigurationDiscovery() : this(new PowerShellJsonRunner()) { }

    public ReadOnlyDnsConfigurationDiscovery(IPowerShellJsonRunner runner) => _runner = runner;

    public async Task<OperationResult<DnsConfigurationSnapshot>> DiscoverAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var configurations = new List<DnsAdapterConfiguration>();
            foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var properties = adapter.GetIPProperties();
                var servers = properties.DnsAddresses.Select(static address => new DnsServerInfo(
                    address.AddressFamily == AddressFamily.InterNetwork ? DnsAddressFamilyKind.Ipv4 :
                    address.AddressFamily == AddressFamily.InterNetworkV6 ? DnsAddressFamilyKind.Ipv6 : DnsAddressFamilyKind.Unknown,
                    address.ToString())).ToArray();
                configurations.Add(new DnsAdapterConfiguration(adapter.Id, adapter.Name, DetermineMode(adapter.Id), servers));
            }

            var capabilityResult = await _runner.RunAsync(EncryptedDnsCapabilityScript, cancellationToken).ConfigureAwait(false);
            var capability = capabilityResult.ExitCode == 0 && capabilityResult.StandardOutput.Trim().Equals("Available", StringComparison.OrdinalIgnoreCase)
                ? EncryptedDnsCapabilityKind.Available : EncryptedDnsCapabilityKind.Unknown;
            var snapshot = new DnsConfigurationSnapshot(configurations, capability, "Not active", DateTimeOffset.UtcNow);
            return OperationResult.Success(snapshot, "Read-only DNS discovery completed; DNS configuration was not changed.");
        }
        catch (OperationCanceledException) { throw; }
        catch (NetworkInformationException exception)
        {
            return OperationResult.Failure<DnsConfigurationSnapshot>($"Read-only DNS discovery failed: {exception.Message}");
        }
    }

    public static DnsConfigurationMode DetermineMode(bool hasManualServers, bool hasDhcpServers) => (hasManualServers, hasDhcpServers) switch
    {
        (true, true) => DnsConfigurationMode.Mixed,
        (true, false) => DnsConfigurationMode.Manual,
        (false, true) => DnsConfigurationMode.Automatic,
        _ => DnsConfigurationMode.Unknown
    };

    private static DnsConfigurationMode DetermineMode(string adapterId)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey($@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{adapterId}", false);
            var manual = key?.GetValue("NameServer") as string;
            var automatic = key?.GetValue("DhcpNameServer") as string;
            return DetermineMode(!string.IsNullOrWhiteSpace(manual), !string.IsNullOrWhiteSpace(automatic));
        }
        catch (UnauthorizedAccessException) { return DnsConfigurationMode.Unknown; }
        catch (System.Security.SecurityException) { return DnsConfigurationMode.Unknown; }
    }
}
