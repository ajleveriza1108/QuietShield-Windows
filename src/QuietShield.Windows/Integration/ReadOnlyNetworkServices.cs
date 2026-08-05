using System.Net.NetworkInformation;
using QuietShield.Core.Results;

namespace QuietShield.Windows.Integration;

public sealed class ReadOnlyNetworkEnvironmentDiscovery : INetworkEnvironmentDiscovery
{
    public Task<OperationResult<NetworkEnvironmentSnapshot>> DiscoverAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var adapters = NetworkInterface.GetAllNetworkInterfaces()
                .Select(static adapter => new NetworkAdapterInfo(
                    adapter.Id,
                    adapter.Name,
                    adapter.Description,
                    MapKind(adapter.NetworkInterfaceType),
                    adapter.OperationalStatus == OperationalStatus.Up,
                    ConnectionCostKind.Unknown))
                .OrderByDescending(static adapter => adapter.IsOperational)
                .ThenBy(static adapter => adapter.Name, StringComparer.CurrentCultureIgnoreCase)
                .ToArray();

            var primary = adapters.FirstOrDefault(static adapter => adapter.IsOperational);
            var primaryKind = primary?.Kind ?? DetectedNetworkKind.None;
            var summary = primary is null
                ? "No operational network adapter was detected."
                : $"{DisplayKind(primaryKind)} detected (cost classification not implemented).";

            var snapshot = new NetworkEnvironmentSnapshot(
                primaryKind,
                ConnectionCostKind.Unknown,
                adapters,
                summary);

            return Task.FromResult(OperationResult.Success(
                snapshot,
                "Read-only adapter discovery completed; no network setting was changed."));
        }
        catch (NetworkInformationException exception)
        {
            return Task.FromResult(OperationResult.Failure<NetworkEnvironmentSnapshot>(
                $"Read-only network discovery failed: {exception.Message}"));
        }
    }

    private static DetectedNetworkKind MapKind(NetworkInterfaceType type) => type switch
    {
        NetworkInterfaceType.Wireless80211 => DetectedNetworkKind.WiFi,
        NetworkInterfaceType.Ethernet => DetectedNetworkKind.Ethernet,
        NetworkInterfaceType.Ethernet3Megabit => DetectedNetworkKind.Ethernet,
        NetworkInterfaceType.FastEthernetFx => DetectedNetworkKind.Ethernet,
        NetworkInterfaceType.FastEthernetT => DetectedNetworkKind.Ethernet,
        NetworkInterfaceType.GigabitEthernet => DetectedNetworkKind.Ethernet,
        NetworkInterfaceType.Wman => DetectedNetworkKind.Cellular,
        NetworkInterfaceType.Wwanpp => DetectedNetworkKind.Cellular,
        NetworkInterfaceType.Wwanpp2 => DetectedNetworkKind.Cellular,
        NetworkInterfaceType.Unknown => DetectedNetworkKind.Unknown,
        _ => DetectedNetworkKind.Other
    };

    private static string DisplayKind(DetectedNetworkKind kind) => kind switch
    {
        DetectedNetworkKind.WiFi => "Wi-Fi",
        DetectedNetworkKind.Ethernet => "Ethernet",
        DetectedNetworkKind.Cellular => "Cellular",
        DetectedNetworkKind.Other => "Other network",
        DetectedNetworkKind.None => "No network",
        _ => "Unknown network"
    };
}

public sealed class ReadOnlyDnsConfigurationDiscovery : IDnsConfigurationDiscovery
{
    public Task<OperationResult<DnsConfigurationSnapshot>> DiscoverAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var configurations = NetworkInterface.GetAllNetworkInterfaces()
                .Select(static adapter => new DnsAdapterConfiguration(
                    adapter.Id,
                    adapter.Name,
                    adapter.GetIPProperties().DnsAddresses
                        .Select(static address => address.ToString())
                        .ToArray()))
                .ToArray();

            return Task.FromResult(OperationResult.Success(
                new DnsConfigurationSnapshot(configurations),
                "Read-only DNS discovery completed; DNS configuration was not changed."));
        }
        catch (NetworkInformationException exception)
        {
            return Task.FromResult(OperationResult.Failure<DnsConfigurationSnapshot>(
                $"Read-only DNS discovery failed: {exception.Message}"));
        }
    }
}
