using QuietShield.Core.Results;
using QuietShield.Windows.Integration;
using System.Text.Json;

namespace QuietShield.Windows.Discovery;

public sealed class ReadOnlyDiscoveryCoordinator : IReadOnlyDiscoveryCoordinator
{
    private readonly IApplicationInventoryService _applications;
    private readonly INetworkEnvironmentDiscovery _network;
    private readonly IDnsConfigurationDiscovery _dns;
    private readonly IFirewallStateDiscovery _firewall;
    private readonly IFilteringPlatformCapabilityDiscovery _wfp;
    private readonly IWindowsServiceStateDiscovery _services;
    private readonly IPowerStateDiscovery _power;

    public ReadOnlyDiscoveryCoordinator(
        IApplicationInventoryService applications,
        INetworkEnvironmentDiscovery network,
        IDnsConfigurationDiscovery dns,
        IFirewallStateDiscovery firewall,
        IFilteringPlatformCapabilityDiscovery wfp,
        IWindowsServiceStateDiscovery services,
        IPowerStateDiscovery power)
    {
        _applications = applications;
        _network = network;
        _dns = dns;
        _firewall = firewall;
        _wfp = wfp;
        _services = services;
        _power = power;
    }

    public async Task<ReadOnlyDiscoveryBundle> RefreshAsync(bool forceApplicationRefresh, IProgress<DiscoveryProgress>? progress, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var applicationTask = SafeAsync(() => _applications.DiscoverAsync(forceApplicationRefresh, progress, cancellationToken), "Application inventory");
        var networkTask = SafeAsync(() => _network.DiscoverAsync(cancellationToken), "Network discovery");
        var dnsTask = SafeAsync(() => _dns.DiscoverAsync(cancellationToken), "DNS discovery");
        var firewallTask = SafeAsync(() => _firewall.DiscoverAsync(cancellationToken), "Firewall discovery");
        var wfpTask = SafeAsync(() => _wfp.DiscoverAsync(cancellationToken), "WFP discovery");
        var servicesTask = SafeAsync(() => _services.DiscoverAsync(cancellationToken), "Service discovery");
        var powerTask = SafeAsync(() => _power.DiscoverAsync(cancellationToken), "Power discovery");
        await Task.WhenAll(applicationTask, networkTask, dnsTask, firewallTask, wfpTask, servicesTask, powerTask).ConfigureAwait(false);

        var applications = await applicationTask.ConfigureAwait(false);
        var network = await networkTask.ConfigureAwait(false);
        var dns = await dnsTask.ConfigureAwait(false);
        var firewall = await firewallTask.ConfigureAwait(false);
        var wfp = await wfpTask.ConfigureAwait(false);
        var services = await servicesTask.ConfigureAwait(false);
        var power = await powerTask.ConfigureAwait(false);
        var outcomes = new IOutcome[]
        {
            Outcome.Create("Applications", applications), Outcome.Create("Network", network), Outcome.Create("DNS", dns),
            Outcome.Create("Firewall", firewall), Outcome.Create("WFP", wfp), Outcome.Create("Services", services), Outcome.Create("Power", power)
        };
        var activities = outcomes.Select(static outcome => new DiscoveryActivity(DateTimeOffset.UtcNow, outcome.Stage, outcome.Succeeded, outcome.Message)).ToArray();
        var allSucceeded = outcomes.All(static outcome => outcome.Succeeded);

        return new ReadOnlyDiscoveryBundle(
            applications.Value ?? Array.Empty<InstalledApplicationInfo>(),
            network.Value,
            dns.Value,
            firewall.Value,
            wfp.Value,
            services.Value,
            power.Value,
            activities,
            allSucceeded ? DateTimeOffset.UtcNow : null,
            outcomes.Count(static outcome => !outcome.Succeeded),
            _applications.LastResultUsedCache);
    }

    public Task ClearSafeCacheAsync(CancellationToken cancellationToken) => _applications.ClearCacheAsync(cancellationToken);

    private static async Task<OperationResult<T>> SafeAsync<T>(Func<Task<OperationResult<T>>> action, string stage)
    {
        try { return await action().ConfigureAwait(false); }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidOperationException or JsonException)
        {
            return OperationResult.Failure<T>($"{stage} failed: {exception.Message}");
        }
    }

    private interface IOutcome
    {
        string Stage { get; }
        bool Succeeded { get; }
        string Message { get; }
    }

    private sealed record Outcome(string Stage, bool Succeeded, string Message) : IOutcome
    {
        public static Outcome Create<T>(string stage, OperationResult<T> result) => new(stage, result.IsSuccess, result.Message);
    }
}
