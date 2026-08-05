using QuietShield.Core.Results;

namespace QuietShield.Windows.Integration;

public sealed class DeferredInstalledApplicationDiscovery : IInstalledApplicationDiscovery
{
    public Task<OperationResult<IReadOnlyList<InstalledApplicationInfo>>> DiscoverAsync(CancellationToken cancellationToken) =>
        Deferred<IReadOnlyList<InstalledApplicationInfo>>("Installed-application enumeration is not implemented in the foundation.", cancellationToken);

    private static Task<OperationResult<T>> Deferred<T>(string message, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(OperationResult.NotImplemented<T>(message));
    }
}

public sealed class DeferredWin32ExecutableDiscovery : IWin32ExecutableDiscovery
{
    public Task<OperationResult<IReadOnlyList<Win32ExecutableInfo>>> DiscoverAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(OperationResult.NotImplemented<IReadOnlyList<Win32ExecutableInfo>>(
            "Win32 executable enumeration is not implemented in the foundation."));
    }
}

public sealed class DeferredStoreApplicationIdentityDiscovery : IStoreApplicationIdentityDiscovery
{
    public Task<OperationResult<IReadOnlyList<StoreApplicationIdentity>>> DiscoverAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(OperationResult.NotImplemented<IReadOnlyList<StoreApplicationIdentity>>(
            "Store application identity discovery is not implemented in the foundation."));
    }
}

public sealed class DeferredFirewallStateDiscovery : IFirewallStateDiscovery
{
    public Task<OperationResult<FirewallStateSnapshot>> DiscoverAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(OperationResult.NotImplemented<FirewallStateSnapshot>(
            "Firewall inspection is deferred; no firewall API was called."));
    }
}

public sealed class DeferredFilteringPlatformCapabilityDiscovery : IFilteringPlatformCapabilityDiscovery
{
    public Task<OperationResult<FilteringPlatformCapability>> DiscoverAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(OperationResult.Unsupported<FilteringPlatformCapability>(
            "Filtering-platform integration is an advanced phase and is not active."));
    }
}

public sealed class DeferredWindowsServiceStateDiscovery : IWindowsServiceStateDiscovery
{
    public Task<OperationResult<ServiceStateSnapshot>> DiscoverAsync(string serviceName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(OperationResult.NotImplemented<ServiceStateSnapshot>(
            $"Service-state discovery for '{serviceName}' is deferred; no service-control API was called."));
    }
}

public sealed class DeferredStartupCapabilityDiscovery : IStartupCapabilityDiscovery
{
    public Task<OperationResult<StartupCapabilitySnapshot>> DiscoverAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(OperationResult.Unsupported<StartupCapabilitySnapshot>(
            "Automatic startup is disabled in the foundation and no startup entry exists."));
    }
}

public sealed class DeferredNotificationCapabilityDiscovery : INotificationCapabilityDiscovery
{
    public Task<OperationResult<NotificationCapabilitySnapshot>> DiscoverAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(OperationResult.NotImplemented<NotificationCapabilitySnapshot>(
            "Native notifications are not implemented in the foundation."));
    }
}

public sealed class DeferredPowerStateDiscovery : IPowerStateDiscovery
{
    public Task<OperationResult<PowerStateSnapshot>> DiscoverAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(OperationResult.NotImplemented<PowerStateSnapshot>(
            "Battery and power-state discovery is not implemented in the foundation."));
    }
}

public sealed class FoundationSystemTrayService : ISystemTrayFoundation
{
    public Task<OperationResult<SystemTrayCapabilitySnapshot>> GetCapabilityAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var snapshot = new SystemTrayCapabilitySnapshot(
            false,
            false,
            "System tray integration is scaffolded but inactive; no startup registration was created.");
        return Task.FromResult(OperationResult.NotImplemented<SystemTrayCapabilitySnapshot>(snapshot.Status));
    }
}
