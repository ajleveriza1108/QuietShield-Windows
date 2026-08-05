using QuietShield.Core.Results;

namespace QuietShield.Windows.Integration;

public interface IInstalledApplicationDiscovery
{
    Task<OperationResult<IReadOnlyList<InstalledApplicationInfo>>> DiscoverAsync(CancellationToken cancellationToken);
}

public interface IApplicationInventoryService
{
    bool LastResultUsedCache { get; }

    Task<OperationResult<IReadOnlyList<InstalledApplicationInfo>>> DiscoverAsync(
        bool forceRefresh,
        IProgress<DiscoveryProgress>? progress,
        CancellationToken cancellationToken);

    Task ClearCacheAsync(CancellationToken cancellationToken);
}

public interface IWin32ExecutableDiscovery
{
    Task<OperationResult<IReadOnlyList<Win32ExecutableInfo>>> DiscoverAsync(CancellationToken cancellationToken);
}

public interface IStoreApplicationIdentityDiscovery
{
    Task<OperationResult<IReadOnlyList<StoreApplicationIdentity>>> DiscoverAsync(CancellationToken cancellationToken);
}

public interface INetworkEnvironmentDiscovery
{
    Task<OperationResult<NetworkEnvironmentSnapshot>> DiscoverAsync(CancellationToken cancellationToken);
}

public interface IDnsConfigurationDiscovery
{
    Task<OperationResult<DnsConfigurationSnapshot>> DiscoverAsync(CancellationToken cancellationToken);
}

public interface IFirewallStateDiscovery
{
    Task<OperationResult<FirewallStateSnapshot>> DiscoverAsync(CancellationToken cancellationToken);
}

public interface IFilteringPlatformCapabilityDiscovery
{
    Task<OperationResult<FilteringPlatformCapability>> DiscoverAsync(CancellationToken cancellationToken);
}

public interface IWindowsServiceStateDiscovery
{
    Task<OperationResult<ServiceStateSnapshot>> DiscoverAsync(CancellationToken cancellationToken);
}

public interface IStartupCapabilityDiscovery
{
    Task<OperationResult<StartupCapabilitySnapshot>> DiscoverAsync(CancellationToken cancellationToken);
}

public interface INotificationCapabilityDiscovery
{
    Task<OperationResult<NotificationCapabilitySnapshot>> DiscoverAsync(CancellationToken cancellationToken);
}

public interface IPowerStateDiscovery
{
    Task<OperationResult<PowerStateSnapshot>> DiscoverAsync(CancellationToken cancellationToken);
}

public interface ISystemTrayFoundation
{
    Task<OperationResult<SystemTrayCapabilitySnapshot>> GetCapabilityAsync(CancellationToken cancellationToken);
}

public interface IReadOnlyDiscoveryCoordinator
{
    Task<ReadOnlyDiscoveryBundle> RefreshAsync(
        bool forceApplicationRefresh,
        IProgress<DiscoveryProgress>? progress,
        CancellationToken cancellationToken);

    Task ClearSafeCacheAsync(CancellationToken cancellationToken);
}

public interface INetworkRefreshNotificationSource : IDisposable
{
    event EventHandler? RefreshRequested;

    void Start();
}

public interface ITransactionalWindowsChange<in TPlan, TBackup>
{
    Task<OperationResult> PreflightAsync(TPlan plan, CancellationToken cancellationToken);

    Task<OperationResult<TBackup>> BackupAsync(TPlan plan, CancellationToken cancellationToken);

    Task<OperationResult> ApplyAsync(TPlan plan, TBackup backup, CancellationToken cancellationToken);

    Task<OperationResult> VerifyAsync(TPlan plan, CancellationToken cancellationToken);

    Task<OperationResult> RollbackAsync(TPlan plan, TBackup backup, CancellationToken cancellationToken);

    Task<OperationResult> RecoverLastKnownGoodAsync(CancellationToken cancellationToken);
}
