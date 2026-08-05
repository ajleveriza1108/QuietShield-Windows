using QuietShield.Core.Results;

namespace QuietShield.Windows.Integration;

public interface IInstalledApplicationDiscovery
{
    Task<OperationResult<IReadOnlyList<InstalledApplicationInfo>>> DiscoverAsync(CancellationToken cancellationToken);
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
    Task<OperationResult<ServiceStateSnapshot>> DiscoverAsync(string serviceName, CancellationToken cancellationToken);
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

public interface ITransactionalWindowsChange<in TPlan, TBackup>
{
    Task<OperationResult> PreflightAsync(TPlan plan, CancellationToken cancellationToken);

    Task<OperationResult<TBackup>> BackupAsync(TPlan plan, CancellationToken cancellationToken);

    Task<OperationResult> ApplyAsync(TPlan plan, TBackup backup, CancellationToken cancellationToken);

    Task<OperationResult> VerifyAsync(TPlan plan, CancellationToken cancellationToken);

    Task<OperationResult> RollbackAsync(TPlan plan, TBackup backup, CancellationToken cancellationToken);

    Task<OperationResult> RecoverLastKnownGoodAsync(CancellationToken cancellationToken);
}
