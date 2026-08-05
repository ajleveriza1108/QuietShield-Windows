namespace QuietShield.Licensing;

public enum LicensingOperationStatus
{
    Succeeded,
    NotImplemented,
    Unsupported,
    Failed
}

public sealed record LicensingResult(LicensingOperationStatus Status, string Message)
{
    public bool IsSuccess => Status == LicensingOperationStatus.Succeeded;

    public static LicensingResult NotImplemented(string message) =>
        new(LicensingOperationStatus.NotImplemented, message);
}

public interface ILicenseService
{
    Task<LicenseSnapshot> GetSnapshotAsync(CancellationToken cancellationToken);
}

public interface IDeviceManagementService
{
    Task<IReadOnlyList<LicensedDevice>> GetDevicesAsync(CancellationToken cancellationToken);

    Task<LicensingResult> DeactivateDeviceAsync(string opaqueDeviceId, CancellationToken cancellationToken);
}

public interface ILicenseRefreshService
{
    Task<LicensingResult> RefreshAsync(CancellationToken cancellationToken);
}

public interface IDeviceIdentityProvider
{
    Task<LicensingResult> EnsureStableOpaqueIdentityAsync(CancellationToken cancellationToken);
}

public interface ISecureTokenStore
{
    Task<LicensingResult> StoreAsync(string logicalName, ReadOnlyMemory<byte> protectedToken, CancellationToken cancellationToken);

    Task<(LicensingResult Result, ReadOnlyMemory<byte> ProtectedToken)> RetrieveAsync(
        string logicalName,
        CancellationToken cancellationToken);

    Task<LicensingResult> RemoveAsync(string logicalName, CancellationToken cancellationToken);
}
