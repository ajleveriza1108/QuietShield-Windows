namespace QuietShield.Licensing;

public sealed class FoundationLicenseService : ILicenseService
{
    public Task<LicenseSnapshot> GetSnapshotAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(LicenseSnapshot.Foundation);
    }
}

public sealed class UnsupportedLicenseRefreshService : ILicenseRefreshService
{
    public Task<LicensingResult> RefreshAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(LicensingResult.NotImplemented(
            "Licence server communication is deferred; no request was sent."));
    }
}
