using QuietShield.Core.Results;
using QuietShield.Windows.Discovery;
using QuietShield.Windows.Integration;

namespace QuietShield.Windows.Tests;

[TestClass]
public sealed class ReadOnlyWindowsServiceTests
{
    private static readonly string[] TransactionMethodNames =
    {
        "PreflightAsync",
        "BackupAsync",
        "ApplyAsync",
        "VerifyAsync",
        "RollbackAsync",
        "RecoverLastKnownGoodAsync"
    };

    [TestMethod]
    public async Task NetworkDiscoveryIsReadOnlyAndReturnsAnExplicitResult()
    {
        var service = new ReadOnlyNetworkEnvironmentDiscovery();

        var result = await service.DiscoverAsync(CancellationToken.None);

        Assert.AreNotEqual(OperationStatus.NotImplemented, result.Status);
        StringAssert.Contains(result.Message, "Read-only");
    }

    [TestMethod]
    public async Task DnsDiscoveryIsReadOnlyAndReturnsAnExplicitResult()
    {
        var service = new ReadOnlyDnsConfigurationDiscovery();

        var result = await service.DiscoverAsync(CancellationToken.None);

        Assert.AreNotEqual(OperationStatus.NotImplemented, result.Status);
        StringAssert.Contains(result.Message, "Read-only");
    }

    [TestMethod]
    public async Task FirewallPlaceholderDoesNotPretendInspectionOrProtectionWasApplied()
    {
        var service = new DeferredFirewallStateDiscovery();

        var result = await service.DiscoverAsync(CancellationToken.None);

        Assert.AreEqual(OperationStatus.NotImplemented, result.Status);
        Assert.IsFalse(result.IsSuccess);
        StringAssert.Contains(result.Message, "no firewall API was called");
    }

    [TestMethod]
    public async Task StartupPlaceholderExplicitlyRejectsRegistration()
    {
        var service = new DeferredStartupCapabilityDiscovery();

        var result = await service.DiscoverAsync(CancellationToken.None);

        Assert.AreEqual(OperationStatus.Unsupported, result.Status);
        StringAssert.Contains(result.Message, "no startup entry exists");
    }

    [TestMethod]
    public async Task FilteringPlatformIsExplicitlyDeferred()
    {
        var service = new DeferredFilteringPlatformCapabilityDiscovery();

        var result = await service.DiscoverAsync(CancellationToken.None);

        Assert.AreEqual(OperationStatus.Unsupported, result.Status);
        Assert.IsFalse(result.IsSuccess);
    }

    [TestMethod]
    public void TransactionContractRequiresEverySafetyPhase()
    {
        var names = typeof(ITransactionalWindowsChange<,>)
            .GetMethods()
            .Select(static method => method.Name)
            .ToHashSet(StringComparer.Ordinal);

        CollectionAssert.AreEquivalent(
            TransactionMethodNames,
            names.ToArray());
    }
}
