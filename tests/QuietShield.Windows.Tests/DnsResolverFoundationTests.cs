using System.Net;
using QuietShield.Core.Dns;
using QuietShield.Windows.Dns;

namespace QuietShield.Windows.Tests;

[TestClass]
public sealed class DnsResolverFoundationTests
{
    [TestMethod]
    public async Task DiagnosticListenerIsDisabledByDefaultAndRejectsImplicitStart()
    {
        await using var listener = new LoopbackDiagnosticDnsListener();

        Assert.IsFalse(listener.IsEnabled);
        Assert.IsNull(listener.BoundAddress);
        Assert.IsNull(listener.BoundPort);
        await Assert.ThrowsAsync<InvalidOperationException>(() => listener.StartAsync(false, CancellationToken.None));
        Assert.IsFalse(listener.IsEnabled);
    }

    [TestMethod]
    public async Task ExplicitDiagnosticListenerUsesLoopbackDynamicUnprivilegedPort()
    {
        await using var listener = new LoopbackDiagnosticDnsListener();

        var port = await listener.StartAsync(true, CancellationToken.None);

        Assert.IsTrue(listener.IsEnabled);
        Assert.AreEqual(IPAddress.Loopback, listener.BoundAddress);
        Assert.AreEqual(port, listener.BoundPort);
        Assert.IsGreaterThan(1023, port);
        Assert.AreNotEqual(53, port);

        await listener.StopAsync(CancellationToken.None);
        Assert.IsFalse(listener.IsEnabled);
    }

    [TestMethod]
    public async Task ResolverFoundationsHonorCancellationWithoutNetworkAccess()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            new DeferredUpstreamDnsResolver().ResolveAsync("example.test", cancellation.Token));
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            new FoundationDnsOverHttpsCapabilityProvider().GetCapabilityAsync(cancellation.Token));
    }

    [TestMethod]
    public async Task SystemResolverRejectsInvalidDomainBeforeResolution()
    {
        var result = await new ReadOnlySystemDnsResolver().ResolveAsync("https://example.test", CancellationToken.None);

        Assert.IsFalse(result.Succeeded);
        Assert.IsEmpty(result.Addresses);
        StringAssert.Contains(result.Status, "domain");
    }
}
