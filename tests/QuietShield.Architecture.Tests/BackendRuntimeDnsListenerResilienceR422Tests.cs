namespace QuietShield.Architecture.Tests;

[TestClass]
public sealed class BackendRuntimeDnsListenerResilienceR422Tests
{
    private static readonly string RepositoryRoot = FindRepositoryRoot();

    [TestMethod]
    public void LocalDnsRuntimeKeepsTransientSocketErrorsInsideListenerLoops()
    {
        var path = Path.Combine(
            RepositoryRoot,
            "src",
            "QuietShield.Windows",
            "Dns",
            "LocalDnsRuntime.cs");
        var source = File.ReadAllText(path);

        StringAssert.Contains(source, "R4.2.2 listener resilience");
        StringAssert.Contains(source, "UdpListenerSocketError");
        StringAssert.Contains(source, "TcpListenerSocketError");
        StringAssert.Contains(source, "_udpLoop?.IsFaulted == true");
        StringAssert.Contains(source, "_tcpLoop?.IsFaulted == true");
        StringAssert.Contains(source, "udpStoppedUnexpectedly");
        StringAssert.Contains(source, "tcpStoppedUnexpectedly");

        var udpCancelCatch = source.IndexOf(
            "catch (SocketException) when (cancellationToken.IsCancellationRequested)",
            StringComparison.Ordinal);
        var udpRecovery = source.IndexOf(
            "WriteEvent(\"UdpListenerSocketError\"",
            StringComparison.Ordinal);
        var tcpRecovery = source.IndexOf(
            "WriteEvent(\"TcpListenerSocketError\"",
            StringComparison.Ordinal);

        Assert.IsGreaterThanOrEqualTo(0, udpCancelCatch);
        Assert.IsGreaterThan(udpCancelCatch, udpRecovery);
        Assert.IsGreaterThan(udpRecovery, tcpRecovery);
    }

    [TestMethod]
    public void ProductionSelfTestProbesLiveUdpAndTcpAndActivationGateRemainsOrdered()
    {
        var path = Path.Combine(
            RepositoryRoot,
            "src",
            "QuietShield.Service",
            "ProductionBackendRuntimeR40.cs");
        var source = File.ReadAllText(path);

        StringAssert.Contains(source, "R4.2.2 live DNS listener self-test");
        StringAssert.Contains(source, "DNS live runtime UDP/TCP");
        StringAssert.Contains(source, "\"quietshield-blocked.test\"");
        StringAssert.Contains(source, "DnsRawProbeProtocol.Udp");
        StringAssert.Contains(source, "DnsRawProbeProtocol.Tcp");

        var activationStart = source.IndexOf(
            "Mandatory Phase 5 process-boundary gate",
            StringComparison.Ordinal);
        var externalUdp = source.IndexOf(
            "RunExternalProbeAsync(\"udp\"",
            activationStart,
            StringComparison.Ordinal);
        var externalTcp = source.IndexOf(
            "RunExternalProbeAsync(\"tcp\"",
            externalUdp,
            StringComparison.Ordinal);
        var adapterMutation = source.IndexOf(
            "SetAdapterDnsLoopbackAsync",
            externalTcp,
            StringComparison.Ordinal);

        Assert.IsGreaterThanOrEqualTo(0, activationStart);
        Assert.IsGreaterThan(activationStart, externalUdp);
        Assert.IsGreaterThan(externalUdp, externalTcp);
        Assert.IsGreaterThan(externalTcp, adapterMutation);
    }

    private static string FindRepositoryRoot()
    {
        var current = new DirectoryInfo(AppContext.BaseDirectory);
        while (current is not null)
        {
            if (File.Exists(Path.Combine(current.FullName, "QuietShield.sln")))
                return current.FullName;
            current = current.Parent;
        }

        throw new DirectoryNotFoundException("QuietShield repository root was not found.");
    }
}
