using System.Net;
using QuietShield.Windows.Dns;

namespace QuietShield.Windows.Tests;

[TestClass]
public sealed class DnsRehearsalReadinessTests
{
    [TestMethod]
    [TestCategory("Phase5Smoke")]
    public void Port53ConflictIsRefusedWithoutBindingAnySocket()
    {
        var source = new FakeListenerSource(
            new[] { new IPEndPoint(IPAddress.Loopback, 53) },
            Array.Empty<IPEndPoint>());

        Assert.IsFalse(DnsPort53ReadinessEvaluator.IsAvailable(source));
        Assert.IsTrue(DnsPort53ReadinessEvaluator.IsAvailable(new FakeListenerSource(Array.Empty<IPEndPoint>(), Array.Empty<IPEndPoint>())));
    }

    private sealed class FakeListenerSource(
        IReadOnlyList<IPEndPoint> udp,
        IReadOnlyList<IPEndPoint> tcp) : IDnsListenerSnapshotSource
    {
        public IReadOnlyList<IPEndPoint> GetUdpListeners() => udp;
        public IReadOnlyList<IPEndPoint> GetTcpListeners() => tcp;
    }
}
