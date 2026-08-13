// QuietShield Backend Pack 1-4 R1
using System.Net;
using System.Net.Sockets;
using System.Text;
using QuietShield.Core.Backends;
using QuietShield.Windows.Backends;

namespace QuietShield.Windows.Tests;

[TestClass]
public sealed class BackendPackWindowsTests
{
    [TestMethod]
    public void TelemetryCapturesWindowsConnectionAndInterfaceSnapshot()
    {
        var source = new WindowsNetworkTelemetrySource();
        var snapshot = source.Capture();

        Assert.IsNotNull(snapshot);
        Assert.IsNotNull(snapshot.Connections);
        Assert.IsNotNull(snapshot.Interfaces);
        Assert.IsLessThanOrEqualTo(DateTimeOffset.UtcNow, snapshot.CapturedAtUtc);
    }

    [TestMethod]
    public void DnsReadinessSystemActivationRemainsSafetyGated()
    {
        var result = WindowsDnsActivationReadinessProbe.Probe();

        Assert.IsFalse(result.SystemDnsActivationAllowed);
        Assert.IsTrue(
            result.Blockers.Any(item =>
                item.Contains("safety-gated", StringComparison.OrdinalIgnoreCase)));
    }

    [TestMethod]
    public async Task DnsProxyBlocksConfiguredDomainLocally()
    {
        var policy = new DnsPolicyEngine(new[]
        {
            new DnsPolicyRule(
                "blocked.quietshield.test",
                DnsPolicyAction.Block,
                IncludeSubdomains: true,
                Priority: 100)
        });

        await using var proxy = new DnsProxyServer(
            policy,
            new DnsProxyConfiguration(
                IPAddress.Parse("1.1.1.1"),
                ListenPort: 0));

        var port = proxy.Start();

        using var client = new UdpClient(AddressFamily.InterNetwork);
        var query = BuildDnsQuery("blocked.quietshield.test");
        await client.SendAsync(
            query,
            query.Length,
            new IPEndPoint(IPAddress.Loopback, port));

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        var response = await client.ReceiveAsync(timeout.Token);

        Assert.IsGreaterThanOrEqualTo(12, response.Buffer.Length);
        Assert.AreEqual(3, response.Buffer[3] & 0x0F);

        var metrics = proxy.GetMetrics();
        Assert.AreEqual(1L, metrics.BlockedQueries);
    }

    private static byte[] BuildDnsQuery(string host)
    {
        var bytes = new List<byte>
        {
            0x12, 0x34,
            0x01, 0x00,
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x00,
            0x00, 0x00
        };

        foreach (var label in host.Split('.'))
        {
            var labelBytes = Encoding.ASCII.GetBytes(label);
            bytes.Add((byte)labelBytes.Length);
            bytes.AddRange(labelBytes);
        }

        bytes.Add(0);
        bytes.Add(0);
        bytes.Add(1);
        bytes.Add(0);
        bytes.Add(1);

        return bytes.ToArray();
    }
}
