using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using QuietShield.Core.Dns;
using QuietShield.Service;
using QuietShield.Windows.Dns;

namespace QuietShield.Windows.Tests;

[TestClass]
public sealed class DnsRuntimeAndUpstreamTests
{
    [TestMethod]
    [TestCategory("Phase5Smoke")]
    public async Task EmbeddedBlockedTestDomainReturnsRawNxdomainOverUdp()
    {
        await using var runtime = CreateRuntime(new DnsRehearsalPolicyEvaluator(), new EchoUpstreamResolver());
        var port = await runtime.StartAsync(CancellationToken.None);

        var result = await DnsRawProbeClient.ProbeAsync(
            new IPEndPoint(IPAddress.Loopback, port),
            "quietshield-blocked.test",
            DnsRawProbeProtocol.Udp,
            TimeSpan.FromSeconds(5),
            CancellationToken.None);

        Assert.IsTrue(result.Validation.Succeeded);
        Assert.AreEqual(result.Validation.ExpectedTransactionId, result.Validation.ResponseTransactionId);
        Assert.IsTrue(result.Validation.IsResponse);
        Assert.AreEqual(DnsResponseCode.NameError, result.Validation.ResponseCode);
        Assert.AreEqual("quietshield-blocked.test", result.Validation.NormalizedQuestionName);
    }

    [TestMethod]
    [TestCategory("Phase5Smoke")]
    public async Task EmbeddedBlockedTestDomainReturnsRawNxdomainOverTcp()
    {
        await using var runtime = CreateRuntime(new DnsRehearsalPolicyEvaluator(), new EchoUpstreamResolver());
        var port = await runtime.StartAsync(CancellationToken.None);

        var result = await DnsRawProbeClient.ProbeAsync(
            new IPEndPoint(IPAddress.Loopback, port),
            "quietshield-blocked.test.",
            DnsRawProbeProtocol.Tcp,
            TimeSpan.FromSeconds(5),
            CancellationToken.None);

        Assert.IsTrue(result.Validation.Succeeded);
        Assert.AreEqual(DnsResponseCode.NameError, result.Validation.ResponseCode);
        Assert.AreEqual("quietshield-blocked.test", result.NormalizedQueryName);
        Assert.AreEqual("quietshield-blocked.test", result.Validation.NormalizedQuestionName);
    }

    [TestMethod]
    [TestCategory("Phase5Smoke")]
    public async Task AllowedExampleDomainStillForwardsAndReturnsNoError()
    {
        var upstream = new EchoUpstreamResolver();
        await using var runtime = CreateRuntime(new DnsRehearsalPolicyEvaluator(), upstream);
        var port = await runtime.StartAsync(CancellationToken.None);

        var result = await DnsRawProbeClient.ProbeAsync(
            new IPEndPoint(IPAddress.Loopback, port),
            "example.com",
            DnsRawProbeProtocol.Udp,
            TimeSpan.FromSeconds(5),
            CancellationToken.None);

        Assert.IsTrue(result.Validation.Succeeded);
        Assert.AreEqual(DnsResponseCode.NoError, result.Validation.ResponseCode);
        Assert.AreEqual(1, upstream.CallCount);
        Assert.AreEqual("example.com", upstream.LastQuestion!.NormalizedDomain);
    }

    [TestMethod]
    [TestCategory("Phase4Smoke")]
    public async Task UdpBlockedQueryReturnsNxdomainOnDynamicLoopbackPort()
    {
        var upstream = new EchoUpstreamResolver();
        await using var runtime = CreateRuntime(new FixedPolicy(DnsDecision.Block), upstream);
        var port = await runtime.StartAsync(CancellationToken.None);

        var response = await SendUdpAsync(port, DnsWireProtocol.CreateQuery("blocked.example.test", 1, 0x1001), CancellationToken.None);

        Assert.IsGreaterThan(1023, port);
        Assert.AreNotEqual(53, port);
        Assert.AreEqual(DnsResponseCode.NameError, DnsWireProtocol.GetResponseCode(response));
        Assert.AreEqual((ushort)0x1001, DnsWireProtocol.GetTransactionId(response));
        Assert.AreEqual(0, upstream.CallCount);
    }

    [TestMethod]
    [TestCategory("Phase4Smoke")]
    public async Task TcpBlockedQueryReturnsNxdomainAndShutsDownCleanly()
    {
        await using var runtime = CreateRuntime(new FixedPolicy(DnsDecision.Block), new EchoUpstreamResolver());
        var port = await runtime.StartAsync(CancellationToken.None);

        var response = await SendTcpAsync(port, DnsWireProtocol.CreateQuery("blocked.example.test", 28, 0x1002), CancellationToken.None);
        await runtime.StopAsync(CancellationToken.None);

        Assert.AreEqual(DnsResponseCode.NameError, DnsWireProtocol.GetResponseCode(response));
        Assert.AreEqual(LocalDnsRuntimeState.Stopped, runtime.GetStatus().State);
    }

    [TestMethod]
    [TestCategory("Phase4Smoke")]
    public async Task AllowedQueryForwardsRawRecordTypeWithoutUsingSystemResolver()
    {
        var upstream = new EchoUpstreamResolver();
        await using var runtime = CreateRuntime(new FixedPolicy(DnsDecision.Allow), upstream);
        var port = await runtime.StartAsync(CancellationToken.None);

        var response = await SendUdpAsync(port, DnsWireProtocol.CreateQuery("mail.example.test", 15, 0x1003), CancellationToken.None);

        Assert.AreEqual(DnsResponseCode.NoError, DnsWireProtocol.GetResponseCode(response));
        Assert.AreEqual((ushort)15, upstream.LastQuestion!.QueryType);
        Assert.AreEqual(1, upstream.CallCount);
    }

    [TestMethod]
    public async Task MalformedPacketReturnsFormatErrorWithoutCrashingRuntime()
    {
        await using var runtime = CreateRuntime(new FixedPolicy(DnsDecision.Allow), new EchoUpstreamResolver());
        var port = await runtime.StartAsync(CancellationToken.None);

        var response = await SendUdpAsync(port, new byte[] { 0x20, 0x02, 0x01 }, CancellationToken.None);

        Assert.AreEqual(DnsResponseCode.FormatError, DnsWireProtocol.GetResponseCode(response));
        Assert.AreEqual(LocalDnsRuntimeState.Running, runtime.GetStatus().State);
    }

    [TestMethod]
    public async Task QueryDeadlineReturnsServerFailureAndCancelsPolicy()
    {
        var options = LocalDnsRuntimeOptions.SafeDiagnosticDefaults with { QueryTimeout = TimeSpan.FromMilliseconds(50) };
        await using var runtime = new LocalDnsRuntime(options, new WaitingPolicy(), new EchoUpstreamResolver());
        var port = await runtime.StartAsync(CancellationToken.None);

        var response = await SendUdpAsync(port, DnsWireProtocol.CreateQuery("timeout.example.test", 16, 0x1004), CancellationToken.None);

        Assert.AreEqual(DnsResponseCode.ServerFailure, DnsWireProtocol.GetResponseCode(response));
    }

    [TestMethod]
    public async Task RuntimeStartHonorsCancellationAndRejectsUnsafeBindings()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await using var runtime = CreateRuntime(new FixedPolicy(DnsDecision.Block), new EchoUpstreamResolver());
        await Assert.ThrowsAsync<OperationCanceledException>(() => runtime.StartAsync(cancellation.Token));
        Assert.Throws<ArgumentException>(() => new LocalDnsRuntime(
            LocalDnsRuntimeOptions.SafeDiagnosticDefaults with { ListenPort = 53 },
            new FixedPolicy(DnsDecision.Block), new EchoUpstreamResolver()));
        Assert.Throws<ArgumentException>(() => new LocalDnsRuntime(
            LocalDnsRuntimeOptions.SafeDiagnosticDefaults with { ListenAddress = IPAddress.Any },
            new FixedPolicy(DnsDecision.Block), new EchoUpstreamResolver()));
    }

    [TestMethod]
    public async Task ConcurrentUdpQueriesRemainBoundedAndDeterministic()
    {
        await using var runtime = CreateRuntime(new FixedPolicy(DnsDecision.Block), new EchoUpstreamResolver(), maximumConcurrency: 4);
        var port = await runtime.StartAsync(CancellationToken.None);

        var tasks = Enumerable.Range(0, 24).Select(index => SendUdpAsync(
            port,
            DnsWireProtocol.CreateQuery($"q{index}.example.test", 1, checked((ushort)(0x2000 + index))),
            CancellationToken.None));
        var responses = await Task.WhenAll(tasks);

        Assert.IsTrue(responses.All(response => DnsWireProtocol.GetResponseCode(response) == DnsResponseCode.NameError));
        Assert.IsLessThanOrEqualTo(4, runtime.GetStatus().ActiveRequests);
    }

    [TestMethod]
    public async Task DomainLoggingIsDisabledByDefaultAndExplicitWhenEnabled()
    {
        var disabledSink = new CollectingSink();
        await using (var runtime = CreateRuntime(new FixedPolicy(DnsDecision.Block), new EchoUpstreamResolver(), sink: disabledSink))
        {
            var port = await runtime.StartAsync(CancellationToken.None);
            await SendUdpAsync(port, DnsWireProtocol.CreateQuery("private.example.test", 1, 0x3001), CancellationToken.None);
        }
        Assert.IsTrue(disabledSink.Entries.All(static entry => entry.Domain is null));
        StringAssert.Contains(DnsRuntimeDiagnosticFormatter.Format(disabledSink.Entries.First(static entry => entry.EventName == "PolicyDecision")), "[domain logging disabled]");

        var enabledSink = new CollectingSink();
        var enabledOptions = LocalDnsRuntimeOptions.SafeDiagnosticDefaults with { DiagnosticDomainLoggingEnabled = true };
        await using (var runtime = new LocalDnsRuntime(enabledOptions, new FixedPolicy(DnsDecision.Block), new EchoUpstreamResolver(), enabledSink))
        {
            var port = await runtime.StartAsync(CancellationToken.None);
            await SendUdpAsync(port, DnsWireProtocol.CreateQuery("private.example.test", 1, 0x3002), CancellationToken.None);
        }
        Assert.IsTrue(enabledSink.Entries.Any(static entry => entry.Domain == "private.example.test"));
        Assert.IsTrue(enabledSink.Entries.All(static entry => !entry.Status.Contains("http", StringComparison.OrdinalIgnoreCase)));
    }

    [TestMethod]
    public async Task TruncatedUdpResponseFallsBackToTcp()
    {
        var question = Parse("fallback.example.test", 1, 0x4001);
        var udp = DnsWireProtocol.CreateResponse(question, DnsResponseCode.NoError);
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(2, 2), (ushort)(BinaryPrimitives.ReadUInt16BigEndian(udp.AsSpan(2, 2)) | 0x0200));
        var tcp = DnsWireProtocol.CreateResponse(question, DnsResponseCode.NoError);
        var transport = new QueueTransport(udp, tcp);
        var resolver = CreateUpstreamResolver(transport);

        var result = await resolver.ResolveAsync(question, LocalEndpoint(), CancellationToken.None);

        Assert.IsTrue(result.Succeeded);
        Assert.IsTrue(result.UsedTcpFallback);
        CollectionAssert.AreEqual(new[] { DnsTransportProtocol.Udp, DnsTransportProtocol.Tcp }, transport.Protocols.ToArray());
    }

    [TestMethod]
    public async Task MultipleUpstreamsRetryAndTrackHealth()
    {
        var question = Parse("health.example.test", 1, 0x4002);
        var first = new DnsEndpointIdentity("192.0.2.10", 53, "first");
        var second = new DnsEndpointIdentity("192.0.2.11", 53, "second");
        var transport = new DelegatingTransport((endpoint, protocol) =>
            endpoint == first ? throw new TimeoutException("test timeout") : DnsWireProtocol.CreateResponse(question, DnsResponseCode.NoError));
        var resolver = new SafeDnsUpstreamResolver(transport, new DnsUpstreamOptions(new[] { first, second }, null, TimeSpan.FromMilliseconds(100), 0, DnsUpstreamFailurePolicy.FailClosed));

        var result = await resolver.ResolveAsync(question, LocalEndpoint(), CancellationToken.None);

        Assert.AreEqual(second, result.Endpoint);
        Assert.IsFalse(resolver.GetHealth().Single(item => item.Endpoint == first).Healthy);
        Assert.IsTrue(resolver.GetHealth().Single(item => item.Endpoint == second).Healthy);
    }

    [TestMethod]
    public async Task RecursionToQuietShieldEndpointIsRejectedWithoutTransportCall()
    {
        var local = LocalEndpoint();
        var transport = new DelegatingTransport((_, _) => throw new AssertFailedException("Transport must not be called for recursive forwarding."));
        var resolver = new SafeDnsUpstreamResolver(
            transport,
            new DnsUpstreamOptions(new[] { local }, null, TimeSpan.FromMilliseconds(100), 0, DnsUpstreamFailurePolicy.FailClosed));

        var result = await resolver.ResolveAsync(Parse("loop.example.test", 1, 0x4003), local, CancellationToken.None);

        Assert.IsFalse(result.Succeeded);
        Assert.AreEqual(0, transport.CallCount);
    }

    [TestMethod]
    public async Task ExplicitEmergencyUpstreamImplementsSafeFailOpenSelection()
    {
        var question = Parse("emergency.example.test", 1, 0x4004);
        var primary = new DnsEndpointIdentity("192.0.2.20", 53, "primary");
        var emergency = new DnsEndpointIdentity("192.0.2.21", 53, "emergency");
        var transport = new DelegatingTransport((endpoint, _) =>
            endpoint == primary ? throw new TimeoutException("test timeout") : DnsWireProtocol.CreateResponse(question, DnsResponseCode.NoError));
        var resolver = new SafeDnsUpstreamResolver(
            transport,
            new DnsUpstreamOptions(new[] { primary }, emergency, TimeSpan.FromMilliseconds(100), 0, DnsUpstreamFailurePolicy.FailOpenToExplicitEmergencyUpstream));

        var result = await resolver.ResolveAsync(question, LocalEndpoint(), CancellationToken.None);

        Assert.IsTrue(result.Succeeded);
        Assert.AreEqual(emergency, result.Endpoint);
        StringAssert.Contains(result.Status, "emergency");
    }

    [TestMethod]
    public async Task FailClosedUpstreamReturnsFailureAfterTimeout()
    {
        var transport = new DelegatingTransport((_, _) => throw new TimeoutException("test timeout"));
        var resolver = CreateUpstreamResolver(transport);

        var result = await resolver.ResolveAsync(Parse("failure.example.test", 1, 0x4005), LocalEndpoint(), CancellationToken.None);

        Assert.IsFalse(result.Succeeded);
        StringAssert.Contains(result.Status, "failed");
    }

    [TestMethod]
    public async Task ServiceCoordinatorStartsStopsAndReportsHeartbeatWithoutRegistration()
    {
        var runtime = new FakeLocalRuntime();
        var coordinator = new DnsRuntimeServiceCoordinator(runtime, new PassingServicePreflight(), NullLogger<DnsRuntimeServiceCoordinator>.Instance);

        await coordinator.StartAsync(CancellationToken.None);
        var healthy = coordinator.GetHealth();
        coordinator.RecordHeartbeat();
        await coordinator.StopAsync(CancellationToken.None);

        Assert.AreEqual(DnsServiceHealthState.Healthy, healthy.State);
        Assert.IsNotNull(healthy.LastHeartbeatUtc);
        Assert.AreEqual(DnsServiceHealthState.Stopped, coordinator.GetHealth().State);
        Assert.AreEqual(1, runtime.StartCount);
        Assert.AreEqual(1, runtime.StopCount);
    }

    private static LocalDnsRuntime CreateRuntime(IDnsRuntimePolicyEvaluator policy, IDnsRawUpstreamResolver upstream, int maximumConcurrency = 8, IDnsRuntimeEventSink? sink = null) =>
        new(LocalDnsRuntimeOptions.SafeDiagnosticDefaults with { MaximumConcurrentRequests = maximumConcurrency }, policy, upstream, sink);

    private static async Task<byte[]> SendUdpAsync(int port, byte[] query, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        using var client = new UdpClient(AddressFamily.InterNetwork);
        await client.SendAsync(query, new IPEndPoint(IPAddress.Loopback, port), timeout.Token);
        return (await client.ReceiveAsync(timeout.Token)).Buffer;
    }

    private static async Task<byte[]> SendTcpAsync(int port, byte[] query, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));
        using var client = new TcpClient(AddressFamily.InterNetwork);
        await client.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
        await using var stream = client.GetStream();
        var prefix = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(prefix, checked((ushort)query.Length));
        await stream.WriteAsync(prefix, timeout.Token);
        await stream.WriteAsync(query, timeout.Token);
        await stream.ReadExactlyAsync(prefix, timeout.Token);
        var response = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)];
        await stream.ReadExactlyAsync(response, timeout.Token);
        return response;
    }

    private static DnsWireQuestion Parse(string domain, ushort queryType, ushort id) =>
        DnsWireProtocol.ParseQuery(DnsWireProtocol.CreateQuery(domain, queryType, id)).Question!;

    private static DnsEndpointIdentity LocalEndpoint() => new("127.0.0.1", 53535, "local");

    private static SafeDnsUpstreamResolver CreateUpstreamResolver(IDnsUpstreamTransport transport) => new(
        transport,
        new DnsUpstreamOptions(
            new[] { new DnsEndpointIdentity("192.0.2.53", 53, "test upstream") },
            null,
            TimeSpan.FromMilliseconds(100),
            0,
            DnsUpstreamFailurePolicy.FailClosed));

    private sealed class FixedPolicy(DnsDecision decision) : IDnsRuntimePolicyEvaluator
    {
        public Task<DnsPolicyResult> EvaluateAsync(string normalizedDomain, CancellationToken cancellationToken) => Task.FromResult(
            new DnsPolicyResult(decision, DnsCategory.Custom, normalizedDomain, Array.Empty<string>(), "Test policy", DateTimeOffset.UtcNow, normalizedDomain));
    }

    private sealed class WaitingPolicy : IDnsRuntimePolicyEvaluator
    {
        public async Task<DnsPolicyResult> EvaluateAsync(string normalizedDomain, CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            throw new AssertFailedException("Unreachable");
        }
    }

    private sealed class EchoUpstreamResolver : IDnsRawUpstreamResolver
    {
        public int CallCount { get; private set; }
        public DnsWireQuestion? LastQuestion { get; private set; }
        public IReadOnlyList<DnsUpstreamHealth> GetHealth() => Array.Empty<DnsUpstreamHealth>();
        public Task<DnsUpstreamResult> ResolveAsync(DnsWireQuestion question, DnsEndpointIdentity localEndpoint, CancellationToken cancellationToken)
        {
            CallCount++;
            LastQuestion = question;
            return Task.FromResult(new DnsUpstreamResult(true, DnsWireProtocol.CreateResponse(question, DnsResponseCode.NoError), new DnsEndpointIdentity("192.0.2.53", 53, "fake"), false, "Fake response"));
        }
    }

    private sealed class CollectingSink : IDnsRuntimeEventSink
    {
        private readonly List<DnsRuntimeLogEntry> _entries = new();
        public IReadOnlyList<DnsRuntimeLogEntry> Entries { get { lock (_entries) return _entries.ToArray(); } }
        public void Write(DnsRuntimeLogEntry entry) { lock (_entries) _entries.Add(entry); }
    }

    private sealed class QueueTransport(params byte[][] responses) : IDnsUpstreamTransport
    {
        private readonly Queue<byte[]> _responses = new(responses);
        public List<DnsTransportProtocol> Protocols { get; } = new();
        public Task<byte[]> ExchangeAsync(DnsEndpointIdentity endpoint, ReadOnlyMemory<byte> query, DnsTransportProtocol protocol, TimeSpan timeout, CancellationToken cancellationToken)
        {
            Protocols.Add(protocol);
            return Task.FromResult(_responses.Dequeue());
        }
    }

    private sealed class DelegatingTransport(Func<DnsEndpointIdentity, DnsTransportProtocol, byte[]> handler) : IDnsUpstreamTransport
    {
        public int CallCount { get; private set; }
        public Task<byte[]> ExchangeAsync(DnsEndpointIdentity endpoint, ReadOnlyMemory<byte> query, DnsTransportProtocol protocol, TimeSpan timeout, CancellationToken cancellationToken)
        {
            CallCount++;
            return Task.FromResult(handler(endpoint, protocol));
        }
    }

    private sealed class FakeLocalRuntime : ILocalDnsRuntime
    {
        public int StartCount { get; private set; }
        public int StopCount { get; private set; }
        public LocalDnsRuntimeStatus GetStatus() => new(StartCount > StopCount ? LocalDnsRuntimeState.Running : LocalDnsRuntimeState.Stopped, StartCount > StopCount ? 53535 : null, 0, "Fake");
        public Task<int> StartAsync(CancellationToken cancellationToken) { StartCount++; return Task.FromResult(53535); }
        public Task StopAsync(CancellationToken cancellationToken) { StopCount++; return Task.CompletedTask; }
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class PassingServicePreflight : IDnsServiceStartupPreflight
    {
        public Task<DnsServicePreflightResult> RunAsync(CancellationToken cancellationToken) => Task.FromResult(new DnsServicePreflightResult(true, "Passed"));
    }
}
