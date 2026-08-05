using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using QuietShield.Core.Dns;

namespace QuietShield.Windows.Dns;

public interface IDnsRuntimePolicyConfiguration
{
    DnsProtectionMode ProtectionMode { get; }
    IReadOnlySet<DnsCategory> CustomEnabledCategories { get; }
    IReadOnlyList<string> RequiredSafetyExemptions { get; }
}

public sealed class FoundationDnsRuntimePolicyConfiguration : IDnsRuntimePolicyConfiguration
{
    public DnsProtectionMode ProtectionMode => DnsProtectionMode.Standard;
    public IReadOnlySet<DnsCategory> CustomEnabledCategories { get; } = new HashSet<DnsCategory>();
    public IReadOnlyList<string> RequiredSafetyExemptions { get; } = new[] { "recovery.quietshield.invalid", "updates.quietshield.invalid" };
}

public sealed class FoundationDnsRuntimePolicyEvaluator : IDnsRuntimePolicyEvaluator
{
    private readonly IProtectionListStore _protectionLists;
    private readonly ICustomDomainListService _customLists;
    private readonly IDnsRuntimePolicyConfiguration _configuration;
    private readonly IDnsClock _clock;

    public FoundationDnsRuntimePolicyEvaluator(
        IProtectionListStore protectionLists,
        ICustomDomainListService customLists,
        IDnsRuntimePolicyConfiguration configuration,
        IDnsClock clock)
    {
        _protectionLists = protectionLists;
        _customLists = customLists;
        _configuration = configuration;
        _clock = clock;
    }

    public async Task<DnsPolicyResult> EvaluateAsync(string normalizedDomain, CancellationToken cancellationToken)
    {
        var custom = await _customLists.GetAllAsync(cancellationToken).ConfigureAwait(false);
        return DnsPolicyEngine.Evaluate(new DnsPolicyRequest(
            normalizedDomain,
            _configuration.ProtectionMode,
            _configuration.CustomEnabledCategories,
            _protectionLists.ActiveSnapshot,
            custom,
            _configuration.RequiredSafetyExemptions,
            _clock.UtcNow));
    }
}

public sealed record LocalDnsDiagnosticResult(
    bool Succeeded,
    int BoundPort,
    bool UdpPassed,
    bool TcpPassed,
    string Status);

public interface ILocalDnsRuntimeDiagnostic
{
    Task<LocalDnsDiagnosticResult> RunAsync(CancellationToken cancellationToken);
}

public sealed class LocalDnsRuntimeDiagnostic : ILocalDnsRuntimeDiagnostic
{
    private readonly IDnsRuntimePolicyEvaluator _policy;

    public LocalDnsRuntimeDiagnostic(IDnsRuntimePolicyEvaluator policy) => _policy = policy;

    public async Task<LocalDnsDiagnosticResult> RunAsync(CancellationToken cancellationToken)
    {
        await using var runtime = new LocalDnsRuntime(
            LocalDnsRuntimeOptions.SafeDiagnosticDefaults,
            _policy,
            UnavailableRawDnsUpstreamResolver.Instance);
        var port = await runtime.StartAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var udp = await QueryUdpAsync(port, cancellationToken).ConfigureAwait(false);
            var tcp = await QueryTcpAsync(port, cancellationToken).ConfigureAwait(false);
            var udpPassed = DnsWireProtocol.GetResponseCode(udp) == DnsResponseCode.NameError;
            var tcpPassed = DnsWireProtocol.GetResponseCode(tcp) == DnsResponseCode.NameError;
            return new LocalDnsDiagnosticResult(
                udpPassed && tcpPassed,
                port,
                udpPassed,
                tcpPassed,
                udpPassed && tcpPassed
                    ? "Loopback UDP and TCP policy diagnostics returned the expected blocked response; no Windows DNS setting changed."
                    : "The local DNS runtime diagnostic response was unexpected.");
        }
        finally
        {
            await runtime.StopAsync(CancellationToken.None).ConfigureAwait(false);
        }
    }

    private static async Task<byte[]> QueryUdpAsync(int port, CancellationToken cancellationToken)
    {
        var query = DnsWireProtocol.CreateQuery("malware.example.test", 1, 0x4401);
        using var client = new UdpClient(AddressFamily.InterNetwork);
        await client.SendAsync(query, new IPEndPoint(IPAddress.Loopback, port), cancellationToken).ConfigureAwait(false);
        return (await client.ReceiveAsync(cancellationToken).ConfigureAwait(false)).Buffer;
    }

    private static async Task<byte[]> QueryTcpAsync(int port, CancellationToken cancellationToken)
    {
        var query = DnsWireProtocol.CreateQuery("malware.example.test", 28, 0x4402);
        using var client = new TcpClient(AddressFamily.InterNetwork);
        await client.ConnectAsync(IPAddress.Loopback, port, cancellationToken).ConfigureAwait(false);
        await using var stream = client.GetStream();
        var prefix = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(prefix, checked((ushort)query.Length));
        await stream.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(query, cancellationToken).ConfigureAwait(false);
        await stream.ReadExactlyAsync(prefix, cancellationToken).ConfigureAwait(false);
        var response = new byte[BinaryPrimitives.ReadUInt16BigEndian(prefix)];
        await stream.ReadExactlyAsync(response, cancellationToken).ConfigureAwait(false);
        return response;
    }

    private sealed class UnavailableRawDnsUpstreamResolver : IDnsRawUpstreamResolver
    {
        public static UnavailableRawDnsUpstreamResolver Instance { get; } = new();
        public IReadOnlyList<DnsUpstreamHealth> GetHealth() => Array.Empty<DnsUpstreamHealth>();
        public Task<DnsUpstreamResult> ResolveAsync(DnsWireQuestion question, DnsEndpointIdentity localEndpoint, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return Task.FromResult(new DnsUpstreamResult(false, null, null, false, "No upstream is configured for the blocked-domain diagnostic."));
        }
    }
}
