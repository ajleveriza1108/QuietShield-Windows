namespace QuietShield.Core.Dns;

public enum DnsTransportProtocol
{
    Udp,
    Tcp
}

public enum DnsUpstreamFailurePolicy
{
    FailClosed,
    FailOpenToExplicitEmergencyUpstream
}

public enum DnsIndeterminatePolicy
{
    FailClosed,
    FailOpenToConfiguredUpstream
}

public sealed record DnsEndpointIdentity(string Address, int Port, string DisplayName);

public sealed record DnsUpstreamOptions(
    IReadOnlyList<DnsEndpointIdentity> Upstreams,
    DnsEndpointIdentity? EmergencyUpstream,
    TimeSpan Timeout,
    int RetryCount,
    DnsUpstreamFailurePolicy FailurePolicy);

public sealed record DnsUpstreamResult(
    bool Succeeded,
    byte[]? Response,
    DnsEndpointIdentity? Endpoint,
    bool UsedTcpFallback,
    string Status);

public sealed record DnsUpstreamHealth(
    DnsEndpointIdentity Endpoint,
    bool Healthy,
    int ConsecutiveFailures,
    DateTimeOffset LastAttemptUtc,
    string Status);

public interface IDnsUpstreamTransport
{
    Task<byte[]> ExchangeAsync(
        DnsEndpointIdentity endpoint,
        ReadOnlyMemory<byte> query,
        DnsTransportProtocol protocol,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

public interface IDnsRawUpstreamResolver
{
    Task<DnsUpstreamResult> ResolveAsync(DnsWireQuestion question, DnsEndpointIdentity localEndpoint, CancellationToken cancellationToken);
    IReadOnlyList<DnsUpstreamHealth> GetHealth();
}

public interface IDnsRuntimePolicyEvaluator
{
    Task<DnsPolicyResult> EvaluateAsync(string normalizedDomain, CancellationToken cancellationToken);
}

public sealed record DnsRuntimeLogEntry(string EventName, string Status, string? Domain, DateTimeOffset TimestampUtc);

public interface IDnsRuntimeEventSink
{
    void Write(DnsRuntimeLogEntry entry);
}

public sealed class NullDnsRuntimeEventSink : IDnsRuntimeEventSink
{
    public static NullDnsRuntimeEventSink Instance { get; } = new();
    private NullDnsRuntimeEventSink() { }
    public void Write(DnsRuntimeLogEntry entry) { }
}

public static class DnsRuntimeDiagnosticFormatter
{
    public static string Format(DnsRuntimeLogEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        return $"DNS runtime event={entry.EventName}; status={entry.Status}; domain={entry.Domain ?? "[domain logging disabled]"}";
    }
}
