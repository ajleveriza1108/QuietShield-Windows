namespace QuietShield.Core.Dns;

public sealed record DnsResolutionResult(bool Succeeded, IReadOnlyList<string> Addresses, string Status, DateTimeOffset CompletedAtUtc);

public enum DnsOverHttpsCapability
{
    Available,
    Unavailable,
    Unknown
}

public interface ISystemDnsResolver
{
    Task<DnsResolutionResult> ResolveAsync(string domain, CancellationToken cancellationToken);
}

public interface IUpstreamDnsResolver
{
    Task<DnsResolutionResult> ResolveAsync(string domain, CancellationToken cancellationToken);
}

public interface IDnsOverHttpsCapabilityProvider
{
    Task<DnsOverHttpsCapability> GetCapabilityAsync(CancellationToken cancellationToken);
}

public interface IDiagnosticDnsListener : IAsyncDisposable
{
    bool IsEnabled { get; }
    int? BoundPort { get; }
    Task<int> StartAsync(bool explicitlyEnabled, CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
}

public static class DnsDiagnosticRedactor
{
    public static string FormatDecision(DnsPolicyResult result, bool domainLoggingExplicitlyEnabled)
    {
        ArgumentNullException.ThrowIfNull(result);
        var domain = domainLoggingExplicitlyEnabled && result.NormalizedDomain is not null ? result.NormalizedDomain : "[domain logging disabled]";
        return $"DNS simulation decision={result.Decision}; category={result.Category?.ToString() ?? "None"}; domain={domain}";
    }
}
