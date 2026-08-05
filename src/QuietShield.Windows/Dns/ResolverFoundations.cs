using System.Net;
using System.Net.Sockets;
using QuietShield.Core.Dns;

namespace QuietShield.Windows.Dns;

public sealed class ReadOnlySystemDnsResolver : ISystemDnsResolver
{
    public async Task<DnsResolutionResult> ResolveAsync(string domain, CancellationToken cancellationToken)
    {
        var normalized = DomainNormalizer.NormalizeDomain(domain);
        if (!normalized.IsValid || normalized.NormalizedValue is null)
        {
            return new DnsResolutionResult(false, Array.Empty<string>(), normalized.Error ?? "Invalid domain.", DateTimeOffset.UtcNow);
        }

        try
        {
            var addresses = await System.Net.Dns.GetHostAddressesAsync(normalized.NormalizedValue, cancellationToken).ConfigureAwait(false);
            return new DnsResolutionResult(true, addresses.Select(static address => address.ToString()).ToArray(), "Resolved with the current Windows system resolver; no DNS setting was changed.", DateTimeOffset.UtcNow);
        }
        catch (SocketException exception)
        {
            return new DnsResolutionResult(false, Array.Empty<string>(), $"System resolution failed: {exception.SocketErrorCode}", DateTimeOffset.UtcNow);
        }
    }
}

public sealed class DeferredUpstreamDnsResolver : IUpstreamDnsResolver
{
    public Task<DnsResolutionResult> ResolveAsync(string domain, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(new DnsResolutionResult(false, Array.Empty<string>(), "Direct upstream DNS resolution is not configured in this foundation.", DateTimeOffset.UtcNow));
    }
}

public sealed class FoundationDnsOverHttpsCapabilityProvider : IDnsOverHttpsCapabilityProvider
{
    public Task<DnsOverHttpsCapability> GetCapabilityAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(DnsOverHttpsCapability.Unknown);
    }
}

public sealed class LoopbackDiagnosticDnsListener : IDiagnosticDnsListener
{
    private UdpClient? _listener;

    public bool IsEnabled => _listener is not null;
    public IPAddress? BoundAddress => (_listener?.Client.LocalEndPoint as IPEndPoint)?.Address;
    public int? BoundPort => (_listener?.Client.LocalEndPoint as IPEndPoint)?.Port;

    public Task<int> StartAsync(bool explicitlyEnabled, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!explicitlyEnabled) throw new InvalidOperationException("The diagnostic listener is disabled by default and requires explicit enablement.");
        if (_listener is not null) return Task.FromResult(BoundPort!.Value);
        _listener = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        return Task.FromResult(BoundPort!.Value);
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _listener?.Dispose();
        _listener = null;
        return Task.CompletedTask;
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync(CancellationToken.None).ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }
}
