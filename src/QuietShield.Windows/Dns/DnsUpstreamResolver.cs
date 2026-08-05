using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using QuietShield.Core.Dns;

namespace QuietShield.Windows.Dns;

public sealed class SocketDnsUpstreamTransport : IDnsUpstreamTransport
{
    public async Task<byte[]> ExchangeAsync(
        DnsEndpointIdentity endpoint,
        ReadOnlyMemory<byte> query,
        DnsTransportProtocol protocol,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        if (!IPAddress.TryParse(endpoint.Address, out var address)) throw new InvalidOperationException("Upstream DNS endpoints must use literal IP addresses.");
        if (endpoint.Port is < 1 or > 65535) throw new InvalidOperationException("The upstream DNS port is invalid.");
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            return protocol == DnsTransportProtocol.Udp
                ? await ExchangeUdpAsync(address, endpoint.Port, query, deadline.Token).ConfigureAwait(false)
                : await ExchangeTcpAsync(address, endpoint.Port, query, deadline.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new TimeoutException($"The {protocol} upstream DNS request timed out.");
        }
    }

    private static async Task<byte[]> ExchangeUdpAsync(IPAddress address, int port, ReadOnlyMemory<byte> query, CancellationToken cancellationToken)
    {
        using var client = new UdpClient(address.AddressFamily);
        client.Connect(address, port);
        await client.SendAsync(query, cancellationToken).ConfigureAwait(false);
        var response = await client.ReceiveAsync(cancellationToken).ConfigureAwait(false);
        return response.Buffer;
    }

    private static async Task<byte[]> ExchangeTcpAsync(IPAddress address, int port, ReadOnlyMemory<byte> query, CancellationToken cancellationToken)
    {
        using var client = new TcpClient(address.AddressFamily);
        await client.ConnectAsync(address, port, cancellationToken).ConfigureAwait(false);
        await using var stream = client.GetStream();
        var lengthPrefix = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(lengthPrefix, checked((ushort)query.Length));
        await stream.WriteAsync(lengthPrefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(query, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);

        await stream.ReadExactlyAsync(lengthPrefix, cancellationToken).ConfigureAwait(false);
        var responseLength = BinaryPrimitives.ReadUInt16BigEndian(lengthPrefix);
        if (responseLength < DnsWireProtocol.HeaderLength) throw new InvalidDataException("The TCP DNS response length is invalid.");
        var response = new byte[responseLength];
        await stream.ReadExactlyAsync(response, cancellationToken).ConfigureAwait(false);
        return response;
    }
}

public sealed class SafeDnsUpstreamResolver : IDnsRawUpstreamResolver
{
    private readonly object _sync = new();
    private readonly IDnsUpstreamTransport _transport;
    private readonly DnsUpstreamOptions _options;
    private readonly Dictionary<DnsEndpointIdentity, DnsUpstreamHealth> _health = new();

    public SafeDnsUpstreamResolver(IDnsUpstreamTransport transport, DnsUpstreamOptions options)
    {
        _transport = transport;
        _options = Validate(options);
        foreach (var endpoint in _options.Upstreams.Concat(_options.EmergencyUpstream is null ? Array.Empty<DnsEndpointIdentity>() : new[] { _options.EmergencyUpstream }))
        {
            _health[endpoint] = new DnsUpstreamHealth(endpoint, false, 0, DateTimeOffset.MinValue, "Not checked");
        }
    }

    public IReadOnlyList<DnsUpstreamHealth> GetHealth()
    {
        lock (_sync) return _health.Values.OrderBy(static item => item.Endpoint.DisplayName, StringComparer.Ordinal).ToArray();
    }

    public async Task<DnsUpstreamResult> ResolveAsync(DnsWireQuestion question, DnsEndpointIdentity localEndpoint, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(question);
        ArgumentNullException.ThrowIfNull(localEndpoint);
        cancellationToken.ThrowIfCancellationRequested();

        var attempted = new HashSet<DnsEndpointIdentity>();
        foreach (var endpoint in _options.Upstreams)
        {
            if (IsRecursiveEndpoint(endpoint, localEndpoint))
            {
                RecordFailure(endpoint, "Rejected because the upstream endpoint is the QuietShield listener itself.");
                continue;
            }

            attempted.Add(endpoint);
            var result = await TryEndpointAsync(endpoint, question, cancellationToken).ConfigureAwait(false);
            if (result.Succeeded) return result;
        }

        if (_options.FailurePolicy == DnsUpstreamFailurePolicy.FailOpenToExplicitEmergencyUpstream &&
            _options.EmergencyUpstream is not null &&
            !attempted.Contains(_options.EmergencyUpstream) &&
            !IsRecursiveEndpoint(_options.EmergencyUpstream, localEndpoint))
        {
            var emergency = await TryEndpointAsync(_options.EmergencyUpstream, question, cancellationToken).ConfigureAwait(false);
            if (emergency.Succeeded) return emergency with { Status = "Resolved through the explicitly configured emergency upstream." };
        }

        return new DnsUpstreamResult(false, null, null, false, "Every safe explicitly configured upstream DNS attempt failed.");
    }

    private async Task<DnsUpstreamResult> TryEndpointAsync(DnsEndpointIdentity endpoint, DnsWireQuestion question, CancellationToken cancellationToken)
    {
        for (var attempt = 0; attempt <= _options.RetryCount; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                var udp = await _transport.ExchangeAsync(endpoint, question.Packet, DnsTransportProtocol.Udp, _options.Timeout, cancellationToken).ConfigureAwait(false);
                if (!IsValidResponse(udp, question.TransactionId))
                {
                    RecordFailure(endpoint, "The UDP response was malformed or had a mismatched transaction ID.");
                    continue;
                }

                if (!DnsWireProtocol.IsTruncated(udp))
                {
                    RecordSuccess(endpoint, "Healthy over UDP");
                    return new DnsUpstreamResult(true, udp, endpoint, false, "Resolved over UDP.");
                }

                var tcp = await _transport.ExchangeAsync(endpoint, question.Packet, DnsTransportProtocol.Tcp, _options.Timeout, cancellationToken).ConfigureAwait(false);
                if (!IsValidResponse(tcp, question.TransactionId))
                {
                    RecordFailure(endpoint, "The TCP fallback response was malformed or had a mismatched transaction ID.");
                    continue;
                }

                RecordSuccess(endpoint, "Healthy with TCP fallback");
                return new DnsUpstreamResult(true, tcp, endpoint, true, "The truncated UDP response was retried successfully over TCP.");
            }
            catch (Exception exception) when (exception is TimeoutException or SocketException or IOException or InvalidDataException)
            {
                RecordFailure(endpoint, exception.GetType().Name);
            }
        }

        return new DnsUpstreamResult(false, null, endpoint, false, "The upstream endpoint exhausted its timeout and retry policy.");
    }

    private static bool IsValidResponse(ReadOnlySpan<byte> response, ushort transactionId) =>
        response.Length >= DnsWireProtocol.HeaderLength &&
        DnsWireProtocol.IsResponse(response) &&
        DnsWireProtocol.GetTransactionId(response) == transactionId;

    private static bool IsRecursiveEndpoint(DnsEndpointIdentity upstream, DnsEndpointIdentity local)
    {
        if (upstream.Port != local.Port) return false;
        return IPAddress.TryParse(upstream.Address, out var upstreamAddress) &&
               IPAddress.TryParse(local.Address, out var localAddress) &&
               upstreamAddress.Equals(localAddress);
    }

    private void RecordSuccess(DnsEndpointIdentity endpoint, string status)
    {
        lock (_sync) _health[endpoint] = new DnsUpstreamHealth(endpoint, true, 0, DateTimeOffset.UtcNow, status);
    }

    private void RecordFailure(DnsEndpointIdentity endpoint, string status)
    {
        lock (_sync)
        {
            var failures = _health.TryGetValue(endpoint, out var current) ? current.ConsecutiveFailures + 1 : 1;
            _health[endpoint] = new DnsUpstreamHealth(endpoint, false, failures, DateTimeOffset.UtcNow, status);
        }
    }

    private static DnsUpstreamOptions Validate(DnsUpstreamOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.Upstreams.Count == 0) throw new ArgumentException("At least one explicit upstream DNS server is required.", nameof(options));
        if (options.Timeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(options));
        if (options.RetryCount is < 0 or > 5) throw new ArgumentOutOfRangeException(nameof(options));
        foreach (var endpoint in options.Upstreams.Concat(options.EmergencyUpstream is null ? Array.Empty<DnsEndpointIdentity>() : new[] { options.EmergencyUpstream }))
        {
            if (!IPAddress.TryParse(endpoint.Address, out _) || endpoint.Port is < 1 or > 65535)
                throw new ArgumentException("Upstream endpoints require literal IP addresses and valid ports.", nameof(options));
        }

        if (options.FailurePolicy == DnsUpstreamFailurePolicy.FailOpenToExplicitEmergencyUpstream && options.EmergencyUpstream is null)
            throw new ArgumentException("Fail-open selection requires an explicitly configured emergency upstream.", nameof(options));
        return options;
    }
}
