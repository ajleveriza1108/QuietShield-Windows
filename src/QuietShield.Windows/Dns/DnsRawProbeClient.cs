using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using QuietShield.Core.Dns;

namespace QuietShield.Windows.Dns;

public enum DnsRawProbeProtocol
{
    Udp,
    Tcp
}

public sealed record DnsRawProbeResult(
    DnsRawProbeProtocol Protocol,
    string NormalizedQueryName,
    DnsWireResponseValidation Validation,
    int ResponseLength);

public static class DnsRawProbeClient
{
    public static async Task<DnsRawProbeResult> ProbeAsync(
        IPEndPoint endpoint,
        string domain,
        DnsRawProbeProtocol protocol,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(timeout, TimeSpan.Zero);
        var transactionId = checked((ushort)RandomNumberGenerator.GetInt32(1, ushort.MaxValue + 1));
        var query = DnsWireProtocol.CreateQuery(domain, 1, transactionId);
        var parsed = DnsWireProtocol.ParseQuery(query);
        if (!parsed.Succeeded || parsed.Question is null) throw new InvalidOperationException(parsed.Status);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        var response = protocol == DnsRawProbeProtocol.Udp
            ? await ProbeUdpAsync(endpoint, query, deadline.Token).ConfigureAwait(false)
            : await ProbeTcpAsync(endpoint, query, deadline.Token).ConfigureAwait(false);
        return new DnsRawProbeResult(
            protocol,
            parsed.Question.NormalizedDomain,
            DnsWireProtocol.ValidateResponse(response, parsed.Question),
            response.Length);
    }

    private static async Task<byte[]> ProbeUdpAsync(IPEndPoint endpoint, byte[] query, CancellationToken cancellationToken)
    {
        using var client = new UdpClient(endpoint.AddressFamily);
        await client.SendAsync(query, endpoint, cancellationToken).ConfigureAwait(false);
        var response = await client.ReceiveAsync(cancellationToken).ConfigureAwait(false);
        if (!response.RemoteEndPoint.Address.Equals(endpoint.Address) || response.RemoteEndPoint.Port != endpoint.Port)
            throw new InvalidDataException("The UDP DNS response came from an unexpected endpoint.");
        return response.Buffer;
    }

    private static async Task<byte[]> ProbeTcpAsync(IPEndPoint endpoint, byte[] query, CancellationToken cancellationToken)
    {
        using var client = new TcpClient(endpoint.AddressFamily);
        await client.ConnectAsync(endpoint.Address, endpoint.Port, cancellationToken).ConfigureAwait(false);
        await using var stream = client.GetStream();
        var prefix = new byte[2];
        BinaryPrimitives.WriteUInt16BigEndian(prefix, checked((ushort)query.Length));
        await stream.WriteAsync(prefix, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(query, cancellationToken).ConfigureAwait(false);
        await stream.ReadExactlyAsync(prefix, cancellationToken).ConfigureAwait(false);
        var responseLength = BinaryPrimitives.ReadUInt16BigEndian(prefix);
        if (responseLength is < DnsWireProtocol.HeaderLength or > DnsWireProtocol.MaximumUdpPacketSize)
            throw new InvalidDataException("The TCP DNS response length is invalid.");
        var response = new byte[responseLength];
        await stream.ReadExactlyAsync(response, cancellationToken).ConfigureAwait(false);
        return response;
    }
}
