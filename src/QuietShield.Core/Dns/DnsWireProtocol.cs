using System.Buffers.Binary;
using System.Text;

namespace QuietShield.Core.Dns;

public enum DnsResponseCode : byte
{
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5
}

public sealed record DnsWireQuestion(
    ushort TransactionId,
    ushort Flags,
    string NormalizedDomain,
    ushort QueryType,
    ushort QueryClass,
    int QuestionEndOffset,
    byte[] Packet);

public sealed record DnsWireParseResult(bool Succeeded, DnsWireQuestion? Question, string Status);

public static class DnsWireProtocol
{
    public const int HeaderLength = 12;
    public const int MaximumUdpPacketSize = 4096;
    private const int MaximumCompressionDepth = 16;

    public static DnsWireParseResult ParseQuery(ReadOnlySpan<byte> packet, int maximumSize = MaximumUdpPacketSize)
    {
        if (packet.Length < HeaderLength) return Failed("The DNS packet is shorter than its header.");
        if (packet.Length > maximumSize) return Failed("The DNS packet exceeds the configured query-size limit.");

        var flags = BinaryPrimitives.ReadUInt16BigEndian(packet[2..4]);
        if ((flags & 0x8000) != 0) return Failed("A DNS query cannot have the response flag set.");
        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(packet[4..6]);
        if (questionCount != 1) return Failed("Exactly one DNS question is required.");

        var offset = HeaderLength;
        if (!TryReadName(packet, ref offset, out var domain, out var nameError)) return Failed(nameError!);
        if (offset + 4 > packet.Length) return Failed("The DNS question is truncated.");

        var queryType = BinaryPrimitives.ReadUInt16BigEndian(packet[offset..(offset + 2)]);
        var queryClass = BinaryPrimitives.ReadUInt16BigEndian(packet[(offset + 2)..(offset + 4)]);
        offset += 4;
        var normalized = DomainNormalizer.NormalizeDomain(domain);
        if (!normalized.IsValid || normalized.NormalizedValue is null) return Failed(normalized.Error ?? "The DNS question name is invalid.");

        return new DnsWireParseResult(
            true,
            new DnsWireQuestion(
                BinaryPrimitives.ReadUInt16BigEndian(packet[..2]),
                flags,
                normalized.NormalizedValue,
                queryType,
                queryClass,
                offset,
                packet.ToArray()),
            "The DNS query is valid.");
    }

    public static byte[] CreateQuery(string domain, ushort queryType, ushort transactionId, bool recursionDesired = true)
    {
        var normalized = DomainNormalizer.NormalizeDomain(domain);
        if (!normalized.IsValid || normalized.NormalizedValue is null) throw new ArgumentException(normalized.Error, nameof(domain));
        var labels = normalized.NormalizedValue.Split('.');
        var length = HeaderLength + labels.Sum(static label => 1 + Encoding.ASCII.GetByteCount(label)) + 1 + 4;
        var packet = new byte[length];
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(0, 2), transactionId);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(2, 2), recursionDesired ? (ushort)0x0100 : (ushort)0);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(4, 2), 1);
        var offset = HeaderLength;
        foreach (var label in labels)
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            packet[offset++] = checked((byte)bytes.Length);
            bytes.CopyTo(packet, offset);
            offset += bytes.Length;
        }

        packet[offset++] = 0;
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset, 2), queryType);
        BinaryPrimitives.WriteUInt16BigEndian(packet.AsSpan(offset + 2, 2), 1);
        return packet;
    }

    public static byte[] CreateResponse(DnsWireQuestion question, DnsResponseCode responseCode)
    {
        ArgumentNullException.ThrowIfNull(question);
        var response = new byte[question.QuestionEndOffset];
        question.Packet.AsSpan(0, question.QuestionEndOffset).CopyTo(response);
        var flags = (ushort)(0x8000 | (question.Flags & 0x7910) | (byte)responseCode);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), flags);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(4, 2), 1);
        response.AsSpan(6, 6).Clear();
        return response;
    }

    public static byte[] CreateFormatError(ReadOnlySpan<byte> packet)
    {
        var response = new byte[HeaderLength];
        if (packet.Length >= 2) packet[..2].CopyTo(response);
        ushort queryFlags = 0;
        if (packet.Length >= 4) queryFlags = BinaryPrimitives.ReadUInt16BigEndian(packet[2..4]);
        BinaryPrimitives.WriteUInt16BigEndian(response.AsSpan(2, 2), (ushort)(0x8000 | (queryFlags & 0x7910) | (byte)DnsResponseCode.FormatError));
        return response;
    }

    public static ushort GetTransactionId(ReadOnlySpan<byte> packet) =>
        packet.Length >= 2 ? BinaryPrimitives.ReadUInt16BigEndian(packet[..2]) : (ushort)0;

    public static DnsResponseCode GetResponseCode(ReadOnlySpan<byte> packet) =>
        packet.Length >= 4 ? (DnsResponseCode)(BinaryPrimitives.ReadUInt16BigEndian(packet[2..4]) & 0x000F) : DnsResponseCode.FormatError;

    public static bool IsTruncated(ReadOnlySpan<byte> packet) =>
        packet.Length >= 4 && (BinaryPrimitives.ReadUInt16BigEndian(packet[2..4]) & 0x0200) != 0;

    public static bool IsResponse(ReadOnlySpan<byte> packet) =>
        packet.Length >= 4 && (BinaryPrimitives.ReadUInt16BigEndian(packet[2..4]) & 0x8000) != 0;

    private static bool TryReadName(ReadOnlySpan<byte> packet, ref int offset, out string domain, out string? error)
    {
        var labels = new List<string>();
        var visited = new HashSet<int>();
        var cursor = offset;
        var nextOffset = -1;
        var depth = 0;

        while (true)
        {
            if (cursor >= packet.Length)
            {
                domain = string.Empty;
                error = "The DNS question name is truncated.";
                return false;
            }

            var length = packet[cursor++];
            if ((length & 0xC0) == 0xC0)
            {
                if (cursor >= packet.Length)
                {
                    domain = string.Empty;
                    error = "The DNS compression pointer is truncated.";
                    return false;
                }

                var pointer = ((length & 0x3F) << 8) | packet[cursor++];
                if (pointer < HeaderLength || pointer >= packet.Length || !visited.Add(pointer) || ++depth > MaximumCompressionDepth)
                {
                    domain = string.Empty;
                    error = "The DNS compression pointer is invalid or recursive.";
                    return false;
                }

                if (nextOffset < 0) nextOffset = cursor;
                cursor = pointer;
                continue;
            }

            if ((length & 0xC0) != 0 || length > 63)
            {
                domain = string.Empty;
                error = "The DNS label length is invalid.";
                return false;
            }

            if (length == 0)
            {
                offset = nextOffset >= 0 ? nextOffset : cursor;
                domain = string.Join('.', labels);
                error = null;
                return labels.Count > 0;
            }

            if (cursor + length > packet.Length)
            {
                domain = string.Empty;
                error = "The DNS label is truncated.";
                return false;
            }

            var labelBytes = packet.Slice(cursor, length);
            if (labelBytes.ContainsAnyExceptInRange((byte)0x21, (byte)0x7E))
            {
                domain = string.Empty;
                error = "The DNS label contains unsupported bytes.";
                return false;
            }

            labels.Add(Encoding.ASCII.GetString(labelBytes));
            cursor += length;
            if (labels.Sum(static label => label.Length + 1) > 254)
            {
                domain = string.Empty;
                error = "The DNS question name exceeds the maximum length.";
                return false;
            }
        }
    }

    private static DnsWireParseResult Failed(string status) => new(false, null, status);
}
