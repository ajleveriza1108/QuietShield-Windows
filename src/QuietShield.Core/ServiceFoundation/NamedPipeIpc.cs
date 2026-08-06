using System.Buffers.Binary;
using System.IO.Pipes;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace QuietShield.Core.ServiceFoundation;

public static class ServiceMessageSerializer
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        Converters = { new JsonStringEnumConverter() }
    };

    public static JsonElement EmptyPayload => JsonSerializer.SerializeToElement(new { }, Options);
    public static JsonElement ToPayload(object? value) => value is null ? EmptyPayload : JsonSerializer.SerializeToElement(value, Options);
}

public static class BoundedMessageFrame
{
    public static async Task WriteAsync(Stream stream, ReadOnlyMemory<byte> message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (message.Length <= 0 || message.Length > QuietShieldServiceProtocol.MaximumMessageBytes)
            throw new InvalidDataException($"IPC messages must contain 1 to {QuietShieldServiceProtocol.MaximumMessageBytes} bytes.");
        var header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(header, message.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(message, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async Task<byte[]> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var header = new byte[sizeof(int)];
        await ReadExactlyAsync(stream, header, cancellationToken).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > QuietShieldServiceProtocol.MaximumMessageBytes)
            throw new InvalidDataException($"IPC frame length {length} is outside the permitted bound.");
        var message = new byte[length];
        await ReadExactlyAsync(stream, message, cancellationToken).ConfigureAwait(false);
        return message;
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer[offset..], cancellationToken).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException("The IPC peer disconnected before completing a frame.");
            offset += read;
        }
    }
}

public sealed class NamedPipeQuietShieldServiceClient : IQuietShieldServiceClient
{
    private readonly string _pipeName;
    private readonly TimeSpan _timeout;
    private readonly bool _currentUserOnly;

    public NamedPipeQuietShieldServiceClient(string pipeName, TimeSpan? timeout = null, bool currentUserOnly = true)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        _pipeName = pipeName;
        _timeout = timeout ?? QuietShieldServiceProtocol.DefaultTimeout;
        _currentUserOnly = currentUserOnly;
        if (_timeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(timeout));
    }

    public async Task<ServiceResponse> SendAsync(ServiceMessageKind messageKind, object? payload, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_timeout);
        var options = _currentUserOnly ? PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly : PipeOptions.Asynchronous;
        await using var client = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, options);
        await client.ConnectAsync(timeout.Token).ConfigureAwait(false);
        var request = new ServiceRequest(QuietShieldServiceProtocol.CurrentVersion, Guid.NewGuid(), messageKind, ServiceMessageSerializer.ToPayload(payload));
        var requestBytes = JsonSerializer.SerializeToUtf8Bytes(request, ServiceMessageSerializer.Options);
        await BoundedMessageFrame.WriteAsync(client, requestBytes, timeout.Token).ConfigureAwait(false);
        var responseBytes = await BoundedMessageFrame.ReadAsync(client, timeout.Token).ConfigureAwait(false);
        return JsonSerializer.Deserialize<ServiceResponse>(responseBytes, ServiceMessageSerializer.Options)
               ?? throw new InvalidDataException("The IPC response was empty.");
    }
}

public sealed class NamedPipeQuietShieldServer
{
    private readonly string _pipeName;
    private readonly IQuietShieldServiceRequestHandler _handler;
    private readonly TimeSpan _requestTimeout;
    private readonly Func<NamedPipeServerStream> _serverFactory;

    public NamedPipeQuietShieldServer(
        string pipeName,
        IQuietShieldServiceRequestHandler handler,
        TimeSpan? requestTimeout = null,
        Func<NamedPipeServerStream>? serverFactory = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pipeName);
        _pipeName = pipeName;
        _handler = handler ?? throw new ArgumentNullException(nameof(handler));
        _requestTimeout = requestTimeout ?? QuietShieldServiceProtocol.DefaultTimeout;
        if (_requestTimeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(requestTimeout));
        _serverFactory = serverFactory ?? (() => new NamedPipeServerStream(
            _pipeName,
            PipeDirection.InOut,
            NamedPipeServerStream.MaxAllowedServerInstances,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly));
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            await using var server = _serverFactory();
            try
            {
                await server.WaitForConnectionAsync(cancellationToken).ConfigureAwait(false);
                await ProcessConnectionAsync(server, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception) when (exception is IOException or InvalidDataException or JsonException)
            {
                // The next loop creates a clean local endpoint. Message content is deliberately not logged.
            }
        }
    }

    private async Task ProcessConnectionAsync(Stream stream, CancellationToken stoppingToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        timeout.CancelAfter(_requestTimeout);
        ServiceResponse response;
        try
        {
            var requestBytes = await BoundedMessageFrame.ReadAsync(stream, timeout.Token).ConfigureAwait(false);
            var request = JsonSerializer.Deserialize<ServiceRequest>(requestBytes, ServiceMessageSerializer.Options)
                          ?? throw new InvalidDataException("The IPC request was empty.");
            if (request.RequestId == Guid.Empty) throw new InvalidDataException("The IPC request ID is required.");
            response = request.ProtocolVersion == QuietShieldServiceProtocol.CurrentVersion
                ? await _handler.HandleAsync(request, timeout.Token).ConfigureAwait(false)
                : new(QuietShieldServiceProtocol.CurrentVersion, request.RequestId, ServiceResponseStatus.UnsupportedProtocol,
                    $"Protocol version {request.ProtocolVersion} is unsupported.", ServiceMessageSerializer.EmptyPayload);
        }
        catch (Exception exception) when (exception is JsonException or InvalidDataException)
        {
            response = new(QuietShieldServiceProtocol.CurrentVersion, Guid.Empty, ServiceResponseStatus.InvalidRequest,
                "Malformed or invalid IPC request rejected.", ServiceMessageSerializer.EmptyPayload);
        }
        var bytes = JsonSerializer.SerializeToUtf8Bytes(response, ServiceMessageSerializer.Options);
        await BoundedMessageFrame.WriteAsync(stream, bytes, timeout.Token).ConfigureAwait(false);
    }
}
