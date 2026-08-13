// QuietShield Backend Pack 1-4 R1
using System.Net;
using System.Net.Sockets;
using System.Text;
using QuietShield.Core.Backends;

namespace QuietShield.Windows.Backends;

public sealed record DnsProxyMetrics(
    long TotalQueries,
    long AllowedQueries,
    long BlockedQueries,
    long FailedQueries,
    int ListenPort);

public sealed class DnsProxyServer : IAsyncDisposable
{
    private readonly DnsPolicyEngine _policy;
    private readonly DnsProxyConfiguration _configuration;
    private UdpClient? _listener;
    private CancellationTokenSource? _cts;
    private Task? _loopTask;
    private long _total;
    private long _allowed;
    private long _blocked;
    private long _failed;

    public DnsProxyServer(
        DnsPolicyEngine policy,
        DnsProxyConfiguration configuration)
    {
        _policy = policy ?? throw new ArgumentNullException(nameof(policy));
        _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));

        if (_configuration.UpstreamPort is < 1 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(configuration), "Upstream DNS port is invalid.");
        }

        if (_configuration.ListenPort is < 0 or > 65535)
        {
            throw new ArgumentOutOfRangeException(nameof(configuration), "Listen port is invalid.");
        }

        if (IPAddress.IsLoopback(_configuration.UpstreamAddress))
        {
            throw new ArgumentException("The DNS proxy upstream cannot be a loopback address.", nameof(configuration));
        }
    }

    public int ListenPort { get; private set; }

    public int Start()
    {
        if (_listener is not null)
        {
            throw new InvalidOperationException("DNS proxy is already running.");
        }

        _listener = new UdpClient(AddressFamily.InterNetwork);
        _listener.Client.ExclusiveAddressUse = true;
        _listener.Client.Bind(new IPEndPoint(IPAddress.Loopback, _configuration.ListenPort));

        ListenPort = ((IPEndPoint)_listener.Client.LocalEndPoint!).Port;
        _cts = new CancellationTokenSource();
        _loopTask = Task.Run(() => RunLoopAsync(_cts.Token));
        return ListenPort;
    }

    public DnsProxyMetrics GetMetrics() =>
        new(
            Interlocked.Read(ref _total),
            Interlocked.Read(ref _allowed),
            Interlocked.Read(ref _blocked),
            Interlocked.Read(ref _failed),
            ListenPort);

    public async Task StopAsync()
    {
        var listener = _listener;
        if (listener is null)
        {
            return;
        }

        _cts?.Cancel();
        listener.Dispose();

        if (_loopTask is not null)
        {
            try
            {
                await _loopTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
            catch (ObjectDisposedException)
            {
            }
        }

        _loopTask = null;
        _cts?.Dispose();
        _cts = null;
        _listener = null;
    }

    private async Task RunLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            UdpReceiveResult request;
            try
            {
                request = await _listener!.ReceiveAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }

            await HandleQueryAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task HandleQueryAsync(
        UdpReceiveResult request,
        CancellationToken cancellationToken)
    {
        Interlocked.Increment(ref _total);

        try
        {
            if (!TryReadQuestionName(request.Buffer, out var host))
            {
                Interlocked.Increment(ref _failed);
                await SendResponseAsync(
                    BuildErrorResponse(request.Buffer, 1),
                    request.RemoteEndPoint,
                    cancellationToken).ConfigureAwait(false);
                return;
            }

            var decision = _policy.Evaluate(host);
            if (decision.Action == DnsPolicyAction.Block)
            {
                Interlocked.Increment(ref _blocked);
                await SendResponseAsync(
                    BuildErrorResponse(request.Buffer, 3),
                    request.RemoteEndPoint,
                    cancellationToken).ConfigureAwait(false);
                return;
            }

            Interlocked.Increment(ref _allowed);

            using var upstream = new UdpClient(AddressFamily.InterNetwork);
            var upstreamEndPoint = new IPEndPoint(
                _configuration.UpstreamAddress,
                _configuration.UpstreamPort);

            await upstream.SendAsync(
                request.Buffer,
                request.Buffer.Length,
                upstreamEndPoint).ConfigureAwait(false);

            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_configuration.EffectiveQueryTimeout);

            var reply = await upstream.ReceiveAsync(timeout.Token).ConfigureAwait(false);
            await SendResponseAsync(
                reply.Buffer,
                request.RemoteEndPoint,
                cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            Interlocked.Increment(ref _failed);
            await TrySendServFailAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (SocketException)
        {
            Interlocked.Increment(ref _failed);
            await TrySendServFailAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            Interlocked.Increment(ref _failed);
            await TrySendServFailAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }

    private async Task TrySendServFailAsync(
        UdpReceiveResult request,
        CancellationToken cancellationToken)
    {
        try
        {
            await SendResponseAsync(
                BuildErrorResponse(request.Buffer, 2),
                request.RemoteEndPoint,
                cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // The original query has already been accounted as failed.
        }
    }

    private async Task SendResponseAsync(
        byte[] response,
        IPEndPoint remote,
        CancellationToken cancellationToken)
    {
        if (_listener is null)
        {
            return;
        }

        await _listener.SendAsync(
            response,
            remote,
            cancellationToken).ConfigureAwait(false);
    }

    internal static bool TryReadQuestionName(
        byte[] packet,
        out string host)
    {
        host = string.Empty;

        if (packet.Length < 17)
        {
            return false;
        }

        var questionCount = (packet[4] << 8) | packet[5];
        if (questionCount < 1)
        {
            return false;
        }

        var offset = 12;
        var labels = new List<string>();

        while (offset < packet.Length)
        {
            var length = packet[offset++];

            if (length == 0)
            {
                break;
            }

            if ((length & 0xC0) != 0 || length > 63 || offset + length > packet.Length)
            {
                return false;
            }

            labels.Add(Encoding.ASCII.GetString(packet, offset, length));
            offset += length;
        }

        if (labels.Count == 0 || offset + 4 > packet.Length)
        {
            return false;
        }

        host = string.Join('.', labels);
        return true;
    }

    internal static byte[] BuildErrorResponse(
        byte[] query,
        int responseCode)
    {
        var response = query.ToArray();
        if (response.Length < 12)
        {
            return response;
        }

        response[2] = (byte)(response[2] | 0x80);
        response[3] = (byte)((response[3] & 0xF0) | (responseCode & 0x0F));

        // Preserve the original question count; clear answer/authority/additional.
        response[6] = 0;
        response[7] = 0;
        response[8] = 0;
        response[9] = 0;
        response[10] = 0;
        response[11] = 0;

        return response;
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync().ConfigureAwait(false);
        GC.SuppressFinalize(this);
    }
}
