using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using QuietShield.Core.Dns;

namespace QuietShield.Windows.Dns;

public enum LocalDnsRuntimeState
{
    Stopped,
    Starting,
    Running,
    Stopping,
    Faulted
}

public enum LocalDnsBindingMode
{
    DynamicUnprivilegedDiagnostic,
    ApprovedTemporaryPort53Rehearsal
}

public sealed record LocalDnsRuntimeOptions(
    IPAddress ListenAddress,
    int ListenPort,
    int MaximumQuerySize,
    int MaximumConcurrentRequests,
    TimeSpan QueryTimeout,
    DnsIndeterminatePolicy IndeterminatePolicy,
    bool DiagnosticDomainLoggingEnabled)
{
    public LocalDnsBindingMode BindingMode { get; init; } = LocalDnsBindingMode.DynamicUnprivilegedDiagnostic;

    public static LocalDnsRuntimeOptions SafeDiagnosticDefaults { get; } = new(
        IPAddress.Loopback,
        0,
        DnsWireProtocol.MaximumUdpPacketSize,
        64,
        TimeSpan.FromSeconds(3),
        DnsIndeterminatePolicy.FailClosed,
        false);
}

public sealed record LocalDnsRuntimeStatus(LocalDnsRuntimeState State, int? BoundPort, int ActiveRequests, string Status);

public interface ILocalDnsRuntime : IAsyncDisposable
{
    LocalDnsRuntimeStatus GetStatus();
    Task<int> StartAsync(CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
}

public sealed class LocalDnsRuntime : ILocalDnsRuntime
{
    private readonly object _sync = new();
    private readonly LocalDnsRuntimeOptions _options;
    private readonly IDnsRuntimePolicyEvaluator _policy;
    private readonly IDnsRawUpstreamResolver _upstream;
    private readonly IDnsRuntimeEventSink _events;
    private readonly SemaphoreSlim _concurrency;
    private readonly ConcurrentDictionary<long, Task> _requests = new();
    private CancellationTokenSource? _shutdown;
    private TcpListener? _tcp;
    private UdpClient? _udp;
    private Task? _udpLoop;
    private Task? _tcpLoop;
    private LocalDnsRuntimeState _state = LocalDnsRuntimeState.Stopped;
    private string _status = "DNS runtime is stopped.";
    private long _requestSequence;

    public LocalDnsRuntime(
        LocalDnsRuntimeOptions options,
        IDnsRuntimePolicyEvaluator policy,
        IDnsRawUpstreamResolver upstream,
        IDnsRuntimeEventSink? events = null)
    {
        _options = Validate(options);
        _policy = policy;
        _upstream = upstream;
        _events = events ?? NullDnsRuntimeEventSink.Instance;
        _concurrency = new SemaphoreSlim(options.MaximumConcurrentRequests, options.MaximumConcurrentRequests);
    }

    public LocalDnsRuntimeStatus GetStatus()
    {
        lock (_sync) return new LocalDnsRuntimeStatus(_state, (_tcp?.LocalEndpoint as IPEndPoint)?.Port, _requests.Count, _status);
    }

    public Task<int> StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            if (_state == LocalDnsRuntimeState.Running) return Task.FromResult(((IPEndPoint)_tcp!.LocalEndpoint).Port);
            if (_state is not LocalDnsRuntimeState.Stopped) throw new InvalidOperationException("The DNS runtime is not in a startable state.");
            _state = LocalDnsRuntimeState.Starting;
            _status = "Starting loopback DNS runtime.";
            try
            {
                _shutdown = new CancellationTokenSource();
                _tcp = new TcpListener(_options.ListenAddress, _options.ListenPort);
                _tcp.Start(_options.MaximumConcurrentRequests);
                var port = ((IPEndPoint)_tcp.LocalEndpoint).Port;
                _udp = new UdpClient(new IPEndPoint(_options.ListenAddress, port));
                _udpLoop = RunUdpLoopAsync(_shutdown.Token);
                _tcpLoop = RunTcpLoopAsync(_shutdown.Token);
                _state = LocalDnsRuntimeState.Running;
                _status = _options.BindingMode == LocalDnsBindingMode.ApprovedTemporaryPort53Rehearsal
                    ? "DNS runtime is listening temporarily on loopback UDP and TCP port 53 for an approved rehearsal."
                    : "DNS runtime is listening on loopback UDP and TCP at a dynamic unprivileged port.";
                WriteEvent("Started", _status, null);
                return Task.FromResult(port);
            }
            catch
            {
                _udp?.Dispose();
                _tcp?.Stop();
                _shutdown?.Dispose();
                _udp = null;
                _tcp = null;
                _shutdown = null;
                _state = LocalDnsRuntimeState.Faulted;
                _status = "DNS runtime failed to start.";
                throw;
            }
        }
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        Task[] loops;
        lock (_sync)
        {
            if (_state == LocalDnsRuntimeState.Stopped) return;
            _state = LocalDnsRuntimeState.Stopping;
            _status = "DNS runtime is stopping.";
            _shutdown?.Cancel();
            _udp?.Dispose();
            _tcp?.Stop();
            loops = new[] { _udpLoop, _tcpLoop }.Where(static task => task is not null).Cast<Task>().ToArray();
        }

        await AwaitShutdownTasksAsync(loops.Concat(_requests.Values).ToArray(), cancellationToken).ConfigureAwait(false);
        lock (_sync)
        {
            _udp = null;
            _tcp = null;
            _udpLoop = null;
            _tcpLoop = null;
            _shutdown?.Dispose();
            _shutdown = null;
            _state = LocalDnsRuntimeState.Stopped;
            _status = "DNS runtime stopped cleanly.";
            WriteEvent("Stopped", _status, null);
        }
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync(CancellationToken.None).ConfigureAwait(false);
        _concurrency.Dispose();
        GC.SuppressFinalize(this);
    }

    private async Task RunUdpLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var packet = await _udp!.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                await _concurrency.WaitAsync(cancellationToken).ConfigureAwait(false);
                Track(HandleUdpAsync(packet, cancellationToken));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
            catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested) { break; }
            catch (SocketException) when (cancellationToken.IsCancellationRequested) { break; }
        }
    }

    private async Task RunTcpLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var client = await _tcp!.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                await _concurrency.WaitAsync(cancellationToken).ConfigureAwait(false);
                Track(HandleTcpAsync(client, cancellationToken));
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { break; }
            catch (ObjectDisposedException) when (cancellationToken.IsCancellationRequested) { break; }
            catch (SocketException) when (cancellationToken.IsCancellationRequested) { break; }
        }
    }

    private async Task HandleUdpAsync(UdpReceiveResult received, CancellationToken shutdownToken)
    {
        try
        {
            var response = await ProcessAsync(received.Buffer, shutdownToken).ConfigureAwait(false);
            if (response is not null && _udp is not null) await _udp.SendAsync(response, received.RemoteEndPoint, shutdownToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (shutdownToken.IsCancellationRequested) { }
        catch (ObjectDisposedException) when (shutdownToken.IsCancellationRequested) { }
        finally { _concurrency.Release(); }
    }

    private async Task HandleTcpAsync(TcpClient client, CancellationToken shutdownToken)
    {
        using (client)
        {
            try
            {
                await using var stream = client.GetStream();
                var lengthPrefix = new byte[2];
                await stream.ReadExactlyAsync(lengthPrefix, shutdownToken).ConfigureAwait(false);
                var length = BinaryPrimitives.ReadUInt16BigEndian(lengthPrefix);
                if (length == 0 || length > _options.MaximumQuerySize)
                {
                    var formatError = DnsWireProtocol.CreateFormatError(Array.Empty<byte>());
                    BinaryPrimitives.WriteUInt16BigEndian(lengthPrefix, checked((ushort)formatError.Length));
                    await stream.WriteAsync(lengthPrefix, shutdownToken).ConfigureAwait(false);
                    await stream.WriteAsync(formatError, shutdownToken).ConfigureAwait(false);
                    return;
                }

                var packet = new byte[length];
                await stream.ReadExactlyAsync(packet, shutdownToken).ConfigureAwait(false);
                var response = await ProcessAsync(packet, shutdownToken).ConfigureAwait(false);
                if (response is null) return;
                BinaryPrimitives.WriteUInt16BigEndian(lengthPrefix, checked((ushort)response.Length));
                await stream.WriteAsync(lengthPrefix, shutdownToken).ConfigureAwait(false);
                await stream.WriteAsync(response, shutdownToken).ConfigureAwait(false);
            }
            catch (EndOfStreamException) { }
            catch (OperationCanceledException) when (shutdownToken.IsCancellationRequested) { }
            catch (IOException) when (shutdownToken.IsCancellationRequested) { }
            finally { _concurrency.Release(); }
        }
    }

    private async Task<byte[]?> ProcessAsync(byte[] packet, CancellationToken shutdownToken)
    {
        if (packet.Length > _options.MaximumQuerySize) return DnsWireProtocol.CreateFormatError(packet);
        var parse = DnsWireProtocol.ParseQuery(packet, _options.MaximumQuerySize);
        if (!parse.Succeeded || parse.Question is null)
        {
            WriteEvent("RejectedMalformedQuery", parse.Status, null);
            return DnsWireProtocol.CreateFormatError(packet);
        }

        var question = parse.Question;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(shutdownToken);
        deadline.CancelAfter(_options.QueryTimeout);
        try
        {
            var decision = await _policy.EvaluateAsync(question.NormalizedDomain, deadline.Token).ConfigureAwait(false);
            WriteEvent("PolicyDecision", decision.Decision.ToString(), question.NormalizedDomain);
            if (decision.Decision == DnsDecision.Block)
                return DnsWireProtocol.CreateResponse(question, DnsResponseCode.NameError);
            if (decision.Decision == DnsDecision.Indeterminate && _options.IndeterminatePolicy == DnsIndeterminatePolicy.FailClosed)
                return DnsWireProtocol.CreateResponse(question, DnsResponseCode.ServerFailure);

            var port = GetStatus().BoundPort ?? throw new InvalidOperationException("The local endpoint is unavailable.");
            var upstream = await _upstream.ResolveAsync(question, new DnsEndpointIdentity(_options.ListenAddress.ToString(), port, "QuietShield local runtime"), deadline.Token).ConfigureAwait(false);
            if (!upstream.Succeeded || upstream.Response is null)
                return DnsWireProtocol.CreateResponse(question, DnsResponseCode.ServerFailure);
            if (DnsWireProtocol.GetTransactionId(upstream.Response) != question.TransactionId || !DnsWireProtocol.IsResponse(upstream.Response))
                return DnsWireProtocol.CreateResponse(question, DnsResponseCode.ServerFailure);
            return upstream.Response;
        }
        catch (OperationCanceledException) when (!shutdownToken.IsCancellationRequested)
        {
            WriteEvent("QueryTimeout", "The bounded query deadline elapsed.", question.NormalizedDomain);
            return DnsWireProtocol.CreateResponse(question, DnsResponseCode.ServerFailure);
        }
    }

    private void Track(Task task)
    {
        var sequence = Interlocked.Increment(ref _requestSequence);
        _requests[sequence] = task;
        _ = task.ContinueWith(
            completedTask => _requests.TryRemove(sequence, out _),
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private void WriteEvent(string eventName, string status, string? domain) =>
        _events.Write(new DnsRuntimeLogEntry(
            eventName,
            status,
            _options.DiagnosticDomainLoggingEnabled ? domain : null,
            DateTimeOffset.UtcNow));

    private static async Task AwaitShutdownTasksAsync(Task[] tasks, CancellationToken cancellationToken)
    {
        if (tasks.Length == 0) return;
        var allTasks = Task.WhenAll(tasks);
        try { await allTasks.WaitAsync(cancellationToken).ConfigureAwait(false); }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception) when (allTasks.IsCompleted) { }
    }

    private static LocalDnsRuntimeOptions Validate(LocalDnsRuntimeOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!IPAddress.IsLoopback(options.ListenAddress)) throw new ArgumentException("Phase 4 DNS runtime may bind only to loopback.", nameof(options));
        if (options.BindingMode == LocalDnsBindingMode.DynamicUnprivilegedDiagnostic && (options.ListenPort is > 0 and <= 1023 || options.ListenPort > 65535))
            throw new ArgumentException("Diagnostic DNS runtime requires a dynamic or unprivileged port and never permits port 53.", nameof(options));
        if (options.BindingMode == LocalDnsBindingMode.ApprovedTemporaryPort53Rehearsal && options.ListenPort != 53)
            throw new ArgumentException("The approved temporary rehearsal binding mode permits only loopback port 53.", nameof(options));
        if (options.MaximumQuerySize is < DnsWireProtocol.HeaderLength or > ushort.MaxValue) throw new ArgumentOutOfRangeException(nameof(options));
        if (options.MaximumConcurrentRequests is < 1 or > 1024) throw new ArgumentOutOfRangeException(nameof(options));
        if (options.QueryTimeout <= TimeSpan.Zero || options.QueryTimeout > TimeSpan.FromMinutes(1)) throw new ArgumentOutOfRangeException(nameof(options));
        return options;
    }
}
