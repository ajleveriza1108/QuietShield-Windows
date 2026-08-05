using Microsoft.Extensions.Logging;
using QuietShield.Windows.Dns;

namespace QuietShield.Service;

public enum DnsServiceHealthState
{
    Stopped,
    Starting,
    Healthy,
    Degraded,
    Stopping,
    Failed
}

public sealed record DnsServiceHealthSnapshot(
    DnsServiceHealthState State,
    int? BoundPort,
    DateTimeOffset UpdatedAtUtc,
    DateTimeOffset? LastHeartbeatUtc,
    string Status,
    string? FailureReason);

public sealed record DnsServicePreflightResult(bool Succeeded, string Status);

public interface IDnsServiceStartupPreflight
{
    Task<DnsServicePreflightResult> RunAsync(CancellationToken cancellationToken);
}

public sealed partial class DnsRuntimeServiceCoordinator
{
    private readonly object _sync = new();
    private readonly ILocalDnsRuntime _runtime;
    private readonly IDnsServiceStartupPreflight _preflight;
    private readonly ILogger<DnsRuntimeServiceCoordinator> _logger;
    private DnsServiceHealthSnapshot _health = new(
        DnsServiceHealthState.Stopped, null, DateTimeOffset.UtcNow, null,
        "DNS service runtime foundation is stopped and not registered as a Windows service.", null);

    public DnsRuntimeServiceCoordinator(
        ILocalDnsRuntime runtime,
        IDnsServiceStartupPreflight preflight,
        ILogger<DnsRuntimeServiceCoordinator> logger)
    {
        _runtime = runtime;
        _preflight = preflight;
        _logger = logger;
    }

    public DnsServiceHealthSnapshot GetHealth()
    {
        lock (_sync) return _health;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        SetHealth(DnsServiceHealthState.Starting, null, "DNS runtime startup preflight is running.", null);
        LogStarting(_logger);
        var preflight = await _preflight.RunAsync(cancellationToken).ConfigureAwait(false);
        if (!preflight.Succeeded)
        {
            SetHealth(DnsServiceHealthState.Failed, null, "DNS runtime startup preflight failed.", preflight.Status);
            LogFailure(_logger, preflight.Status);
            return;
        }

        try
        {
            var port = await _runtime.StartAsync(cancellationToken).ConfigureAwait(false);
            SetHealth(DnsServiceHealthState.Healthy, port, "DNS runtime started on the approved loopback diagnostic endpoint.", null);
            RecordHeartbeat();
            LogStarted(_logger, port);
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or System.Net.Sockets.SocketException)
        {
            SetHealth(DnsServiceHealthState.Failed, null, "DNS runtime failed to start.", exception.Message);
            LogFailure(_logger, exception.Message);
        }
    }

    public void RecordHeartbeat()
    {
        lock (_sync)
        {
            _health = _health with { LastHeartbeatUtc = DateTimeOffset.UtcNow, UpdatedAtUtc = DateTimeOffset.UtcNow };
        }
        LogHeartbeat(_logger);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        SetHealth(DnsServiceHealthState.Stopping, GetHealth().BoundPort, "DNS runtime shutdown cleanup is running.", null);
        LogStopping(_logger);
        try
        {
            await _runtime.StopAsync(cancellationToken).ConfigureAwait(false);
            SetHealth(DnsServiceHealthState.Stopped, null, "DNS runtime stopped and released its loopback sockets cleanly.", null);
            LogStopped(_logger);
        }
        catch (Exception exception) when (exception is IOException or InvalidOperationException or System.Net.Sockets.SocketException)
        {
            SetHealth(DnsServiceHealthState.Failed, GetHealth().BoundPort, "DNS runtime shutdown cleanup failed.", exception.Message);
            LogFailure(_logger, exception.Message);
        }
    }

    private void SetHealth(DnsServiceHealthState state, int? port, string status, string? failure)
    {
        lock (_sync) _health = new DnsServiceHealthSnapshot(state, port, DateTimeOffset.UtcNow, _health.LastHeartbeatUtc, status, failure);
    }

    [LoggerMessage(EventId = 1201, Level = LogLevel.Information, Message = "QuietShield DNS runtime startup preflight beginning; Windows service registration and system DNS activation remain disabled.")]
    private static partial void LogStarting(ILogger logger);

    [LoggerMessage(EventId = 1202, Level = LogLevel.Information, Message = "QuietShield DNS runtime started on loopback port {Port}.")]
    private static partial void LogStarted(ILogger logger, int port);

    [LoggerMessage(EventId = 1203, Level = LogLevel.Debug, Message = "QuietShield DNS runtime health heartbeat recorded.")]
    private static partial void LogHeartbeat(ILogger logger);

    [LoggerMessage(EventId = 1204, Level = LogLevel.Information, Message = "QuietShield DNS runtime shutdown cleanup beginning.")]
    private static partial void LogStopping(ILogger logger);

    [LoggerMessage(EventId = 1205, Level = LogLevel.Information, Message = "QuietShield DNS runtime stopped cleanly.")]
    private static partial void LogStopped(ILogger logger);

    [LoggerMessage(EventId = 1206, Level = LogLevel.Error, Message = "QuietShield DNS runtime operation failed: {FailureReason}")]
    private static partial void LogFailure(ILogger logger, string failureReason);
}
