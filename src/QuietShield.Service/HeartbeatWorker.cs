using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace QuietShield.Service;

public sealed partial class HeartbeatWorker : BackgroundService
{
    private static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(30);
    private readonly DiagnosticHeartbeat _heartbeat;
    private readonly ILogger<HeartbeatWorker> _logger;

    public HeartbeatWorker(DiagnosticHeartbeat heartbeat, ILogger<HeartbeatWorker> logger)
    {
        _heartbeat = heartbeat;
        _logger = logger;
    }

    public override Task StartAsync(CancellationToken cancellationToken)
    {
        LogStarting(_logger);
        return base.StartAsync(cancellationToken);
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken) =>
        _heartbeat.RunAsync(HeartbeatInterval, stoppingToken);

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        LogStopping(_logger);
        await base.StopAsync(cancellationToken).ConfigureAwait(false);
        LogStopped(_logger);
    }

    [LoggerMessage(
        EventId = 1101,
        Level = LogLevel.Information,
        Message = "QuietShield background-service foundation starting. No service, firewall, DNS, filtering, monitoring, or startup change is active.")]
    private static partial void LogStarting(ILogger logger);

    [LoggerMessage(
        EventId = 1102,
        Level = LogLevel.Information,
        Message = "QuietShield background-service foundation stopping.")]
    private static partial void LogStopping(ILogger logger);

    [LoggerMessage(
        EventId = 1103,
        Level = LogLevel.Information,
        Message = "QuietShield background-service foundation stopped cleanly.")]
    private static partial void LogStopped(ILogger logger);
}
