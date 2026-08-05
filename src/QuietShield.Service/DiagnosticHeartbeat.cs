using Microsoft.Extensions.Logging;

namespace QuietShield.Service;

public interface IHeartbeatDelay
{
    Task WaitAsync(TimeSpan interval, CancellationToken cancellationToken);
}

public sealed class SystemHeartbeatDelay : IHeartbeatDelay
{
    public Task WaitAsync(TimeSpan interval, CancellationToken cancellationToken) =>
        Task.Delay(interval, cancellationToken);
}

public sealed partial class DiagnosticHeartbeat
{
    private readonly ILogger<DiagnosticHeartbeat> _logger;
    private readonly IHeartbeatDelay _delay;

    public DiagnosticHeartbeat(ILogger<DiagnosticHeartbeat> logger, IHeartbeatDelay delay)
    {
        _logger = logger;
        _delay = delay;
    }

    public async Task RunAsync(TimeSpan interval, CancellationToken cancellationToken)
    {
        var sequence = 0L;

        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                sequence++;
                LogHeartbeat(_logger, sequence);
                await _delay.WaitAsync(interval, cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            LogCancelled(_logger);
        }
    }

    [LoggerMessage(
        EventId = 1001,
        Level = LogLevel.Information,
        Message = "QuietShield foundation diagnostic heartbeat {Sequence}; protection engines remain inactive.")]
    private static partial void LogHeartbeat(ILogger logger, long sequence);

    [LoggerMessage(
        EventId = 1002,
        Level = LogLevel.Information,
        Message = "QuietShield foundation diagnostic heartbeat cancelled cleanly.")]
    private static partial void LogCancelled(ILogger logger);
}
