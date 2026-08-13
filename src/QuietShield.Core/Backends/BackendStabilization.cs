// QuietShield Backend Pack 1-4 R1
namespace QuietShield.Core.Backends;

public enum BackendHealthState
{
    Healthy = 0,
    Degraded = 1,
    Failed = 2,
    Recovering = 3
}

public sealed record BackendHealthSnapshot(
    BackendHealthState State,
    int Samples,
    int ConsecutiveFailures,
    int RecoveryAttempts,
    double FailureRate,
    double AverageLatencyMilliseconds,
    DateTimeOffset? NextRecoveryAtUtc,
    string LastComponent,
    string LastDetail);

public sealed class BackendHealthSupervisor
{
    private sealed record Observation(DateTimeOffset AtUtc, bool Success, double LatencyMilliseconds);

    private readonly object _sync = new();
    private readonly Queue<Observation> _observations = new();
    private readonly TimeSpan _window;
    private readonly int _failureThreshold;
    private readonly TimeSpan _baseRecoveryDelay;
    private int _consecutiveFailures;
    private int _recoveryAttempts;
    private DateTimeOffset? _nextRecoveryAtUtc;
    private string _lastComponent = "Not sampled";
    private string _lastDetail = "No backend health samples have been recorded.";

    public BackendHealthSupervisor(
        TimeSpan? window = null,
        int failureThreshold = 3,
        TimeSpan? baseRecoveryDelay = null)
    {
        _window = window ?? TimeSpan.FromMinutes(2);
        _failureThreshold = Math.Max(1, failureThreshold);
        _baseRecoveryDelay = baseRecoveryDelay ?? TimeSpan.FromSeconds(2);
    }

    public void RecordSuccess(
        string component,
        TimeSpan latency,
        DateTimeOffset? nowUtc = null,
        string detail = "Healthy")
    {
        var now = nowUtc ?? DateTimeOffset.UtcNow;
        lock (_sync)
        {
            Trim(now);
            _observations.Enqueue(new(now, true, Math.Max(0d, latency.TotalMilliseconds)));
            _consecutiveFailures = 0;
            _recoveryAttempts = 0;
            _nextRecoveryAtUtc = null;
            _lastComponent = component;
            _lastDetail = detail;
        }
    }

    public void RecordFailure(
        string component,
        TimeSpan latency,
        string detail,
        DateTimeOffset? nowUtc = null)
    {
        var now = nowUtc ?? DateTimeOffset.UtcNow;
        lock (_sync)
        {
            Trim(now);
            _observations.Enqueue(new(now, false, Math.Max(0d, latency.TotalMilliseconds)));
            _consecutiveFailures++;
            _lastComponent = component;
            _lastDetail = detail;

            if (_consecutiveFailures >= _failureThreshold && _nextRecoveryAtUtc is null)
            {
                _nextRecoveryAtUtc = now + GetRecoveryDelay(_recoveryAttempts);
            }
        }
    }

    public bool ShouldAttemptRecovery(DateTimeOffset? nowUtc = null)
    {
        var now = nowUtc ?? DateTimeOffset.UtcNow;
        lock (_sync)
        {
            return _consecutiveFailures >= _failureThreshold &&
                   _nextRecoveryAtUtc.HasValue &&
                   now >= _nextRecoveryAtUtc.Value;
        }
    }

    public void MarkRecoveryAttempt(DateTimeOffset? nowUtc = null)
    {
        var now = nowUtc ?? DateTimeOffset.UtcNow;
        lock (_sync)
        {
            _recoveryAttempts++;
            _nextRecoveryAtUtc = now + GetRecoveryDelay(_recoveryAttempts);
            _lastDetail = "Bounded backend recovery attempt scheduled.";
        }
    }

    public BackendHealthSnapshot Snapshot(DateTimeOffset? nowUtc = null)
    {
        var now = nowUtc ?? DateTimeOffset.UtcNow;
        lock (_sync)
        {
            Trim(now);
            var samples = _observations.Count;
            var failures = _observations.Count(item => !item.Success);
            var failureRate = samples == 0 ? 0d : (double)failures / samples;
            var averageLatency = samples == 0 ? 0d : _observations.Average(item => item.LatencyMilliseconds);

            var state =
                _consecutiveFailures >= _failureThreshold
                    ? (_recoveryAttempts > 0 ? BackendHealthState.Recovering : BackendHealthState.Failed)
                    : failureRate >= 0.20d
                        ? BackendHealthState.Degraded
                        : BackendHealthState.Healthy;

            return new(
                state,
                samples,
                _consecutiveFailures,
                _recoveryAttempts,
                Math.Round(failureRate, 4),
                Math.Round(averageLatency, 2),
                _nextRecoveryAtUtc,
                _lastComponent,
                _lastDetail);
        }
    }

    private TimeSpan GetRecoveryDelay(int attempt)
    {
        var exponent = Math.Min(6, Math.Max(0, attempt));
        var multiplier = 1 << exponent;
        var milliseconds = Math.Min(
            TimeSpan.FromMinutes(2).TotalMilliseconds,
            _baseRecoveryDelay.TotalMilliseconds * multiplier);

        return TimeSpan.FromMilliseconds(milliseconds);
    }

    private void Trim(DateTimeOffset now)
    {
        var cutoff = now - _window;
        while (_observations.Count > 0 && _observations.Peek().AtUtc < cutoff)
        {
            _observations.Dequeue();
        }
    }
}
