// QuietShield Backend Integration 04 R1
namespace QuietShield.Core.IntegrationWave;

public sealed record QuietShieldTelemetryEvent(
    DateTimeOffset TimestampUtc,
    string Category,
    string EventName,
    string Message,
    long? Value);

public sealed class BoundedTelemetryJournal
{
    private readonly object _sync = new();
    private readonly Queue<QuietShieldTelemetryEvent> _events;
    private readonly int _capacity;

    public BoundedTelemetryJournal(int capacity = 512)
    {
        if (capacity < 16 || capacity > 100_000)
            throw new ArgumentOutOfRangeException(nameof(capacity));

        _capacity = capacity;
        _events = new Queue<QuietShieldTelemetryEvent>(capacity);
    }

    public void Add(QuietShieldTelemetryEvent item)
    {
        ArgumentNullException.ThrowIfNull(item);

        lock (_sync)
        {
            while (_events.Count >= _capacity)
                _events.Dequeue();

            _events.Enqueue(item);
        }
    }

    public IReadOnlyList<QuietShieldTelemetryEvent> Snapshot()
    {
        lock (_sync)
            return _events.ToArray();
    }
}

public sealed record NetworkUsageSnapshot(
    DateTimeOffset CapturedAtUtc,
    long BytesReceived,
    long BytesSent)
{
    public long TotalBytes => checked(BytesReceived + BytesSent);
}

public sealed record NetworkUsageDelta(
    TimeSpan Interval,
    long BytesReceived,
    long BytesSent)
{
    public long TotalBytes => checked(BytesReceived + BytesSent);
}

public static class NetworkUsageDeltaCalculator
{
    public static NetworkUsageDelta Calculate(
        NetworkUsageSnapshot previous,
        NetworkUsageSnapshot current)
    {
        ArgumentNullException.ThrowIfNull(previous);
        ArgumentNullException.ThrowIfNull(current);

        if (current.CapturedAtUtc < previous.CapturedAtUtc)
            throw new ArgumentException("Current snapshot precedes previous snapshot.");

        return new(
            current.CapturedAtUtc - previous.CapturedAtUtc,
            Math.Max(0, current.BytesReceived - previous.BytesReceived),
            Math.Max(0, current.BytesSent - previous.BytesSent));
    }
}
