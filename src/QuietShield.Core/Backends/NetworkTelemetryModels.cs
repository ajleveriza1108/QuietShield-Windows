// QuietShield Backend Pack 1-4 R1
namespace QuietShield.Core.Backends;

public enum NetworkTransportProtocol
{
    Tcp = 0,
    Udp = 1
}

public sealed record NetworkConnectionSample(
    NetworkTransportProtocol Protocol,
    string LocalAddress,
    int LocalPort,
    string RemoteAddress,
    int RemotePort,
    int ProcessId,
    string ProcessName,
    string State);

public sealed record NetworkInterfaceSample(
    string Id,
    string Name,
    string Description,
    string InterfaceType,
    string OperationalStatus,
    long BytesReceived,
    long BytesSent,
    long UnicastPacketsReceived,
    long UnicastPacketsSent);

public sealed record NetworkTelemetrySnapshot(
    DateTimeOffset CapturedAtUtc,
    IReadOnlyList<NetworkConnectionSample> Connections,
    IReadOnlyList<NetworkInterfaceSample> Interfaces);

public sealed record NetworkTelemetrySummary(
    DateTimeOffset WindowStartedAtUtc,
    DateTimeOffset WindowEndedAtUtc,
    int Samples,
    int PeakConnectionCount,
    long LatestBytesReceived,
    long LatestBytesSent,
    long ReceivedDelta,
    long SentDelta);

public interface INetworkTelemetrySource
{
    NetworkTelemetrySnapshot Capture();
}

public sealed class NetworkTelemetryAccumulator
{
    private readonly object _sync = new();
    private readonly Queue<NetworkTelemetrySnapshot> _samples = new();
    private readonly int _capacity;

    public NetworkTelemetryAccumulator(int capacity = 120)
    {
        _capacity = Math.Max(2, capacity);
    }

    public void Add(NetworkTelemetrySnapshot snapshot)
    {
        ArgumentNullException.ThrowIfNull(snapshot);
        lock (_sync)
        {
            _samples.Enqueue(snapshot);
            while (_samples.Count > _capacity)
            {
                _samples.Dequeue();
            }
        }
    }

    public NetworkTelemetrySummary Snapshot()
    {
        lock (_sync)
        {
            if (_samples.Count == 0)
            {
                var now = DateTimeOffset.UtcNow;
                return new(now, now, 0, 0, 0, 0, 0, 0);
            }

            var first = _samples.Peek();
            var last = _samples.Last();
            var firstRx = first.Interfaces.Sum(item => item.BytesReceived);
            var firstTx = first.Interfaces.Sum(item => item.BytesSent);
            var lastRx = last.Interfaces.Sum(item => item.BytesReceived);
            var lastTx = last.Interfaces.Sum(item => item.BytesSent);

            return new(
                first.CapturedAtUtc,
                last.CapturedAtUtc,
                _samples.Count,
                _samples.Max(item => item.Connections.Count),
                lastRx,
                lastTx,
                Math.Max(0, lastRx - firstRx),
                Math.Max(0, lastTx - firstTx));
        }
    }
}
