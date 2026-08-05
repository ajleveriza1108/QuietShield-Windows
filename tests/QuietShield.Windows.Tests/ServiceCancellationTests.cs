using Microsoft.Extensions.Logging.Abstractions;
using QuietShield.Service;

namespace QuietShield.Windows.Tests;

[TestClass]
public sealed class ServiceCancellationTests
{
    [TestMethod]
    public async Task DiagnosticHeartbeatStopsCleanlyWhenCancelled()
    {
        using var cancellation = new CancellationTokenSource();
        var delay = new CancelOnFirstDelay(cancellation);
        var heartbeat = new DiagnosticHeartbeat(NullLogger<DiagnosticHeartbeat>.Instance, delay);

        await heartbeat.RunAsync(TimeSpan.FromSeconds(30), cancellation.Token);

        Assert.AreEqual(1, delay.CallCount);
        Assert.IsTrue(cancellation.IsCancellationRequested);
    }

    private sealed class CancelOnFirstDelay : IHeartbeatDelay
    {
        private readonly CancellationTokenSource _cancellation;

        public CancelOnFirstDelay(CancellationTokenSource cancellation)
        {
            _cancellation = cancellation;
        }

        public int CallCount { get; private set; }

        public Task WaitAsync(TimeSpan interval, CancellationToken cancellationToken)
        {
            CallCount++;
            _cancellation.Cancel();
            return Task.FromCanceled(cancellationToken);
        }
    }
}
