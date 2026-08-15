// QuietShield Backend Integration 04 R1
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QuietShield.Core.IntegrationWave;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class BackendIntegration04Tests
{
    [TestMethod]
    public void JournalIsBounded()
    {
        var journal = new BoundedTelemetryJournal(16);

        for (var index = 0; index < 30; index++)
        {
            journal.Add(new(
                DateTimeOffset.UtcNow,
                "test",
                "event",
                index.ToString(System.Globalization.CultureInfo.InvariantCulture),
                index));
        }

        Assert.HasCount(16, journal.Snapshot());
    }

    [TestMethod]
    public void UsageDeltaNeverGoesNegative()
    {
        var first = new NetworkUsageSnapshot(
            DateTimeOffset.UtcNow,
            100,
            200);

        var second = new NetworkUsageSnapshot(
            first.CapturedAtUtc.AddSeconds(30),
            90,
            250);

        var delta = NetworkUsageDeltaCalculator.Calculate(first, second);

        Assert.AreEqual(0L, delta.BytesReceived);
        Assert.AreEqual(50L, delta.BytesSent);
    }
}
