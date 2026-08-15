// QuietShield Backend Integration 02 R1
using Microsoft.VisualStudio.TestTools.UnitTesting;
using QuietShield.Core.IntegrationWave;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class BackendIntegration02Tests
{
    [TestMethod]
    public void OvernightScheduleMatchesAfterMidnight()
    {
        var schedule = new ProtectionScheduleEntry(
            "night",
            true,
            DayOfWeek.Monday,
            new TimeOnly(22, 0),
            new TimeOnly(6, 0),
            ProtectionProfilePreset.Strict,
            10);

        var when = new DateTimeOffset(
            2026, 8, 11, 1, 30, 0, TimeSpan.FromHours(8));

        var result = ProtectionScheduleEngine.Evaluate([schedule], when);

        Assert.IsTrue(result.Matched);
        Assert.AreEqual(ProtectionProfilePreset.Strict, result.Profile);
    }

    [TestMethod]
    public void HighestPriorityScheduleWins()
    {
        var when = new DateTimeOffset(
            2026, 8, 13, 12, 0, 0, TimeSpan.FromHours(8));

        var schedules = new[]
        {
            new ProtectionScheduleEntry(
                "balanced",
                true,
                DayOfWeek.Thursday,
                new TimeOnly(0, 0),
                new TimeOnly(23, 59),
                ProtectionProfilePreset.Balanced,
                1),
            new ProtectionScheduleEntry(
                "data",
                true,
                DayOfWeek.Thursday,
                new TimeOnly(10, 0),
                new TimeOnly(14, 0),
                ProtectionProfilePreset.DataSaving,
                20)
        };

        var result = ProtectionScheduleEngine.Evaluate(schedules, when);
        Assert.AreEqual(ProtectionProfilePreset.DataSaving, result.Profile);
    }
}
