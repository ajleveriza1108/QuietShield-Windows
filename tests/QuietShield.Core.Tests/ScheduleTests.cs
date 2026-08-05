using QuietShield.Core.Scheduling;

namespace QuietShield.Core.Tests;

[TestClass]
public sealed class ScheduleTests
{
    [TestMethod]
    public void ValidSchedulePassesValidation()
    {
        var schedule = new ProtectionSchedule(
            "weekday",
            "Weekday protection",
            new HashSet<DayOfWeek> { DayOfWeek.Monday, DayOfWeek.Tuesday },
            new TimeOnly(8, 0),
            new TimeOnly(18, 0),
            "standard",
            true);

        Assert.IsTrue(schedule.Validate().IsValid);
        Assert.IsFalse(schedule.CrossesMidnight);
    }

    [TestMethod]
    public void OvernightScheduleIsSupported()
    {
        var schedule = new ProtectionSchedule(
            "overnight",
            "Overnight protection",
            new HashSet<DayOfWeek> { DayOfWeek.Friday },
            new TimeOnly(22, 0),
            new TimeOnly(6, 0),
            "high",
            true);

        Assert.IsTrue(schedule.Validate().IsValid);
        Assert.IsTrue(schedule.CrossesMidnight);
    }

    [TestMethod]
    public void ScheduleRequiresDayDistinctTimesAndProfile()
    {
        var schedule = new ProtectionSchedule(
            "invalid",
            "Invalid",
            new HashSet<DayOfWeek>(),
            new TimeOnly(9, 0),
            new TimeOnly(9, 0),
            "",
            true);

        var result = schedule.Validate();

        Assert.IsFalse(result.IsValid);
        Assert.HasCount(3, result.Errors);
    }
}
