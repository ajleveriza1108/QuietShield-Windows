// QuietShield Backend Integration 02 R1
namespace QuietShield.Core.IntegrationWave;

public sealed record ProtectionScheduleEntry(
    string ScheduleId,
    bool Enabled,
    DayOfWeek Day,
    TimeOnly StartInclusive,
    TimeOnly EndExclusive,
    ProtectionProfilePreset Profile,
    int Priority);

public sealed record ProtectionScheduleEvaluation(
    bool Matched,
    ProtectionProfilePreset? Profile,
    string? ScheduleId,
    DateTimeOffset EvaluatedAtLocal,
    string Reason);

public static class ProtectionScheduleEngine
{
    public static ProtectionScheduleEvaluation Evaluate(
        IReadOnlyList<ProtectionScheduleEntry> schedules,
        DateTimeOffset localTime)
    {
        ArgumentNullException.ThrowIfNull(schedules);

        var candidates = schedules
            .Where(static item => item.Enabled)
            .Where(item => Contains(item, localTime))
            .OrderByDescending(static item => item.Priority)
            .ThenBy(static item => item.ScheduleId, StringComparer.Ordinal)
            .ToArray();

        if (candidates.Length == 0)
        {
            return new(
                false,
                null,
                null,
                localTime,
                "No enabled protection schedule matches the current local time.");
        }

        var selected = candidates[0];
        return new(
            true,
            selected.Profile,
            selected.ScheduleId,
            localTime,
            "Highest-priority matching schedule selected.");
    }

    private static bool Contains(
        ProtectionScheduleEntry entry,
        DateTimeOffset localTime)
    {
        var time = TimeOnly.FromDateTime(localTime.DateTime);

        if (entry.StartInclusive == entry.EndExclusive)
        {
            return localTime.DayOfWeek == entry.Day;
        }

        if (entry.StartInclusive < entry.EndExclusive)
        {
            return localTime.DayOfWeek == entry.Day &&
                   time >= entry.StartInclusive &&
                   time < entry.EndExclusive;
        }

        if (localTime.DayOfWeek == entry.Day &&
            time >= entry.StartInclusive)
        {
            return true;
        }

        var previousDay = (DayOfWeek)(((int)localTime.DayOfWeek + 6) % 7);
        return previousDay == entry.Day &&
               time < entry.EndExclusive;
    }
}
