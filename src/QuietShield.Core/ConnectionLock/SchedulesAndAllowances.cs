using QuietShield.Core.Protection;
using QuietShield.Core.Validation;

namespace QuietShield.Core.ConnectionLock;

public enum TemporaryAllowanceKind
{
    UntilProgramCloses,
    FiveMinutes,
    FifteenMinutes,
    ThirtyMinutes,
    SixtyMinutes,
    CustomExpiration
}

public sealed record ProgramTemporaryAllowance(
    string ApplicationId,
    TemporaryAllowanceKind Kind,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset? ExpiresAtUtc,
    ProgramConnectionPolicy PriorPolicy,
    string Reason)
{
    public bool IsActiveAt(DateTimeOffset nowUtc, bool isProgramRunning) =>
        Kind == TemporaryAllowanceKind.UntilProgramCloses ? isProgramRunning : ExpiresAtUtc.HasValue && nowUtc < ExpiresAtUtc.Value;

    public static ProgramTemporaryAllowance CreateTimed(
        string applicationId,
        TemporaryAllowanceKind kind,
        DateTimeOffset nowUtc,
        ProgramConnectionPolicy priorPolicy,
        DateTimeOffset? customExpiration = null)
    {
        var expiration = kind switch
        {
            TemporaryAllowanceKind.FiveMinutes => nowUtc.AddMinutes(5),
            TemporaryAllowanceKind.FifteenMinutes => nowUtc.AddMinutes(15),
            TemporaryAllowanceKind.ThirtyMinutes => nowUtc.AddMinutes(30),
            TemporaryAllowanceKind.SixtyMinutes => nowUtc.AddMinutes(60),
            TemporaryAllowanceKind.CustomExpiration when customExpiration > nowUtc => customExpiration.Value,
            TemporaryAllowanceKind.CustomExpiration => throw new ArgumentOutOfRangeException(nameof(customExpiration), "Custom expiration must be in the future."),
            TemporaryAllowanceKind.UntilProgramCloses => (DateTimeOffset?)null,
            _ => throw new ArgumentOutOfRangeException(nameof(kind))
        };
        return new(applicationId, kind, nowUtc, expiration, priorPolicy, "Temporary simulation allowance; the prior policy is restored when inactive.");
    }
}

public sealed class TemporaryAllowanceStore
{
    private readonly List<ProgramTemporaryAllowance> _items = new();
    public IReadOnlyList<ProgramTemporaryAllowance> Items => _items.AsReadOnly();
    public void Add(ProgramTemporaryAllowance allowance)
    {
        ArgumentNullException.ThrowIfNull(allowance);
        _items.RemoveAll(item => item.ApplicationId.Equals(allowance.ApplicationId, StringComparison.OrdinalIgnoreCase));
        _items.Add(allowance);
    }
    public IReadOnlyList<ProgramTemporaryAllowance> CleanupExpired(DateTimeOffset nowUtc, Func<string, bool> isProgramRunning)
    {
        ArgumentNullException.ThrowIfNull(isProgramRunning);
        var expired = _items.Where(item => !item.IsActiveAt(nowUtc, isProgramRunning(item.ApplicationId))).ToArray();
        foreach (var item in expired) _items.Remove(item);
        return expired;
    }
}

public enum ConnectionSchedulePreset
{
    Study,
    Work,
    Bedtime,
    Custom
}

public sealed record ConnectionPolicySchedule(
    string Id,
    string Name,
    IReadOnlySet<DayOfWeek> Days,
    TimeOnly Start,
    TimeOnly End,
    string TimeZoneId,
    ProgramConnectionPolicy Policy,
    ConnectionSchedulePreset Preset,
    int Priority,
    bool IsEnabled)
{
    public bool CrossesMidnight => End < Start;

    public ValidationResult Validate()
    {
        var errors = new List<string>();
        if (string.IsNullOrWhiteSpace(Id)) errors.Add("A schedule identifier is required.");
        if (string.IsNullOrWhiteSpace(Name)) errors.Add("A schedule name is required.");
        if (Days.Count == 0) errors.Add("A schedule must include at least one day.");
        if (Start == End) errors.Add("Schedule start and end times must differ.");
        try { _ = TimeZoneInfo.FindSystemTimeZoneById(TimeZoneId); }
        catch (TimeZoneNotFoundException) { errors.Add("The schedule time zone is unavailable."); }
        catch (InvalidTimeZoneException) { errors.Add("The schedule time zone is invalid."); }
        if (!Enum.IsDefined(Policy)) errors.Add("The schedule policy is unsupported.");
        return errors.Count == 0 ? ValidationResult.Valid : new ValidationResult(errors);
    }

    public static ConnectionPolicySchedule CreatePreset(ConnectionSchedulePreset preset, string timeZoneId, string id, ProgramConnectionPolicy policy) => preset switch
    {
        ConnectionSchedulePreset.Study => new(id, "Study", Weekdays, new TimeOnly(16, 0), new TimeOnly(19, 0), timeZoneId, policy, preset, 200, true),
        ConnectionSchedulePreset.Work => new(id, "Work", Weekdays, new TimeOnly(9, 0), new TimeOnly(17, 0), timeZoneId, policy, preset, 200, true),
        ConnectionSchedulePreset.Bedtime => new(id, "Bedtime", EveryDay, new TimeOnly(22, 0), new TimeOnly(7, 0), timeZoneId, policy, preset, 300, true),
        _ => throw new ArgumentException("Custom schedules must supply explicit days and times.", nameof(preset))
    };

    private static IReadOnlySet<DayOfWeek> Weekdays { get; } = new HashSet<DayOfWeek>
        { DayOfWeek.Monday, DayOfWeek.Tuesday, DayOfWeek.Wednesday, DayOfWeek.Thursday, DayOfWeek.Friday };
    private static IReadOnlySet<DayOfWeek> EveryDay { get; } = Enum.GetValues<DayOfWeek>().ToHashSet();
}

public sealed record ScheduleEvaluation(
    bool IsActive,
    ConnectionPolicySchedule? MatchedSchedule,
    string Result,
    bool ReconciledAfterSleepOrWake);

public static class ConnectionScheduleEvaluator
{
    public static ScheduleEvaluation Evaluate(
        IEnumerable<ConnectionPolicySchedule> schedules,
        DateTimeOffset nowUtc,
        DateTimeOffset? previousEvaluationUtc = null)
    {
        ArgumentNullException.ThrowIfNull(schedules);
        var valid = schedules.Where(static item => item.IsEnabled && item.Validate().IsValid).ToArray();
        var active = valid.Where(item => IsActive(item, nowUtc))
            .OrderByDescending(static item => item.Priority)
            .ThenBy(static item => Restrictiveness(item.Policy))
            .ThenBy(static item => item.Id, StringComparer.Ordinal)
            .FirstOrDefault();
        var reconciled = previousEvaluationUtc.HasValue && valid.Any(item => IsActive(item, previousEvaluationUtc.Value) != IsActive(item, nowUtc));
        return active is null
            ? new(false, null, "No schedule is active.", reconciled)
            : new(true, active, $"Active schedule '{active.Name}' in {active.TimeZoneId}; conflicts resolved by priority, restrictive policy, then stable ID.", reconciled);
    }

    public static bool IsActive(ConnectionPolicySchedule schedule, DateTimeOffset utcTime)
    {
        var zone = TimeZoneInfo.FindSystemTimeZoneById(schedule.TimeZoneId);
        var local = TimeZoneInfo.ConvertTime(utcTime, zone);
        var time = TimeOnly.FromDateTime(local.DateTime);
        if (!schedule.CrossesMidnight) return schedule.Days.Contains(local.DayOfWeek) && time >= schedule.Start && time < schedule.End;
        if (time >= schedule.Start) return schedule.Days.Contains(local.DayOfWeek);
        if (time < schedule.End) return schedule.Days.Contains(local.AddDays(-1).DayOfWeek);
        return false;
    }

    private static int Restrictiveness(ProgramConnectionPolicy policy) => policy switch
    {
        ProgramConnectionPolicy.Blocked => 0,
        ProgramConnectionPolicy.WiFiOnly or ProgramConnectionPolicy.EthernetOnly or ProgramConnectionPolicy.CellularOnly or ProgramConnectionPolicy.MeteredOnly or ProgramConnectionPolicy.UnmeteredOnly => 1,
        ProgramConnectionPolicy.AllowedOnAll => 2,
        _ => 3
    };
}
