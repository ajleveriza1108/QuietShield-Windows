using QuietShield.Core.Protection;
using QuietShield.Core.Validation;

namespace QuietShield.Core.Scheduling;

public sealed record ProtectionSchedule(
    string Id,
    string Name,
    IReadOnlySet<DayOfWeek> Days,
    TimeOnly Start,
    TimeOnly End,
    string ProfileId,
    bool IsEnabled)
{
    public bool CrossesMidnight => End < Start;

    public ValidationResult Validate()
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(Id))
        {
            errors.Add("A schedule identifier is required.");
        }

        if (string.IsNullOrWhiteSpace(Name))
        {
            errors.Add("A schedule name is required.");
        }

        if (Days.Count == 0)
        {
            errors.Add("A schedule must include at least one day.");
        }

        if (Start == End)
        {
            errors.Add("Schedule start and end times must differ.");
        }

        if (string.IsNullOrWhiteSpace(ProfileId))
        {
            errors.Add("A schedule must reference a protection profile.");
        }

        return errors.Count == 0 ? ValidationResult.Valid : new ValidationResult(errors);
    }
}

public interface IProtectionScheduler
{
    Task<IReadOnlyList<ProtectionSchedule>> GetSchedulesAsync(CancellationToken cancellationToken);

    Task<Results.OperationResult> EvaluateAsync(DateTimeOffset now, CancellationToken cancellationToken);
}
