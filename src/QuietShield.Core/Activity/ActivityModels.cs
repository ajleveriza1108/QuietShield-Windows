namespace QuietShield.Core.Activity;

public sealed record ActivityCounters(
    long BlockedConnectionAttempts,
    long AllowedConnectionAttempts,
    long CompatibilityInterventions,
    DateTimeOffset? LastUpdatedUtc)
{
    public static ActivityCounters Empty { get; } = new(0, 0, 0, null);
}

public sealed record ActivityEvent(
    DateTimeOffset OccurredAtUtc,
    string Category,
    string Summary,
    bool ContainsSensitiveData);

public interface IActivityStore
{
    Task<ActivityCounters> GetCountersAsync(CancellationToken cancellationToken);

    Task<IReadOnlyList<ActivityEvent>> GetRecentActivityAsync(
        int maximumCount,
        CancellationToken cancellationToken);
}
