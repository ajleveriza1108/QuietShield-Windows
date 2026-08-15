// QuietShield Backend Integration 05 R1
namespace QuietShield.Core.IntegrationWave;

public enum CompatibilityTier
{
    CriticalSystem = 0,
    TemporarySystem = 1,
    OptionalSystem = 2,
    UserApplication = 3
}

public sealed record CompatibilityRule(
    string IdentityPrefix,
    CompatibilityTier Tier,
    bool MayBeRestricted,
    string Reason);

public sealed record ProgramObservation(
    string StableIdentity,
    string DisplayName,
    bool IsWindowsSystemComponent,
    DateTimeOffset ObservedAtUtc);

public sealed record CompatibilityDecision(
    CompatibilityTier Tier,
    bool MayBeRestricted,
    string Reason);

public static class CompatibilityGuardEngine
{
    public static CompatibilityDecision Evaluate(
        ProgramObservation observation,
        IReadOnlyList<CompatibilityRule> rules)
    {
        ArgumentNullException.ThrowIfNull(observation);
        ArgumentNullException.ThrowIfNull(rules);

        var matched = rules
            .Where(rule =>
                observation.StableIdentity.StartsWith(
                    rule.IdentityPrefix,
                    StringComparison.OrdinalIgnoreCase))
            .OrderByDescending(static rule => rule.IdentityPrefix.Length)
            .FirstOrDefault();

        if (matched is not null)
        {
            return new(
                matched.Tier,
                matched.MayBeRestricted,
                matched.Reason);
        }

        if (observation.IsWindowsSystemComponent)
        {
            return new(
                CompatibilityTier.CriticalSystem,
                false,
                "Unknown Windows system component defaults to protected.");
        }

        return new(
            CompatibilityTier.UserApplication,
            true,
            "User application may be evaluated by the active QuietShield policy.");
    }
}

public static class AdaptiveProgramWatchCadence
{
    public static TimeSpan GetNextDelay(
        bool batterySaver,
        bool guiVisible,
        bool recentChange)
    {
        if (recentChange)
            return TimeSpan.FromSeconds(10);
        if (batterySaver)
            return TimeSpan.FromMinutes(2);
        if (guiVisible)
            return TimeSpan.FromSeconds(30);

        return TimeSpan.FromMinutes(1);
    }
}
