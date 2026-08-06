using QuietShield.Core.Validation;

namespace QuietShield.Core.Protection;

public enum ProtectionMode
{
    Standard,
    High,
    Extreme,
    Custom
}

public enum ProgramConnectionPolicy
{
    Blocked,
    WiFiOnly,
    EthernetOnly,
    CellularOnly,
    MeteredOnly,
    UnmeteredOnly,
    AllowedOnAll
}

public enum NotificationPriority
{
    Quiet,
    Normal,
    Important,
    Critical
}

public sealed record ProgramRule(
    string ProgramId,
    string DisplayName,
    ProgramConnectionPolicy ConnectionPolicy,
    bool IsEnabled = true)
{
    public ValidationResult Validate()
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(ProgramId))
        {
            errors.Add("A stable program identifier is required.");
        }

        if (string.IsNullOrWhiteSpace(DisplayName))
        {
            errors.Add("A program display name is required.");
        }

        if (!Enum.IsDefined(ConnectionPolicy))
        {
            errors.Add("The program connection policy is not recognized.");
        }

        return errors.Count == 0 ? ValidationResult.Valid : new ValidationResult(errors);
    }
}

public sealed record CompatibilityExclusion(string ProgramId, string Reason)
{
    public ValidationResult Validate()
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(ProgramId))
        {
            errors.Add("A program identifier is required for an exclusion.");
        }

        if (string.IsNullOrWhiteSpace(Reason))
        {
            errors.Add("A reason is required for an exclusion.");
        }

        return errors.Count == 0 ? ValidationResult.Valid : new ValidationResult(errors);
    }
}

public sealed record ProtectionProfile(
    string Id,
    string Name,
    ProtectionMode Mode,
    IReadOnlyList<ProgramRule> ProgramRules,
    IReadOnlyList<CompatibilityExclusion> CompatibilityExclusions,
    NotificationPriority NotificationPriority,
    bool ParentProtected)
{
    public ValidationResult Validate()
    {
        var errors = new List<string>();

        if (string.IsNullOrWhiteSpace(Id))
        {
            errors.Add("A profile identifier is required.");
        }

        if (string.IsNullOrWhiteSpace(Name))
        {
            errors.Add("A profile name is required.");
        }

        if (!Enum.IsDefined(Mode))
        {
            errors.Add("The protection mode is not recognized.");
        }

        if (Mode == ProtectionMode.Custom && ProgramRules.Count == 0)
        {
            errors.Add("A custom profile must contain at least one program rule.");
        }

        var duplicateProgramIds = ProgramRules
            .Where(static rule => !string.IsNullOrWhiteSpace(rule.ProgramId))
            .GroupBy(static rule => rule.ProgramId, StringComparer.OrdinalIgnoreCase)
            .Where(static group => group.Count() > 1)
            .Select(static group => group.Key);

        foreach (var duplicateProgramId in duplicateProgramIds)
        {
            errors.Add($"Program rule '{duplicateProgramId}' appears more than once.");
        }

        foreach (var rule in ProgramRules)
        {
            errors.AddRange(rule.Validate().Errors);
        }

        foreach (var exclusion in CompatibilityExclusions)
        {
            errors.AddRange(exclusion.Validate().Errors);
        }

        return errors.Count == 0 ? ValidationResult.Valid : new ValidationResult(errors);
    }
}
