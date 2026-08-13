namespace QuietShield.Core.DataSaving;

public enum QuietShieldOperatingMode
{
    DataSaving = 0,
    WiFi = 1
}

public enum NetworkClassification
{
    Ask = 0,
    Limited = 1,
    Unlimited = 2
}

public enum DataSavingAccessDecision
{
    Allowed = 0,
    Blocked = 1,
    SystemProtected = 2
}

public sealed record OperatingModeState(
    QuietShieldOperatingMode Mode,
    string ProfileName,
    NetworkClassification NetworkClassification,
    IReadOnlyList<string> AllowedApplicationIds)
{
    public static OperatingModeState Default { get; } = new(
        QuietShieldOperatingMode.WiFi,
        "Mobile Data",
        NetworkClassification.Ask,
        Array.Empty<string>());

    public OperatingModeState Normalize()
    {
        var profileName = string.IsNullOrWhiteSpace(ProfileName)
            ? "Mobile Data"
            : ProfileName.Trim();

        var source = AllowedApplicationIds ?? Array.Empty<string>();
        var allowed = source
            .Where(static id => !string.IsNullOrWhiteSpace(id))
            .Select(static id => id.Trim())
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static id => id, StringComparer.Ordinal)
            .ToArray();

        return this with
        {
            ProfileName = profileName,
            AllowedApplicationIds = allowed
        };
    }
}

public sealed record DataSavingApplicationDescriptor(
    string Id,
    bool IsWindowsSystemComponent);

public sealed record DataSavingApplicationDecision(
    string Id,
    DataSavingAccessDecision Decision);

public sealed record DataSavingPolicyPlan(
    QuietShieldOperatingMode Mode,
    IReadOnlyList<DataSavingApplicationDecision> Applications,
    bool MachineEnforcementApplied)
{
    public string SafetyStatus => MachineEnforcementApplied
        ? "Machine enforcement applied."
        : "Local policy plan only; machine enforcement is not applied.";
}

public interface IOperatingModeStore
{
    Task<OperatingModeState> LoadAsync(CancellationToken cancellationToken);

    Task SaveAsync(OperatingModeState state, CancellationToken cancellationToken);
}
