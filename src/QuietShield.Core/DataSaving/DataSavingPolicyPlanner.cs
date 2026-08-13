namespace QuietShield.Core.DataSaving;

public static class DataSavingPolicyPlanner
{
    public static DataSavingPolicyPlan Build(
        IEnumerable<DataSavingApplicationDescriptor> applications,
        OperatingModeState state)
    {
        ArgumentNullException.ThrowIfNull(applications);
        ArgumentNullException.ThrowIfNull(state);

        var normalized = state.Normalize();
        var allowedIds = new HashSet<string>(
            normalized.AllowedApplicationIds,
            StringComparer.Ordinal);

        var decisions = applications
            .OrderBy(static application => application.Id, StringComparer.Ordinal)
            .Select(application => new DataSavingApplicationDecision(
                application.Id,
                GetDecision(application, normalized.Mode, allowedIds)))
            .ToArray();

        return new DataSavingPolicyPlan(
            normalized.Mode,
            decisions,
            MachineEnforcementApplied: false);
    }

    private static DataSavingAccessDecision GetDecision(
        DataSavingApplicationDescriptor application,
        QuietShieldOperatingMode mode,
        HashSet<string> allowedIds)
    {
        if (application.IsWindowsSystemComponent)
        {
            return DataSavingAccessDecision.SystemProtected;
        }

        if (mode == QuietShieldOperatingMode.WiFi)
        {
            return DataSavingAccessDecision.Allowed;
        }

        return allowedIds.Contains(application.Id)
            ? DataSavingAccessDecision.Allowed
            : DataSavingAccessDecision.Blocked;
    }
}
