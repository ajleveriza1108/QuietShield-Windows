using QuietShield.Core.Protection;
using QuietShield.Core.Scheduling;

namespace QuietShield.Core.Simulation;

public sealed class PolicySimulator
{
    public static PolicySimulationResult Simulate(PolicySimulationInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        var scheduleState = EvaluateSchedule(input.Schedule, input.CurrentTime);
        var exclusionState = input.CompatibilityExclusion is null
            ? "Not configured"
            : input.IsCompatibilityExclusionActive
                ? "Active"
                : "Inactive";
        var unknownWarning = input.ConnectionType == SimulatedConnectionType.Unknown
            ? "The connection type is unknown; connection-specific policies may be indeterminate."
            : null;

        if (input.IsSafetyRecoveryExempt)
        {
            return Result(
                SimulatedDecision.Allow,
                "Safety recovery traffic is exempt so recovery cannot be blocked by a simulated policy.",
                "SafetyRecoveryExemption",
                scheduleState.Description,
                exclusionState,
                unknownWarning);
        }

        if (input.IsRequiredQuietShieldComponent)
        {
            return Result(
                SimulatedDecision.Allow,
                "A required QuietShield component is exempt to preserve diagnostics and recovery.",
                "RequiredQuietShieldComponentExemption",
                scheduleState.Description,
                exclusionState,
                unknownWarning);
        }

        if (input.IsParentProtected)
        {
            return Result(
                SimulatedDecision.RequireParentApproval,
                "The selected application or profile is parent protected.",
                "ParentProtectedRestriction",
                scheduleState.Description,
                exclusionState,
                unknownWarning);
        }

        if (input.TemporaryAllowance is not null && input.TemporaryAllowance.IsActiveAt(input.CurrentTime))
        {
            return Result(
                SimulatedDecision.AllowTemporarily,
                $"A temporary allowance is active until {input.TemporaryAllowance.ExpiresAtUtc:O}.",
                "ActiveTemporaryAllowance",
                scheduleState.Description,
                exclusionState,
                unknownWarning);
        }

        if (input.CompatibilityExclusion is not null && input.IsCompatibilityExclusionActive)
        {
            return Result(
                SimulatedDecision.Allow,
                $"Compatibility exclusion: {input.CompatibilityExclusion.Reason}",
                "ActiveCompatibilityExclusion",
                scheduleState.Description,
                exclusionState,
                unknownWarning);
        }

        if (scheduleState.IsActive && input.Schedule is not null)
        {
            return EvaluatePolicy(
                input.Schedule.Policy,
                input.ConnectionType,
                "ActiveSchedule",
                scheduleState.Description,
                exclusionState,
                unknownWarning);
        }

        if (input.ExplicitProgramRule is not null && input.ExplicitProgramRule.IsEnabled)
        {
            return EvaluatePolicy(
                input.ExplicitProgramRule.ConnectionPolicy,
                input.ConnectionType,
                "ExplicitProgramRule",
                scheduleState.Description,
                exclusionState,
                unknownWarning);
        }

        if (input.ProfileDefaultPolicy.HasValue)
        {
            return EvaluatePolicy(
                input.ProfileDefaultPolicy.Value,
                input.ConnectionType,
                "ProfileDefault",
                scheduleState.Description,
                exclusionState,
                unknownWarning);
        }

        return Result(
            SimulatedDecision.Indeterminate,
            "No active schedule, explicit program rule, or profile default determines this connection.",
            "SafeFallback",
            scheduleState.Description,
            exclusionState,
            unknownWarning ?? "No deterministic policy matched; the simulator did not silently allow or block.");
    }

    public static bool IsScheduleActive(ProtectionSchedule schedule, DateTimeOffset currentTime)
    {
        ArgumentNullException.ThrowIfNull(schedule);

        if (!schedule.IsEnabled || schedule.Days.Count == 0)
        {
            return false;
        }

        var localDay = currentTime.DayOfWeek;
        var localTime = TimeOnly.FromDateTime(currentTime.DateTime);

        if (!schedule.CrossesMidnight)
        {
            return schedule.Days.Contains(localDay) &&
                   localTime >= schedule.Start &&
                   localTime < schedule.End;
        }

        if (localTime >= schedule.Start)
        {
            return schedule.Days.Contains(localDay);
        }

        if (localTime < schedule.End)
        {
            var previousDay = currentTime.AddDays(-1).DayOfWeek;
            return schedule.Days.Contains(previousDay);
        }

        return false;
    }

    private static (bool IsActive, string Description) EvaluateSchedule(
        SimulationSchedule? schedule,
        DateTimeOffset currentTime)
    {
        if (schedule is null)
        {
            return (false, "Not configured");
        }

        var isActive = IsScheduleActive(schedule.Schedule, currentTime);
        return isActive
            ? (true, $"Active: {schedule.Schedule.Name}")
            : (false, $"Inactive: {schedule.Schedule.Name}");
    }

    private static PolicySimulationResult EvaluatePolicy(
        ProgramConnectionPolicy policy,
        SimulatedConnectionType connectionType,
        string responsibleRule,
        string scheduleResult,
        string exclusionResult,
        string? warning)
    {
        if (policy == ProgramConnectionPolicy.Blocked)
        {
            return Result(SimulatedDecision.Block, "The responsible policy blocks every connection type.", responsibleRule, scheduleResult, exclusionResult, warning);
        }

        if (policy == ProgramConnectionPolicy.AllowedOnAll)
        {
            return Result(SimulatedDecision.Allow, "The responsible policy allows every connection type.", responsibleRule, scheduleResult, exclusionResult, warning);
        }

        if (connectionType == SimulatedConnectionType.Unknown)
        {
            return Result(SimulatedDecision.Indeterminate, "The connection type is unknown, so this connection-specific policy cannot be resolved.", responsibleRule, scheduleResult, exclusionResult, warning);
        }

        var matches = policy switch
        {
            ProgramConnectionPolicy.WiFiOnly => connectionType == SimulatedConnectionType.WiFi,
            ProgramConnectionPolicy.EthernetOnly => connectionType == SimulatedConnectionType.Ethernet,
            ProgramConnectionPolicy.CellularOnly => connectionType == SimulatedConnectionType.Cellular,
            ProgramConnectionPolicy.UnmeteredOnly => connectionType == SimulatedConnectionType.Unmetered,
            _ => false
        };

        if (connectionType is SimulatedConnectionType.Vpn or SimulatedConnectionType.Metered &&
            policy is ProgramConnectionPolicy.WiFiOnly or ProgramConnectionPolicy.EthernetOnly or ProgramConnectionPolicy.CellularOnly)
        {
            return Result(
                SimulatedDecision.Indeterminate,
                "The selected logical connection type does not reveal the physical transport required by this policy.",
                responsibleRule,
                scheduleResult,
                exclusionResult,
                warning);
        }

        return matches
            ? Result(SimulatedDecision.Allow, $"The {policy} policy matches the selected connection.", responsibleRule, scheduleResult, exclusionResult, warning)
            : Result(SimulatedDecision.Block, $"The {policy} policy does not match the selected connection.", responsibleRule, scheduleResult, exclusionResult, warning);
    }

    private static PolicySimulationResult Result(
        SimulatedDecision decision,
        string reason,
        string responsibleRule,
        string scheduleResult,
        string exclusionResult,
        string? warning) =>
        new(
            decision,
            reason,
            responsibleRule,
            scheduleResult,
            exclusionResult,
            warning,
            PolicySimulationResult.SimulationOnlyLabel);
}
