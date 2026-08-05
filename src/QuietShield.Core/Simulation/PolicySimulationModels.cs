using QuietShield.Core.Protection;
using QuietShield.Core.Scheduling;

namespace QuietShield.Core.Simulation;

public enum SimulatedConnectionType
{
    WiFi,
    Ethernet,
    Cellular,
    Metered,
    Unmetered,
    Vpn,
    Unknown
}

public enum SimulatedDecision
{
    Allow,
    Block,
    AllowTemporarily,
    RequireParentApproval,
    Unsupported,
    Indeterminate
}

public sealed record TemporaryAllowance(DateTimeOffset ExpiresAtUtc, string Reason)
{
    public bool IsActiveAt(DateTimeOffset nowUtc) => nowUtc < ExpiresAtUtc;
}

public sealed record SimulationSchedule(ProtectionSchedule Schedule, ProgramConnectionPolicy Policy);

public sealed record PolicySimulationInput(
    string ApplicationId,
    SimulatedConnectionType ConnectionType,
    ProtectionProfile Profile,
    ProgramRule? ExplicitProgramRule,
    ProgramConnectionPolicy? ProfileDefaultPolicy,
    DateTimeOffset CurrentTime,
    SimulationSchedule? Schedule,
    CompatibilityExclusion? CompatibilityExclusion,
    bool IsCompatibilityExclusionActive,
    bool IsParentProtected,
    TemporaryAllowance? TemporaryAllowance,
    bool IsSafetyRecoveryExempt,
    bool IsRequiredQuietShieldComponent);

public sealed record PolicySimulationResult(
    SimulatedDecision Decision,
    string Reason,
    string ResponsibleRule,
    string ScheduleResult,
    string CompatibilityExclusionResult,
    string? Warning,
    string EnforcementLabel)
{
    public const string SimulationOnlyLabel = "Simulation only — no Windows rule was applied";
}
