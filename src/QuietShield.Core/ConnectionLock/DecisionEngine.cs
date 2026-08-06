using QuietShield.Core.Dns;
using QuietShield.Core.Protection;
using QuietShield.Core.Simulation;

namespace QuietShield.Core.ConnectionLock;

public enum SafetyExemptionKind
{
    QuietShieldDesktopApp,
    FutureQuietShieldService,
    LicensingRefresh,
    Updater,
    Dhcp,
    RequiredDnsOperations,
    WindowsNetworking,
    EmergencyRecovery
}

public sealed record SafetyExemption(SafetyExemptionKind Kind, string VisibleReason)
{
    public static SafetyExemption Create(SafetyExemptionKind kind) => new(kind, kind switch
    {
        SafetyExemptionKind.QuietShieldDesktopApp => "QuietShield desktop diagnostics and recovery must remain reachable.",
        SafetyExemptionKind.FutureQuietShieldService => "The future QuietShield service control channel must remain reachable.",
        SafetyExemptionKind.LicensingRefresh => "A future licensing refresh path is explicitly exempt; no licensing connection is started.",
        SafetyExemptionKind.Updater => "A future signed update path is explicitly exempt; no updater is started.",
        SafetyExemptionKind.Dhcp => "DHCP is required to retain a valid network configuration.",
        SafetyExemptionKind.RequiredDnsOperations => "Required DNS operations are exempt to preserve name resolution and recovery.",
        SafetyExemptionKind.WindowsNetworking => "Core Windows networking is exempt to prevent loss of basic connectivity.",
        SafetyExemptionKind.EmergencyRecovery => "Emergency recovery has highest precedence so simulated restrictions cannot prevent rollback.",
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    });
}

public enum CompatibilityExclusionKind
{
    Program,
    Domain,
    TemporaryBypass
}

public sealed record ConnectionCompatibilityExclusion(
    CompatibilityExclusionKind Kind,
    string Target,
    string Relaxation,
    DateTimeOffset? ExpiresAtUtc = null)
{
    public bool IsActiveAt(DateTimeOffset nowUtc) => !ExpiresAtUtc.HasValue || nowUtc < ExpiresAtUtc.Value;

    public static ConnectionCompatibilityExclusion CreateDomain(string domain, string relaxation, DateTimeOffset? expiresAtUtc = null)
    {
        var normalization = DomainNormalizer.NormalizeDomain(domain);
        if (!normalization.IsValid) throw new ArgumentException(normalization.Error, nameof(domain));
        return new(CompatibilityExclusionKind.Domain, normalization.NormalizedValue!, relaxation, expiresAtUtc);
    }

    public void EnsureSafe()
    {
        if (string.IsNullOrWhiteSpace(Target)) throw new ArgumentException("An exact compatibility target is required.", nameof(Target));
        if (Target.Trim().Equals("*", StringComparison.Ordinal) || Target.Trim().Equals("all", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("A global silent protection disable is prohibited.", nameof(Target));
        if (string.IsNullOrWhiteSpace(Relaxation)) throw new ArgumentException("The exact relaxation must be visible.", nameof(Relaxation));
    }
}

public sealed record ConnectionDecisionInput(
    ProgramIdentity Identity,
    ConnectionLockProfile Profile,
    SimulatedConnectionType ConnectionType,
    DateTimeOffset NowUtc,
    ConnectionLockProgramRule? ExplicitRule = null,
    ProgramTemporaryAllowance? TemporaryAllowance = null,
    bool IsProgramRunning = false,
    ConnectionCompatibilityExclusion? CompatibilityExclusion = null,
    ScheduleEvaluation? Schedule = null,
    SafetyExemption? SafetyExemption = null,
    bool IsParentProtected = false);

public sealed record ConnectionDecisionResult(
    SimulatedDecision Decision,
    string Reason,
    string MatchedRule,
    string ActiveProfile,
    SimulatedConnectionType ConnectionType,
    string ScheduleResult,
    string CompatibilityResult,
    string SafetyExemptionResult,
    string SimulationLabel);

public static class ConnectionPolicyDecisionEngine
{
    public static ConnectionDecisionResult Evaluate(ConnectionDecisionInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var identityValidation = input.Identity.Validate();
        if (!identityValidation.IsValid)
        {
            return Result(SimulatedDecision.Unsupported, string.Join(" ", identityValidation.Errors), "UnsupportedOrAmbiguousIdentity", input);
        }

        if (input.SafetyExemption?.Kind == SafetyExemptionKind.EmergencyRecovery)
            return Result(SimulatedDecision.Allow, input.SafetyExemption.VisibleReason, "EmergencyRecoveryExemption", input);
        if (input.SafetyExemption is not null)
            return Result(SimulatedDecision.Allow, input.SafetyExemption.VisibleReason, "RequiredQuietShieldComponentExemption", input);
        if (input.IsParentProtected || input.Profile.ParentProtected)
            return Result(SimulatedDecision.RequireParentApproval, "A parent-protected restriction requires parent approval before the simulated policy can be relaxed.", "ParentProtectedRestriction", input);
        if (input.TemporaryAllowance?.IsActiveAt(input.NowUtc, input.IsProgramRunning) == true)
            return Result(SimulatedDecision.AllowTemporarily, $"Temporary allowance is active; prior simulated policy {input.TemporaryAllowance.PriorPolicy} will be restored automatically.", "ActiveTemporaryAllowance", input);
        if (input.CompatibilityExclusion?.IsActiveAt(input.NowUtc) == true)
        {
            input.CompatibilityExclusion.EnsureSafe();
            return Result(SimulatedDecision.Allow, $"Compatibility Guard would relax only: {input.CompatibilityExclusion.Relaxation}", "ActiveCompatibilityExclusion", input);
        }
        if (input.Schedule?.IsActive == true && input.Schedule.MatchedSchedule is not null)
            return EvaluatePolicy(input.Schedule.MatchedSchedule.Policy, "ActiveSchedule", input);
        if (input.ExplicitRule?.IsEnabled == true)
            return EvaluatePolicy(input.ExplicitRule.Policy, "ExplicitProgramRule", input);
        return EvaluatePolicy(input.Profile.DefaultPolicy, "ProfileDefault", input);
    }

    private static ConnectionDecisionResult EvaluatePolicy(ProgramConnectionPolicy policy, string matchedRule, ConnectionDecisionInput input)
    {
        if (!Enum.IsDefined(policy)) return Result(SimulatedDecision.Unsupported, "The policy is unsupported.", matchedRule, input);
        if (policy == ProgramConnectionPolicy.Blocked) return Result(SimulatedDecision.Block, "The matched policy blocks all connection types.", matchedRule, input);
        if (policy == ProgramConnectionPolicy.AllowedOnAll) return Result(SimulatedDecision.Allow, "The matched policy allows all connection types.", matchedRule, input);
        if (input.ConnectionType == SimulatedConnectionType.Unknown)
            return Result(SimulatedDecision.Indeterminate, "The connection type is unknown; the simulator refuses to guess.", matchedRule, input);

        var matches = policy switch
        {
            ProgramConnectionPolicy.WiFiOnly => input.ConnectionType == SimulatedConnectionType.WiFi,
            ProgramConnectionPolicy.EthernetOnly => input.ConnectionType == SimulatedConnectionType.Ethernet,
            ProgramConnectionPolicy.CellularOnly => input.ConnectionType == SimulatedConnectionType.Cellular,
            ProgramConnectionPolicy.MeteredOnly => input.ConnectionType == SimulatedConnectionType.Metered,
            ProgramConnectionPolicy.UnmeteredOnly => input.ConnectionType == SimulatedConnectionType.Unmetered,
            _ => false
        };
        if (input.ConnectionType == SimulatedConnectionType.Vpn && policy is ProgramConnectionPolicy.WiFiOnly or ProgramConnectionPolicy.EthernetOnly or ProgramConnectionPolicy.CellularOnly)
            return Result(SimulatedDecision.Indeterminate, "A VPN does not reveal its physical transport; the simulator refuses to guess.", matchedRule, input);
        return matches
            ? Result(SimulatedDecision.Allow, $"The {policy} policy matches the selected connection.", matchedRule, input)
            : Result(SimulatedDecision.Block, $"The {policy} policy does not match the selected connection.", matchedRule, input);
    }

    private static ConnectionDecisionResult Result(SimulatedDecision decision, string reason, string matchedRule, ConnectionDecisionInput input) => new(
        decision,
        reason,
        matchedRule,
        input.Profile.Name,
        input.ConnectionType,
        input.Schedule?.Result ?? "Not configured",
        input.CompatibilityExclusion is null ? "Not configured" : input.CompatibilityExclusion.IsActiveAt(input.NowUtc) ? $"Active: {input.CompatibilityExclusion.Relaxation}" : "Expired",
        input.SafetyExemption?.VisibleReason ?? "No exemption matched",
        PolicySimulationResult.SimulationOnlyLabel);
}
