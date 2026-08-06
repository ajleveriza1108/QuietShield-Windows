using QuietShield.Core.Protection;
using QuietShield.Core.Simulation;

namespace QuietShield.Core.ConnectionLock.Transactions;

public enum ProgramLockPreflightSeverity
{
    Warning,
    Blocker
}

public sealed record ProgramLockPreflightFinding(string Code, ProgramLockPreflightSeverity Severity, string Message);

public sealed record ProgramLockPreflightInput(
    bool IsAdministrator,
    bool WindowsFirewallServiceAvailable,
    bool BaseFilteringEngineAvailable,
    ConnectionLockProfile Profile,
    ProgramIdentity Application,
    ProgramConnectionPolicy Policy,
    int ExistingQuietShieldOwnedRuleCount,
    bool ConflictingTransactionExists,
    SimulatedConnectionType ActiveConnectionType,
    bool EmergencyRecoveryReady,
    bool MsixIdentitySupported = true);

public sealed record ProgramLockPreflightResult(
    bool Passed,
    PolicyEnforceability Enforceability,
    IReadOnlyList<ProgramLockPreflightFinding> Blockers,
    IReadOnlyList<ProgramLockPreflightFinding> Warnings,
    string Summary);

public static class ProgramLockPreflightEvaluator
{
    public static ProgramLockPreflightResult Evaluate(ProgramLockPreflightInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var findings = new List<ProgramLockPreflightFinding>();
        if (!input.IsAdministrator) findings.Add(Blocker("AdministratorRequired", "A future real transaction requires explicit Administrator approval; this dry-run remains non-elevated."));
        if (!input.WindowsFirewallServiceAvailable) findings.Add(Blocker("FirewallServiceUnavailable", "The Windows Firewall service is unavailable."));
        if (!input.BaseFilteringEngineAvailable) findings.Add(Blocker("BaseFilteringEngineUnavailable", "The Base Filtering Engine is unavailable."));
        var profileValidation = input.Profile.Validate();
        if (!profileValidation.IsValid) findings.Add(Blocker("InvalidProfile", string.Join(" ", profileValidation.Errors)));
        var identityValidation = input.Application.Validate();
        if (!identityValidation.IsValid) findings.Add(Blocker("InvalidApplicationIdentity", string.Join(" ", identityValidation.Errors)));
        if (input.Application.Kind == ProgramIdentityKind.Win32Executable && input.Application.PathStatus is ProgramPathStatus.Missing or ProgramPathStatus.Moved)
            findings.Add(Blocker("ExecutableUnavailable", "The Win32 executable is missing or moved and must be re-identified."));
        if (input.Application.Kind == ProgramIdentityKind.MicrosoftStoreOrMsix && !input.MsixIdentitySupported)
            findings.Add(Blocker("MsixIdentityUnsupported", "The selected MSIX package identity is not supported by the future rule layer."));
        if (input.ExistingQuietShieldOwnedRuleCount > 0)
            findings.Add(Warning("ExistingOwnedRules", $"{input.ExistingQuietShieldOwnedRuleCount} existing QuietShield-owned rule(s) require backup and collision validation."));
        if (input.ConflictingTransactionExists) findings.Add(Blocker("ConflictingTransaction", "Another QuietShield Program Lock transaction is active or requires recovery."));
        if (input.ActiveConnectionType == SimulatedConnectionType.Unknown)
            findings.Add(Warning("ConnectionTypeUnknown", "The active connection type is unknown; connection-specific coverage cannot be verified."));
        var enforceability = PolicyEnforceabilityClassifier.Classify(input.Policy);
        if (enforceability.Support == PolicyEnforcementSupport.Unsupported)
            findings.Add(Blocker("PolicyUnsupported", enforceability.Reason));
        else if (enforceability.Support == PolicyEnforcementSupport.RequiresRuntimeNetworkTransitionManagement)
            findings.Add(Blocker("RuntimeTransitionManagementRequired", enforceability.Reason));
        if (!input.EmergencyRecoveryReady) findings.Add(Blocker("EmergencyRecoveryUnavailable", "Emergency recovery is not ready."));

        var blockers = findings.Where(static item => item.Severity == ProgramLockPreflightSeverity.Blocker).ToArray();
        var warnings = findings.Where(static item => item.Severity == ProgramLockPreflightSeverity.Warning).ToArray();
        return new(blockers.Length == 0, enforceability, blockers, warnings,
            blockers.Length == 0 ? "Preflight passed." : $"Preflight blocked by {blockers.Length} requirement(s); no apply may start.");
    }

    private static ProgramLockPreflightFinding Blocker(string code, string message) => new(code, ProgramLockPreflightSeverity.Blocker, message);
    private static ProgramLockPreflightFinding Warning(string code, string message) => new(code, ProgramLockPreflightSeverity.Warning, message);
}
