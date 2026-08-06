using QuietShield.Core.Protection;

namespace QuietShield.Core.ConnectionLock;

public enum ProposedEnforcementStrategy
{
    ApplicationIdentityPolicy,
    ConnectionAwarePolicy,
    Unsupported
}

public sealed record ProgramEnforcementPlan(
    string StableApplicationIdentity,
    string Target,
    ProgramConnectionPolicy DesiredPolicy,
    ProposedEnforcementStrategy Strategy,
    string RequiredPrivilege,
    IReadOnlyList<string> BackupRequirements,
    IReadOnlyList<string> ApplicationSteps,
    IReadOnlyList<string> VerificationSteps,
    IReadOnlyList<string> RollbackSteps,
    string? UnsupportedOrAmbiguousReason,
    bool CanExecute);

public interface IReadOnlyProgramEnforcementPlanner
{
    ProgramEnforcementPlan Plan(ConnectionLockProgramRule rule);
}

public sealed class ReadOnlyProgramEnforcementPlanner : IReadOnlyProgramEnforcementPlanner
{
    private static readonly string[] BackupRequirements =
        { "Export matching pre-existing platform filtering state.", "Create a hash-verified, application-specific rollback checkpoint." };
    private static readonly string[] VerificationSteps =
        { "Verify only the selected application and connection policy.", "Confirm QuietShield safety exemptions and normal Windows networking." };
    private static readonly string[] ApplicationIdentitySteps =
        { "Re-resolve the stable identity.", "Propose application-specific identity policy objects.", "Request explicit approval before applying anything." };
    private static readonly string[] ConnectionAwareSteps =
        { "Re-resolve the stable identity.", "Propose application-specific connection-aware policy objects.", "Request explicit approval before applying anything." };
    private static readonly string[] RollbackSteps =
        { "Remove only objects created by the approved transaction.", "Restore the hash-verified application-specific backup.", "Verify connectivity and absence of orphaned objects." };
    private static readonly string[] UnsupportedBackup = { "No backup is created because the target is unsupported or ambiguous." };
    private static readonly string[] UnsupportedApplication = { "Resolve the exact application identity before planning." };
    private static readonly string[] UnsupportedVerification = { "No verification can proceed without an exact target." };
    private static readonly string[] UnsupportedRollback = { "No rollback is needed because no change is permitted." };

    public ProgramEnforcementPlan Plan(ConnectionLockProgramRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        var validation = rule.Validate();
        var target = rule.Identity.Kind == ProgramIdentityKind.MicrosoftStoreOrMsix
            ? rule.Identity.PackageFamilyName ?? "[missing package identity]"
            : rule.Identity.ExecutablePath ?? "[missing executable identity]";
        if (!validation.IsValid || rule.Identity.PathStatus == ProgramPathStatus.Ambiguous)
        {
            return Unsupported(rule, target, string.Join(" ", validation.Errors));
        }
        if (rule.Identity.Kind == ProgramIdentityKind.Win32Executable && rule.Identity.PathStatus is ProgramPathStatus.Missing or ProgramPathStatus.Moved)
        {
            return Unsupported(rule, target, "The executable is missing or moved; exact identity must be reverified before any future enforcement.");
        }

        var strategy = rule.Policy is ProgramConnectionPolicy.Blocked or ProgramConnectionPolicy.AllowedOnAll
            ? ProposedEnforcementStrategy.ApplicationIdentityPolicy
            : ProposedEnforcementStrategy.ConnectionAwarePolicy;
        return new(
            rule.Identity.StableId,
            target,
            rule.Policy,
            strategy,
            "Administrator approval would be required in a separately approved enforcement phase.",
            BackupRequirements,
            strategy == ProposedEnforcementStrategy.ApplicationIdentityPolicy ? ApplicationIdentitySteps : ConnectionAwareSteps,
            VerificationSteps,
            RollbackSteps,
            null,
            false);
    }

    private static ProgramEnforcementPlan Unsupported(ConnectionLockProgramRule rule, string target, string reason) => new(
        rule.Identity.StableId,
        target,
        rule.Policy,
        ProposedEnforcementStrategy.Unsupported,
        "Not applicable; planning is refused.",
        UnsupportedBackup,
        UnsupportedApplication,
        UnsupportedVerification,
        UnsupportedRollback,
        reason,
        false);
}
