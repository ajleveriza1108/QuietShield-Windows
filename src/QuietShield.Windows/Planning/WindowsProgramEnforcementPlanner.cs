using QuietShield.Core.ConnectionLock;
using QuietShield.Core.Protection;

namespace QuietShield.Windows.Planning;

public enum WindowsProposedEnforcementStrategy
{
    WindowsFirewall,
    UserModeWindowsFilteringPlatform,
    Unsupported
}

public sealed record WindowsProgramEnforcementPlan(
    string StableApplicationIdentity,
    string Target,
    ProgramConnectionPolicy DesiredPolicy,
    WindowsProposedEnforcementStrategy Strategy,
    string RequiredPrivilege,
    IReadOnlyList<string> BackupRequirements,
    IReadOnlyList<string> ApplicationSteps,
    IReadOnlyList<string> VerificationSteps,
    IReadOnlyList<string> RollbackSteps,
    string? UnsupportedOrAmbiguousReason,
    bool CanExecute);

public interface IReadOnlyWindowsProgramEnforcementPlanner
{
    WindowsProgramEnforcementPlan Plan(ConnectionLockProgramRule rule);
}

public sealed class WindowsProgramEnforcementPlanner : IReadOnlyWindowsProgramEnforcementPlanner
{
    private static readonly string[] BackupRequirements =
        { "Export matching pre-existing Windows Firewall/WFP state.", "Create a hash-verified, application-specific rollback checkpoint." };
    private static readonly string[] VerificationSteps =
        { "Verify only the selected application and connection policy.", "Confirm QuietShield safety exemptions and normal Windows networking." };
    private static readonly string[] FirewallApplicationSteps =
        { "Re-resolve the stable identity.", "Propose application-specific Windows Firewall objects.", "Request explicit approval before applying anything." };
    private static readonly string[] WfpApplicationSteps =
        { "Re-resolve the stable identity.", "Propose application-specific user-mode WFP objects.", "Request explicit approval before applying anything." };
    private static readonly string[] RollbackSteps =
        { "Remove only objects created by the approved transaction.", "Restore the hash-verified application-specific backup.", "Verify connectivity and absence of orphaned objects." };
    private static readonly string[] UnsupportedBackup = { "No backup is created because the target is unsupported or ambiguous." };
    private static readonly string[] UnsupportedApplication = { "Resolve the exact application identity before planning." };
    private static readonly string[] UnsupportedVerification = { "No verification can proceed without an exact target." };
    private static readonly string[] UnsupportedRollback = { "No rollback is needed because no change is permitted." };

    public WindowsProgramEnforcementPlan Plan(ConnectionLockProgramRule rule)
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
            ? WindowsProposedEnforcementStrategy.WindowsFirewall
            : WindowsProposedEnforcementStrategy.UserModeWindowsFilteringPlatform;
        return new(
            rule.Identity.StableId,
            target,
            rule.Policy,
            strategy,
            "Administrator approval would be required in a separately approved enforcement phase.",
            BackupRequirements,
            strategy == WindowsProposedEnforcementStrategy.WindowsFirewall ? FirewallApplicationSteps : WfpApplicationSteps,
            VerificationSteps,
            RollbackSteps,
            null,
            false);
    }

    private static WindowsProgramEnforcementPlan Unsupported(ConnectionLockProgramRule rule, string target, string reason) => new(
        rule.Identity.StableId,
        target,
        rule.Policy,
        WindowsProposedEnforcementStrategy.Unsupported,
        "Not applicable; planning is refused.",
        UnsupportedBackup,
        UnsupportedApplication,
        UnsupportedVerification,
        UnsupportedRollback,
        reason,
        false);
}
