using System.Security.Cryptography;
using System.Text;
using QuietShield.Core.Protection;

namespace QuietShield.Core.ConnectionLock.Transactions;

public enum ProgramLockRuleOperationKind
{
    Add,
    Replace,
    Remove,
    Preserve,
    Unsupported,
    NoChange
}

public enum ProgramLockDesiredAction
{
    Block,
    Allow,
    RemoveRestriction,
    None
}

public enum ProgramLockRollbackCounterpart
{
    RemoveAddedRule,
    RestoreReplacedRule,
    RestoreRemovedRule,
    PreserveExistingRule,
    None
}

public sealed record ForeignProgramLockRuleCollision(string RuleName, string OwnerDescription);

public sealed record ProgramLockRuleOperation(
    ProgramLockRuleOperationKind Operation,
    string TargetStableApplicationIdentity,
    string FutureRuleId,
    ProgramLockDesiredAction DesiredAction,
    ProgramLockRuleDirection Direction,
    ProgramLockNetworkScope NetworkScope,
    string Reason,
    string RequiredPrivilege,
    string VerificationRequirement,
    ProgramLockRollbackCounterpart RollbackCounterpart,
    PolicyEnforcementSupport Enforceability,
    ProposedEnforcementLayer Layer,
    QuietShieldProgramRuleIdentity? ExistingRule,
    QuietShieldProgramRuleIdentity? ProposedRule);

public sealed record ProgramLockRulePlan(
    int SchemaVersion,
    Guid TransactionId,
    string ProfileId,
    IReadOnlyList<ProgramLockRuleOperation> Operations,
    string PlanSha256,
    bool IsValid,
    bool CanExecute,
    string SafetyStatement);

public static class ProgramLockRulePlanGenerator
{
    public static ProgramLockRulePlan Generate(
        Guid transactionId,
        ConnectionLockProfile profile,
        IReadOnlyList<ConnectionLockProgramRule> desiredRules,
        IReadOnlyList<QuietShieldProgramRuleIdentity> existingQuietShieldRules,
        IReadOnlyList<ForeignProgramLockRuleCollision>? foreignCollisions = null)
    {
        if (transactionId == Guid.Empty) throw new ArgumentException("A transaction ID is required.", nameof(transactionId));
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(desiredRules);
        ArgumentNullException.ThrowIfNull(existingQuietShieldRules);
        var operations = new List<ProgramLockRuleOperation>();
        var collisions = foreignCollisions ?? Array.Empty<ForeignProgramLockRuleCollision>();
        var desiredApplicationIds = desiredRules.Select(static rule => rule.Identity.StableId).ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var duplicate in desiredRules.GroupBy(static rule => rule.Identity.StableId, StringComparer.OrdinalIgnoreCase).Where(static group => group.Count() > 1))
        {
            operations.Add(Unsupported(duplicate.Key, "[duplicate]", PolicyEnforceabilityClassifier.Classify(duplicate.First().Policy),
                "Duplicate desired rules for one stable application identity are refused."));
        }

        foreach (var desired in desiredRules.GroupBy(static rule => rule.Identity.StableId, StringComparer.OrdinalIgnoreCase).Select(static group => group.First()))
        {
            var support = PolicyEnforceabilityClassifier.Classify(desired.Policy);
            var proposed = QuietShieldProgramRuleIdentity.Create(transactionId, profile.Id, desired.Identity, desired.Policy);
            var matchingExisting = existingQuietShieldRules.Where(rule =>
                rule.StableApplicationIdentity.Equals(desired.Identity.StableId, StringComparison.OrdinalIgnoreCase)).ToArray();
            if (desired.Identity.Kind == ProgramIdentityKind.Win32Executable && desired.Identity.PathStatus is ProgramPathStatus.Missing or ProgramPathStatus.Moved)
            {
                operations.Add(Unsupported(desired.Identity.StableId, proposed.StableRuleId, support,
                    "The executable is missing or moved; exact identity recovery is required before any rule operation is planned.", proposed));
                continue;
            }
            if (collisions.Any(collision => collision.RuleName.Equals(proposed.RuleName, StringComparison.OrdinalIgnoreCase)))
            {
                operations.Add(Unsupported(desired.Identity.StableId, proposed.StableRuleId, support,
                    "A foreign rule collides with the deterministic QuietShield rule name; no replacement or removal is permitted."));
                continue;
            }
            if (support.Support != PolicyEnforcementSupport.WindowsFirewallStatic)
            {
                operations.Add(Unsupported(desired.Identity.StableId, proposed.StableRuleId, support, support.Reason, proposed));
                continue;
            }
            if (desired.Policy == ProgramConnectionPolicy.AllowedOnAll)
            {
                if (matchingExisting.Length == 0)
                {
                    operations.Add(Operation(ProgramLockRuleOperationKind.NoChange, desired.Identity.StableId, proposed.StableRuleId,
                        ProgramLockDesiredAction.Allow, support, "No QuietShield-owned restriction exists for this application.",
                        ProgramLockRollbackCounterpart.None, null, proposed));
                }
                else
                {
                    operations.AddRange(matchingExisting.Select(existing => Operation(ProgramLockRuleOperationKind.Remove,
                        desired.Identity.StableId, existing.StableRuleId, ProgramLockDesiredAction.RemoveRestriction, support,
                        "Allowed on All requires removal of this exact QuietShield-owned restriction.",
                        ProgramLockRollbackCounterpart.RestoreRemovedRule, existing, proposed)));
                }
                continue;
            }

            var sameStableId = matchingExisting.Where(rule => rule.StableRuleId.Equals(proposed.StableRuleId, StringComparison.Ordinal)).ToArray();
            if (sameStableId.Length > 1)
            {
                operations.Add(Unsupported(desired.Identity.StableId, proposed.StableRuleId, support,
                    "Duplicate existing QuietShield rules share the deterministic stable rule ID; recovery review is required.", proposed));
            }
            else if (sameStableId.Length == 1 && EquivalentConfiguration(sameStableId[0], proposed))
            {
                operations.Add(Operation(ProgramLockRuleOperationKind.NoChange, desired.Identity.StableId, proposed.StableRuleId,
                    ProgramLockDesiredAction.Block, support, "The exact hypothetical rule already matches; the plan is idempotent.",
                    ProgramLockRollbackCounterpart.None, sameStableId[0], proposed));
            }
            else if (matchingExisting.Length == 1)
            {
                operations.Add(Operation(ProgramLockRuleOperationKind.Replace, desired.Identity.StableId, proposed.StableRuleId,
                    ProgramLockDesiredAction.Block, support, "The existing QuietShield rule belongs to this application but differs from the desired profile or policy.",
                    ProgramLockRollbackCounterpart.RestoreReplacedRule, matchingExisting[0], proposed));
            }
            else if (matchingExisting.Length > 1)
            {
                operations.Add(Unsupported(desired.Identity.StableId, proposed.StableRuleId, support,
                    "Multiple existing QuietShield rules for the application are ambiguous; no automatic replacement is planned.", proposed));
            }
            else
            {
                operations.Add(Operation(ProgramLockRuleOperationKind.Add, desired.Identity.StableId, proposed.StableRuleId,
                    ProgramLockDesiredAction.Block, support, "Add one deterministic application-specific outbound block rule.",
                    ProgramLockRollbackCounterpart.RemoveAddedRule, null, proposed));
            }
        }

        foreach (var existing in existingQuietShieldRules.Where(rule => !desiredApplicationIds.Contains(rule.StableApplicationIdentity)))
        {
            var support = PolicyEnforceabilityClassifier.Classify(existing.ConnectionPolicy);
            operations.Add(Operation(ProgramLockRuleOperationKind.Preserve, existing.StableApplicationIdentity, existing.StableRuleId,
                ProgramLockDesiredAction.None, support, "The rule is outside the selected profile plan and must remain untouched.",
                ProgramLockRollbackCounterpart.PreserveExistingRule, existing, null));
        }

        var ordered = operations.OrderBy(static operation => operation.TargetStableApplicationIdentity, StringComparer.Ordinal)
            .ThenBy(static operation => operation.Operation)
            .ThenBy(static operation => operation.FutureRuleId, StringComparer.Ordinal)
            .ToArray();
        var hash = ComputePlanHash(transactionId, profile.Id, ordered);
        return new(1, transactionId, profile.Id, ordered, hash,
            ordered.All(static operation => operation.Operation != ProgramLockRuleOperationKind.Unsupported),
            false,
            "Simulation only — no Windows Firewall or WFP operation can execute from this plan.");
    }

    private static ProgramLockRuleOperation Operation(
        ProgramLockRuleOperationKind kind,
        string applicationId,
        string ruleId,
        ProgramLockDesiredAction action,
        PolicyEnforceability support,
        string reason,
        ProgramLockRollbackCounterpart rollback,
        QuietShieldProgramRuleIdentity? existing,
        QuietShieldProgramRuleIdentity? proposed) => new(
            kind,
            applicationId,
            ruleId,
            action,
            ProgramLockRuleDirection.Outbound,
            proposed?.NetworkScope ?? existing?.NetworkScope ?? ProgramLockNetworkScope.All,
            reason,
            kind is ProgramLockRuleOperationKind.NoChange or ProgramLockRuleOperationKind.Preserve or ProgramLockRuleOperationKind.Unsupported
                ? "No privilege is used by this dry-run operation."
                : "Administrator approval would be required by a future modifying implementation.",
            "Verify exact ownership, identity, action, direction, scope, rule count, backup validity, and emergency recovery.",
            rollback,
            support.Support,
            support.Layer,
            existing,
            proposed);

    private static ProgramLockRuleOperation Unsupported(string applicationId, string ruleId, PolicyEnforceability support, string reason, QuietShieldProgramRuleIdentity? proposed = null) =>
        Operation(ProgramLockRuleOperationKind.Unsupported, applicationId, ruleId, ProgramLockDesiredAction.None, support, reason,
            ProgramLockRollbackCounterpart.None, null, proposed);

    private static bool EquivalentConfiguration(QuietShieldProgramRuleIdentity existing, QuietShieldProgramRuleIdentity proposed) =>
        existing.OwnershipMarker.Equals(proposed.OwnershipMarker, StringComparison.Ordinal) &&
        existing.SchemaVersion == proposed.SchemaVersion &&
        existing.StableRuleId.Equals(proposed.StableRuleId, StringComparison.Ordinal) &&
        existing.ProfileId.Equals(proposed.ProfileId, StringComparison.Ordinal) &&
        existing.StableApplicationIdentity.Equals(proposed.StableApplicationIdentity, StringComparison.Ordinal) &&
        string.Equals(existing.ExecutablePath, proposed.ExecutablePath, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(existing.MsixPackageIdentity, proposed.MsixPackageIdentity, StringComparison.Ordinal) &&
        existing.ConnectionPolicy == proposed.ConnectionPolicy && existing.Direction == proposed.Direction &&
        existing.ProtocolScope == proposed.ProtocolScope && existing.NetworkScope == proposed.NetworkScope;

    private static string ComputePlanHash(Guid transactionId, string profileId, IEnumerable<ProgramLockRuleOperation> operations)
    {
        var builder = new StringBuilder().Append(1).Append('|').Append(transactionId.ToString("D")).Append('|').Append(profileId).Append('\n');
        foreach (var operation in operations)
            builder.Append(operation.Operation).Append('|').Append(operation.TargetStableApplicationIdentity).Append('|')
                .Append(operation.FutureRuleId).Append('|').Append(operation.DesiredAction).Append('|').Append(operation.Direction).Append('|')
                .Append(operation.NetworkScope).Append('|').Append(operation.Enforceability).Append('|').Append(operation.Layer).Append('|')
                .Append(operation.RollbackCounterpart).Append('\n');
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(builder.ToString())));
    }
}
