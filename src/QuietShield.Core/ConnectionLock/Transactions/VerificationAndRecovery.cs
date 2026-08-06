using QuietShield.Core.Protection;
using QuietShield.Core.Simulation;

namespace QuietShield.Core.ConnectionLock.Transactions;

public sealed record ProgramLockVerificationInput(
    ProgramLockRulePlan Plan,
    IReadOnlyList<QuietShieldProgramRuleIdentity> ExpectedRules,
    IReadOnlyList<QuietShieldProgramRuleIdentity> ActualRules,
    ProgramLockBackup Backup,
    bool EmergencyRecoveryAvailable);

public sealed record ProgramLockVerificationResult(
    bool Passed,
    int ExpectedOwnedRuleCount,
    int ActualOwnedRuleCount,
    IReadOnlyList<string> Errors,
    IReadOnlyDictionary<string, SimulatedDecision> SimulatedOutcomes);

public static class ProgramLockVerificationService
{
    public static ProgramLockVerificationResult Verify(ProgramLockVerificationInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        var errors = new List<string>();
        if (!input.Plan.IsValid) errors.Add("The rule plan is invalid or contains unsupported operations.");
        var backupValidation = ProgramLockBackupValidator.Validate(input.Backup);
        if (!backupValidation.IsValid) errors.AddRange(backupValidation.Errors);
        if (!input.EmergencyRecoveryAvailable) errors.Add("Emergency recovery is unavailable.");
        if (input.ActualRules.Any(rule => !string.Equals(rule.OwnershipMarker, QuietShieldProgramRuleIdentity.Owner, StringComparison.Ordinal)))
            errors.Add("A foreign rule was incorrectly included in the QuietShield-owned verification set.");
        if (input.ExpectedRules.Count != input.ActualRules.Count) errors.Add("The exact expected QuietShield-owned rule count does not match.");
        if (input.ActualRules.GroupBy(static rule => rule.StableRuleId, StringComparer.Ordinal).Any(static group => group.Count() > 1))
            errors.Add("Unexpected duplicate QuietShield rule IDs were detected.");

        foreach (var expected in input.ExpectedRules)
        {
            var matches = input.ActualRules.Where(actual => actual.StableRuleId.Equals(expected.StableRuleId, StringComparison.Ordinal)).ToArray();
            if (matches.Length != 1)
            {
                errors.Add($"Expected rule '{expected.StableRuleId}' was not present exactly once.");
                continue;
            }
            var actual = matches[0];
            if (!actual.StableApplicationIdentity.Equals(expected.StableApplicationIdentity, StringComparison.Ordinal) ||
                actual.ConnectionPolicy != expected.ConnectionPolicy || actual.Direction != expected.Direction ||
                actual.ProtocolScope != expected.ProtocolScope || actual.NetworkScope != expected.NetworkScope)
                errors.Add($"Rule '{expected.StableRuleId}' does not match the exact application, action, direction, protocol, or network scope.");
        }
        foreach (var unexpected in input.ActualRules.Where(actual => input.ExpectedRules.All(expected => !expected.StableRuleId.Equals(actual.StableRuleId, StringComparison.Ordinal))))
            errors.Add($"Unexpected QuietShield rule '{unexpected.StableRuleId}' was detected.");

        var outcomes = input.Plan.Operations.Where(static operation => operation.ProposedRule is not null)
            .GroupBy(static operation => operation.TargetStableApplicationIdentity, StringComparer.Ordinal)
            .ToDictionary(
                static group => group.Key,
                static group => group.Last().ProposedRule!.ConnectionPolicy == ProgramConnectionPolicy.Blocked ? SimulatedDecision.Block : SimulatedDecision.Allow,
                StringComparer.Ordinal);
        return new(errors.Count == 0, input.ExpectedRules.Count, input.ActualRules.Count, errors, outcomes);
    }
}

public enum ProgramLockRecoveryScenario
{
    NormalRollback,
    PartialApply,
    ApplicationCrash,
    SystemShutdown,
    StaleTransaction,
    ProfileSwitch,
    MissingExecutable,
    MalformedBackup,
    EmergencyOwnedRuleRemoval
}

public sealed record ProgramLockRecoveryPlan(
    ProgramLockRecoveryScenario Scenario,
    bool CanProceed,
    bool BackupValidated,
    bool RemovesOnlyQuietShieldOwnedRules,
    IReadOnlyList<string> Steps,
    string Reason);

public static class ProgramLockRecoveryPlanner
{
    private static readonly string[] RestoreSteps =
    {
        "Validate the immutable QuietShield backup and SHA-256 payload.",
        "Enumerate only rules with validated QuietShield ownership.",
        "Remove only transaction-created QuietShield rules.",
        "Restore backed-up QuietShield rules in recorded order.",
        "Verify exact ownership, count, identity, and emergency readiness."
    };
    private static readonly string[] RefusalSteps = { "Stop without touching any rule and preserve evidence for review." };

    public static ProgramLockRecoveryPlan Plan(
        ProgramLockRecoveryScenario scenario,
        ProgramLockBackup? backup,
        ProgramLockTransactionState state,
        DateTimeOffset lastUpdatedUtc,
        DateTimeOffset nowUtc,
        bool executableAvailable = true)
    {
        var backupValid = backup is not null && ProgramLockBackupValidator.Validate(backup).IsValid;
        if (!backupValid)
            return new(scenario, false, false, true, RefusalSteps, "Malformed, foreign, missing, or hash-invalid backup data is refused.");
        if (scenario == ProgramLockRecoveryScenario.StaleTransaction && nowUtc - lastUpdatedUtc < TimeSpan.FromMinutes(15))
            return new(scenario, false, true, true, RefusalSteps, "The transaction is not stale; concurrent recovery is refused.");
        if (scenario == ProgramLockRecoveryScenario.MissingExecutable && executableAvailable)
            return new(scenario, false, true, true, RefusalSteps, "The executable is still present; missing-executable recovery does not apply.");
        if (scenario is ProgramLockRecoveryScenario.PartialApply or ProgramLockRecoveryScenario.ApplicationCrash or ProgramLockRecoveryScenario.SystemShutdown &&
            state is not (ProgramLockTransactionState.ApplyStarted or ProgramLockTransactionState.RulesApplied or
                ProgramLockTransactionState.VerificationStarted or ProgramLockTransactionState.InterruptedRecoveryRequired))
            return new(scenario, false, true, true, RefusalSteps, "The transaction state does not indicate a partial or interrupted apply.");
        return new(scenario, true, true, true, RestoreSteps,
            scenario == ProgramLockRecoveryScenario.ProfileSwitch
                ? "Restore the prior profile's exact owned rules before planning the new profile."
                : "Validated simulation rollback can restore only QuietShield-owned state.");
    }
}

public static class ProgramLockRollbackCoordinator
{
    public static async Task<int> RestoreAsync(
        ProgramLockBackup backup,
        IProgramLockRollback rollback,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(rollback);
        var validation = ProgramLockBackupValidator.Validate(backup);
        if (!validation.IsValid) throw new InvalidDataException(string.Join(" ", validation.Errors));
        await rollback.RollbackAsync(backup, cancellationToken).ConfigureAwait(false);
        return backup.QuietShieldOwnedRules.Count;
    }

    public static async Task<int> EmergencyRemoveOwnedAsync(
        IProgramLockRuleEnumerator enumerator,
        IProgramLockRuleRemover remover,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(enumerator);
        ArgumentNullException.ThrowIfNull(remover);
        var rules = await enumerator.EnumerateAsync(cancellationToken).ConfigureAwait(false);
        foreach (var rule in rules)
        {
            if (!string.Equals(rule.OwnershipMarker, QuietShieldProgramRuleIdentity.Owner, StringComparison.Ordinal))
                throw new InvalidDataException("A foreign rule was returned by the owned-rule enumerator; emergency removal stopped.");
            await remover.RemoveAsync(rule.StableRuleId, cancellationToken).ConfigureAwait(false);
        }
        return rules.Count;
    }
}
