using QuietShield.Core.ConnectionLock;
using QuietShield.Core.ConnectionLock.Transactions;
using QuietShield.Core.Protection;

namespace QuietShield.Core.ServiceFoundation;

public enum CoordinatorStage
{
    Preflight,
    PolicyValidation,
    PlanGeneration,
    Backup,
    Apply,
    Verification,
    Commit,
    Rollback,
    InterruptedRecovery,
    EmergencyCleanup
}

public sealed record CoordinatorAuditEntry(CoordinatorStage Stage, string Result, string Detail, DateTimeOffset OccurredAtUtc);

public sealed record PersistentPolicyPlan(
    ProgramConnectionPolicy Policy,
    PolicyEnforceability Enforceability,
    bool ApplyPermitted,
    IReadOnlyList<SafetyExemption> SafetyExemptions,
    IReadOnlyList<CoordinatorAuditEntry> Audit);

public interface IPersistentPolicyPreflight
{
    Task<(bool Succeeded, string Detail)> RunAsync(CancellationToken cancellationToken);
}

public interface IPersistentPolicyBackup
{
    Task<string> CreateAsync(PersistentPolicyPlan plan, CancellationToken cancellationToken);
}

public interface IPersistentPolicyApplicator
{
    bool IsWindowsModifier { get; }
    Task ApplyAsync(PersistentPolicyPlan plan, CancellationToken cancellationToken);
}

public interface IPersistentPolicyVerifier
{
    Task<bool> VerifyAsync(PersistentPolicyPlan plan, CancellationToken cancellationToken);
}

public interface IPersistentPolicyRollback
{
    Task RollbackAsync(string backupId, CancellationToken cancellationToken);
    Task RecoverInterruptedAsync(PersistentTransactionCheckpoint checkpoint, CancellationToken cancellationToken);
    Task EmergencyCleanupAsync(CancellationToken cancellationToken);
}

public interface IPersistentPolicyCoordinator
{
    Task<PersistentPolicyPlan> PreviewAsync(ProgramConnectionPolicy policy, CancellationToken cancellationToken);
}

public sealed class ReadOnlyPersistentPolicyCoordinator : IPersistentPolicyCoordinator
{
    private readonly IPersistentPolicyPreflight _preflight;

    public ReadOnlyPersistentPolicyCoordinator(IPersistentPolicyPreflight preflight) => _preflight = preflight;

    public async Task<PersistentPolicyPlan> PreviewAsync(ProgramConnectionPolicy policy, CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var audit = new List<CoordinatorAuditEntry>();
        var preflight = await _preflight.RunAsync(cancellationToken).ConfigureAwait(false);
        audit.Add(new(CoordinatorStage.Preflight, preflight.Succeeded ? "Passed" : "Failed", preflight.Detail, now));
        var classification = PolicyEnforceabilityClassifier.Classify(policy);
        var supported = classification.Support == PolicyEnforcementSupport.WindowsFirewallStatic &&
                        policy is ProgramConnectionPolicy.Blocked or ProgramConnectionPolicy.AllowedOnAll;
        audit.Add(new(CoordinatorStage.PolicyValidation, supported ? "SupportedEventually" : "NotPersistentlySupported",
            classification.Reason, now));
        audit.Add(new(CoordinatorStage.PlanGeneration, "ReadOnly", "A deterministic plan preview was generated; application is disabled in Phase 10A.", now));
        audit.Add(new(CoordinatorStage.Backup, "Deferred", "A hash-verified backup is mandatory before a future approved apply.", now));
        audit.Add(new(CoordinatorStage.Apply, "NotActive", QuietShieldServiceProtocol.NotActiveMessage, now));
        audit.Add(new(CoordinatorStage.Verification, "Modeled", "Exact policy and safety-exemption verification is modeled.", now));
        audit.Add(new(CoordinatorStage.Commit, "Disabled", "No state can commit because enforcement is inactive.", now));
        audit.Add(new(CoordinatorStage.Rollback, "Ready", "Exact transaction rollback is required for any future apply.", now));
        audit.Add(new(CoordinatorStage.InterruptedRecovery, "Ready", "Interrupted checkpoints are detected before any future apply.", now));
        audit.Add(new(CoordinatorStage.EmergencyCleanup, "Ready", "Emergency cleanup remains explicit and ownership-scoped.", now));
        return new(policy, classification, false, Enum.GetValues<SafetyExemptionKind>().Select(SafetyExemption.Create).ToArray(), audit);
    }
}

public sealed class ReadOnlyPersistentPolicyPreflight : IPersistentPolicyPreflight
{
    public Task<(bool Succeeded, string Detail)> RunAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult((true, "Read-only preflight passed; no service registration or Windows modifier is active."));
    }
}

public sealed class InMemoryPolicyBackup : IPersistentPolicyBackup
{
    public Task<string> CreateAsync(PersistentPolicyPlan plan, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult("memory:" + Guid.NewGuid().ToString("N"));
    }
}

public sealed class InMemoryPolicyApplicator : IPersistentPolicyApplicator
{
    public bool IsWindowsModifier => false;
    public PersistentPolicyPlan? LastPlan { get; private set; }
    public Task ApplyAsync(PersistentPolicyPlan plan, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        LastPlan = plan;
        return Task.CompletedTask;
    }
}

public sealed class InMemoryPolicyVerifier : IPersistentPolicyVerifier
{
    public Task<bool> VerifyAsync(PersistentPolicyPlan plan, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(!plan.ApplyPermitted);
    }
}

public sealed class InMemoryPolicyRollback : IPersistentPolicyRollback
{
    public Task RollbackAsync(string backupId, CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return Task.CompletedTask; }
    public Task RecoverInterruptedAsync(PersistentTransactionCheckpoint checkpoint, CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return Task.CompletedTask; }
    public Task EmergencyCleanupAsync(CancellationToken cancellationToken) { cancellationToken.ThrowIfCancellationRequested(); return Task.CompletedTask; }
}
